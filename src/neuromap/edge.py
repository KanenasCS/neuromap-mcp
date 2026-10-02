"""Edge devices: Azure Firewall, Load Balancer, Application Gateway, route next hops,
VPN / ExpressRoute, VM Scale Sets.

Everything here is declared configuration turned into exact edges:
  DNAT_FORWARDS      firewall public IP:port -> translated target        (firewall NAT rules)
  LB_FORWARDS        LB frontend:port -> backend members:port             (LB rules, inbound NAT)
  APPGW_ROUTES       App Gateway listener -> backend target, with WAF     (routing rules, path maps)
  NEXT_HOP           route table route -> resource that owns the next-hop IP
  HYBRID_CONNECTION  VNet gateway -> local network gateway / ER circuit / other gateway
  INGRESS_ANY_SOURCE Internet -> public IP, only where a DNAT rule accepts any source

A target that is referenced but not owned by any scanned resource becomes an explicit
external node ("ip:10.9.9.9", "fqdn:x.example.com") instead of being guessed.
"""
from __future__ import annotations

from typing import Any

from . import access as A

INTERNET = "internet"


def _lid(v):
    return v.lower() if isinstance(v, str) and v else None


def _parent(rid: str) -> str:
    return "/".join(rid.split("/")[:9])


def _l(v: Any) -> list:
    return [x for x in (v or []) if x not in (None, "")]


# ------------------------------------------------------------- lookups
def _ip_targets(g, ip: str) -> list[str]:
    owners = sorted(g.by_ip.get(ip, set()))
    if owners:
        return owners
    nid = f"ip:{ip}"
    if nid not in g.nodes:
        g.add_node(nid, "ip", ip, in_scan=False,
                   props={"note": "IP not owned by any scanned resource", "ips": [ip]})
    return [nid]


def _fqdn_targets(g, fqdn: str) -> list[str]:
    owners = sorted(g.by_fqdn.get(fqdn.lower(), set()))
    if owners:
        return owners
    nid = f"fqdn:{fqdn.lower()}"
    if nid not in g.nodes:
        g.add_node(nid, "fqdn", fqdn.lower(), in_scan=False,
                   props={"note": "FQDN not matched to any scanned resource hostname"})
    return [nid]


def _any_source(sources: list[str]) -> bool:
    toks = {s.strip().lower() for s in sources}
    if toks & A.ANY_TOKENS or "internet" in toks:
        return True
    return A.covers_all_ipv4([r for r in (A.ip_range(s) for s in sources) if r])


def _expand_ipgroups(g, ids: list[str]) -> tuple[list[str], list[dict]]:
    out, unknown = [], []
    for i in ids:
        n = g.nodes.get(i.lower())
        if n and n["in_scan"]:
            out += n["props"].get("ip_addresses", [])
        else:
            unknown.append({"ip_group": i, "reason": "IP group not in scan"})
    return out, unknown


# --------------------------------------------------------- firewall rules
def _proto_list(protocols: Any) -> list[str]:
    out = []
    for p in protocols or []:
        if isinstance(p, dict):
            out.append(f"{p.get('protocolType')}:{p.get('port')}")
        else:
            out.append(str(p))
    return out


def _norm_policy_rule(rule: dict, ctx: dict) -> dict:
    t = {"NatRule": "dnat", "NetworkRule": "network", "ApplicationRule": "application"}.get(rule.get("ruleType"), rule.get("ruleType"))
    return {**ctx, "type": t, "name": rule.get("name"),
            "protocols": _proto_list(rule.get("ipProtocols") or rule.get("protocols")),
            "sources": _l(rule.get("sourceAddresses")), "source_ip_groups": [x.lower() for x in _l(rule.get("sourceIpGroups"))],
            "destinations": _l(rule.get("destinationAddresses")),
            "destination_ip_groups": [x.lower() for x in _l(rule.get("destinationIpGroups"))],
            "destination_fqdns": _l(rule.get("destinationFqdns")), "ports": _l(rule.get("destinationPorts")),
            "translated_address": rule.get("translatedAddress"), "translated_fqdn": rule.get("translatedFqdn"),
            "translated_port": rule.get("translatedPort"), "target_fqdns": _l(rule.get("targetFqdns")),
            "target_urls": _l(rule.get("targetUrls")), "fqdn_tags": _l(rule.get("fqdnTags")),
            "web_categories": _l(rule.get("webCategories")), "terminate_tls": rule.get("terminateTLS")}


def _parse_policy_groups(groups: list[dict], policy: str) -> list[dict]:
    rules = []
    for grp in groups:
        gp = grp.get("properties") or {}
        for coll in gp.get("ruleCollections") or []:
            ctx = {"policy": policy, "group": grp.get("name"), "group_priority": gp.get("priority"),
                   "collection": coll.get("name"), "collection_priority": coll.get("priority"),
                   "action": (coll.get("action") or {}).get("type")}
            for i, rule in enumerate(coll.get("rules") or []):
                rules.append(_norm_policy_rule(rule, ctx | {"index": i}))
    return rules


def _parse_classic(p: dict, fw_name: str) -> list[dict]:
    rules = []
    for key, t in (("natRuleCollections", "dnat"), ("networkRuleCollections", "network"),
                   ("applicationRuleCollections", "application")):
        for coll in p.get(key) or []:
            cp = coll.get("properties") or {}
            ctx = {"policy": None, "classic": True, "firewall": fw_name, "group": None, "group_priority": 0,
                   "collection": coll.get("name"), "collection_priority": cp.get("priority"),
                   "action": "DNAT" if t == "dnat" else (cp.get("action") or {}).get("type")}
            for i, r in enumerate(cp.get("rules") or []):
                rules.append({**ctx, "index": i, "type": t, "name": r.get("name"),
                              "protocols": _proto_list(r.get("protocols")),
                              "sources": _l(r.get("sourceAddresses")),
                              "source_ip_groups": [x.lower() for x in _l(r.get("sourceIpGroups"))],
                              "destinations": _l(r.get("destinationAddresses")),
                              "destination_ip_groups": [x.lower() for x in _l(r.get("destinationIpGroups"))],
                              "destination_fqdns": _l(r.get("destinationFqdns")), "ports": _l(r.get("destinationPorts")),
                              "translated_address": r.get("translatedAddress"), "translated_fqdn": r.get("translatedFqdn"),
                              "translated_port": r.get("translatedPort"), "target_fqdns": _l(r.get("targetFqdns")),
                              "target_urls": [], "fqdn_tags": _l(r.get("fqdnTags")), "web_categories": [],
                              "terminate_tls": None})
    return rules


def policy_chain(g, policy_id: str | None) -> list[str]:
    """Own policy first, then parent, grandparent... (cycle-safe)."""
    chain, cur = [], policy_id
    while cur and cur not in chain:
        chain.append(cur)
        cur = (g.nodes.get(cur, {}).get("props") or {}).get("base_policy")
    return chain


def effective_firewall_rules(g, fw: dict) -> dict:
    """Rules in Azure Firewall processing order.

    DNAT, then network, then application rules. Within each type: rule collection groups
    inherited from parent policies first (root parent first), then by group priority,
    collection priority, and rule order.
    """
    props = fw["props"]
    unknown: list[dict] = []
    rules = list(props.get("classic_rules", []))
    chain = policy_chain(g, props.get("policy"))
    depth = {pid: d for d, pid in enumerate(chain)}
    for pid in chain:
        pn = g.nodes.get(pid)
        if not pn or not pn["in_scan"]:
            unknown.append({"policy": pid, "reason": "policy not in scan"})
            continue
        if pn["props"].get("rule_groups_error"):
            unknown.append({"policy": pn["name"], "reason": pn["props"]["rule_groups_error"]})
            continue
        for r in pn["props"].get("rules", []):
            rules.append({**r, "inherited": pid != props.get("policy"), "_depth": depth[pid]})
    for r in rules:
        srcs, u1 = _expand_ipgroups(g, r["source_ip_groups"])
        dsts, u2 = _expand_ipgroups(g, r["destination_ip_groups"])
        r["sources_expanded"] = r["sources"] + srcs
        r["destinations_expanded"] = r["destinations"] + dsts
        unknown += u1 + u2
    order = {"dnat": 0, "network": 1, "application": 2}
    rules.sort(key=lambda r: (order.get(r["type"], 9), -r.get("_depth", 0), r["group_priority"] or 0,
                              r["collection_priority"] or 0, r["index"]))
    for r in rules:
        r.pop("_depth", None)
    settings = {"threat_intel_mode": props.get("threat_intel_mode"), "sku": props.get("sku")}
    if chain and chain[0] in g.nodes:
        pp = g.nodes[chain[0]]["props"]
        settings.update({k: pp.get(k) for k in ("threat_intel_mode", "idps_mode", "dns_proxy", "policy_sku")
                         if pp.get(k) is not None})
    return {"firewall": fw["name"], "policy_chain": [g.nodes[c]["name"] if c in g.nodes else c for c in chain],
            "processing_order": "DNAT -> network -> application; parent policy groups first, then group "
                                "priority, collection priority, rule order",
            "settings": settings, "rules": rules, "unknown": unknown}


def _dnat_edges(g, fw: dict) -> None:
    eff = effective_firewall_rules(g, fw)
    for r in eff["rules"]:
        if r["type"] != "dnat" or not (r["translated_address"] or r["translated_fqdn"]):
            continue
        targets = (_ip_targets(g, r["translated_address"]) if r["translated_address"]
                   else _fqdn_targets(g, r["translated_fqdn"]))
        any_src = _any_source(r["sources_expanded"])
        for dest in r["destinations"] or ["(firewall)"]:
            src = sorted(g.by_ip.get(dest, set())) or [fw["id"]]
            for s in src:
                if any_src and g.nodes[s]["kind"] == "pip":
                    if INTERNET not in g.nodes:
                        g.add_node(INTERNET, "internet", "Internet (any IP)", in_scan=False)
                    g.link(INTERNET, s, "INGRESS_ANY_SOURCE", uniq=f"{fw['id']}|{r['collection']}|{r['name']}",
                           via=fw["name"], rule=r["name"], ports=r["ports"])
                for t in targets:
                    g.link(s, t, "DNAT_FORWARDS", uniq=f"{fw['id']}|{r.get('policy')}|{r['collection']}|{r['name']}|{dest}",
                           firewall=fw["name"], firewall_id=fw["id"], rule=r["name"], collection=r["collection"], group=r["group"],
                           policy=r.get("policy"), classic=bool(r.get("classic")), destination=dest,
                           ports=r["ports"], translated_port=r["translated_port"], protocols=r["protocols"],
                           sources=r["sources_expanded"], any_source=any_src)


# ---------------------------------------------------------- load balancer
def _lb_parse(g, lb: dict, p: dict) -> None:
    fe = {}
    for f in p.get("frontendIPConfigurations") or []:
        fp = f.get("properties") or {}
        pip = _lid((fp.get("publicIPAddress") or {}).get("id"))
        fe[f["id"].lower()] = {"name": f.get("name"), "private_ip": fp.get("privateIPAddress"), "public_ip_id": pip,
                               "public_ip": (g.nodes.get(pip, {}).get("props") or {}).get("ip_address") if pip else None}
    pools = {}
    for b in p.get("backendAddressPools") or []:
        bp = b.get("properties") or {}
        # Azure can list the same node under backendIPConfigurations AND loadBalancerBackendAddresses
        # (pointing at the same IP configuration), so members are keyed by ipconfig id / IP.
        seen: dict[str, dict] = {}
        for c in bp.get("backendIPConfigurations") or []:
            cid = c["id"].lower()
            seen.setdefault(cid, {"ipconfig": cid, "member": _parent(cid), "via": "ipconfig"})
        for a in bp.get("loadBalancerBackendAddresses") or []:
            ap = a.get("properties") or {}
            if ap.get("networkInterfaceIPConfiguration"):
                cid = ap["networkInterfaceIPConfiguration"]["id"].lower()
                seen.setdefault(cid, {"ipconfig": cid, "member": _parent(cid), "via": "ipconfig"})
            elif ap.get("ipAddress"):
                seen.setdefault(f"ip:{ap['ipAddress']}", {"member_ip": ap["ipAddress"], "via": "ip"})
        pools[b["id"].lower()] = {"name": b.get("name"), "members": list(seen.values())}
    probes = {x["id"].lower(): {"name": x.get("name"), **{k: (x.get("properties") or {}).get(k)
              for k in ("protocol", "port", "requestPath")}} for x in p.get("probes") or []}
    rules = []
    for x in p.get("loadBalancingRules") or []:
        xp = x.get("properties") or {}
        pool_ids = [_lid(xp["backendAddressPool"]["id"])] if xp.get("backendAddressPool") else \
            [_lid(b["id"]) for b in xp.get("backendAddressPools") or []]
        rules.append({"kind": "lb_rule", "name": x.get("name"), "frontend": _lid((xp.get("frontendIPConfiguration") or {}).get("id")),
                      "protocol": xp.get("protocol"), "frontend_port": xp.get("frontendPort"), "backend_port": xp.get("backendPort"),
                      "pools": pool_ids, "floating_ip": xp.get("enableFloatingIP"), "disable_outbound_snat": xp.get("disableOutboundSnat"),
                      "probe": probes.get(_lid((xp.get("probe") or {}).get("id")) or "", None),
                      "ha_ports": xp.get("protocol") == "All" and xp.get("frontendPort") == 0})
    for x in p.get("inboundNatRules") or []:
        xp = x.get("properties") or {}
        rule = {"kind": "inbound_nat", "name": x.get("name"), "frontend": _lid((xp.get("frontendIPConfiguration") or {}).get("id")),
                "protocol": xp.get("protocol"), "backend_port": xp.get("backendPort"), "pools": [], "direct_members": []}
        if xp.get("frontendPortRangeStart") is not None:
            rule["frontend_port"] = f"{xp['frontendPortRangeStart']}-{xp.get('frontendPortRangeEnd')}"
            rule["pools"] = [_lid((xp.get("backendAddressPool") or {}).get("id"))]
        else:
            rule["frontend_port"] = xp.get("frontendPort")
            if xp.get("backendIPConfiguration"):
                rule["direct_members"] = [_parent(xp["backendIPConfiguration"]["id"].lower())]
        rules.append(rule)
    outbound = [{"name": x.get("name"), "protocol": (x.get("properties") or {}).get("protocol"),
                 "frontends": [_lid(f["id"]) for f in (x.get("properties") or {}).get("frontendIPConfigurations") or []],
                 "pool": _lid(((x.get("properties") or {}).get("backendAddressPool") or {}).get("id")),
                 "allocated_ports": (x.get("properties") or {}).get("allocatedOutboundPorts")}
                for x in p.get("outboundRules") or []]
    lb["props"].update({"frontends": fe, "pools": pools, "rules": rules, "outbound_rules": outbound})
    for pool in pools.values():
        for m in pool["members"]:
            if "member" in m:
                g.link(lb["id"], m["member"], "BALANCES_TO")
    for r in rules:
        f = fe.get(r["frontend"] or "", {})
        src = f.get("public_ip_id") or lb["id"]
        members = list(r.get("direct_members", []))
        instances = len(r.get("direct_members", []))
        for pid in r["pools"]:
            for m in (pools.get(pid or "", {}) or {}).get("members", []):
                instances += 1
                members += [m["member"]] if "member" in m else _ip_targets(g, m["member_ip"])
        r["backend_instances"] = instances
        r["public"] = bool(f.get("public_ip_id"))
        r["frontend_ip"] = f.get("public_ip") or f.get("private_ip")
        r["entry"] = src
        for t in dict.fromkeys(members):
            g.link(src, t, "LB_FORWARDS", uniq=f"{lb['id']}|{r['name']}|{t}", load_balancer=lb["name"], lb_id=lb["id"],
                   rule=r["name"], rule_kind=r["kind"], frontend=f.get("name"),
                   frontend_ip=f.get("public_ip") or f.get("private_ip"), public=bool(f.get("public_ip_id")),
                   protocol=r["protocol"], frontend_port=r["frontend_port"], backend_port=r["backend_port"],
                   backend_instances=instances,
                   source_filter="none at the load balancer; NSGs on the backend apply")


# ----------------------------------------------------- application gateway
def _waf_state(g, policy_id: str | None, level: str) -> dict:
    n = g.nodes.get(policy_id or "")
    if not n or not n["in_scan"]:
        return {"source": level, "policy": policy_id, "mode": None, "state": None,
                "unknown": "WAF policy not in scan"}
    return {"source": level, "policy": n["name"], "mode": n["props"].get("waf_mode"),
            "state": n["props"].get("waf_state"), "rule_sets": n["props"].get("managed_rule_sets"),
            "custom_rules": n["props"].get("custom_rule_count")}


def _appgw_parse(g, gw: dict, r: dict, p: dict) -> None:
    tier = ((p.get("sku") or {}).get("tier") or "")
    idx = lambda key: {x["id"].lower(): x for x in p.get(key) or []}
    fes, ports, listeners = idx("frontendIPConfigurations"), idx("frontendPorts"), idx("httpListeners")
    pools, settings, pathmaps = idx("backendAddressPools"), idx("backendHttpSettingsCollection"), idx("urlPathMaps")
    gw_policy = _lid((p.get("firewallPolicy") or {}).get("id"))
    legacy = p.get("webApplicationFirewallConfiguration")

    def waf_for(listener: dict, path_policy: str | None) -> dict:
        if "waf" not in tier.lower():
            return {"source": "sku", "mode": None, "state": "not available", "because": f"sku tier = {tier}"}
        if path_policy:
            return _waf_state(g, path_policy, "path rule")
        lp = _lid(((listener.get("properties") or {}).get("firewallPolicy") or {}).get("id"))
        if lp:
            return _waf_state(g, lp, "listener")
        if gw_policy:
            return _waf_state(g, gw_policy, "gateway")
        if legacy:
            return {"source": "webApplicationFirewallConfiguration", "mode": legacy.get("firewallMode"),
                    "state": "Enabled" if legacy.get("enabled") else "Disabled"}
        return {"source": "none", "mode": None, "state": "no WAF policy or configuration"}

    def targets_of(pool_id: str | None) -> list[str]:
        pool = pools.get(pool_id or "")
        if not pool:
            return []
        pp = pool.get("properties") or {}
        out = [_parent(c["id"].lower()) for c in pp.get("backendIPConfigurations") or []]
        for a in pp.get("backendAddresses") or []:
            out += _ip_targets(g, a["ipAddress"]) if a.get("ipAddress") else _fqdn_targets(g, a["fqdn"]) if a.get("fqdn") else []
        return list(dict.fromkeys(out))

    routes = []
    for rule in p.get("requestRoutingRules") or []:
        rp = rule.get("properties") or {}
        lst = listeners.get(_lid((rp.get("httpListener") or {}).get("id")) or "", {})
        lp = lst.get("properties") or {}
        fe = fes.get(_lid((lp.get("frontendIPConfiguration") or {}).get("id")) or "", {})
        fep = fe.get("properties") or {}
        pip = _lid((fep.get("publicIPAddress") or {}).get("id"))
        port = ((ports.get(_lid((lp.get("frontendPort") or {}).get("id")) or "", {}).get("properties")) or {}).get("port")
        base = {"app_gateway": gw["name"], "app_gateway_id": gw["id"], "rule": rule.get("name"), "rule_type": rp.get("ruleType"),
                "priority": rp.get("priority"), "listener": lst.get("name"), "listener_protocol": lp.get("protocol"),
                "listener_port": port, "host_names": _l(lp.get("hostNames")) or _l([lp.get("hostName")]),
                "public": bool(pip), "frontend_ip": (g.nodes.get(pip, {}).get("props") or {}).get("ip_address") if pip
                else fep.get("privateIPAddress")}
        legs = []  # (paths, pool id, settings id, path policy)
        if rp.get("redirectConfiguration"):
            routes.append(base | {"redirect": rp["redirectConfiguration"]["id"].split("/")[-1], "backends": []})
            continue
        if rp.get("urlPathMap"):
            um = (pathmaps.get(_lid(rp["urlPathMap"]["id"]) or "", {}).get("properties")) or {}
            legs.append((["(default)"], _lid((um.get("defaultBackendAddressPool") or {}).get("id")),
                         _lid((um.get("defaultBackendHttpSettings") or {}).get("id")), None))
            for pr in um.get("pathRules") or []:
                prp = pr.get("properties") or {}
                legs.append((_l(prp.get("paths")), _lid((prp.get("backendAddressPool") or {}).get("id")),
                             _lid((prp.get("backendHttpSettings") or {}).get("id")),
                             _lid((prp.get("firewallPolicy") or {}).get("id"))))
        else:
            legs.append((["(all)"], _lid((rp.get("backendAddressPool") or {}).get("id")),
                         _lid((rp.get("backendHttpSettings") or {}).get("id")), None))
        for paths, pool_id, set_id, path_pol in legs:
            sp = (settings.get(set_id or "", {}).get("properties")) or {}
            waf = waf_for(lst, path_pol)
            tg = targets_of(pool_id)
            leg = base | {"paths": paths, "backend_pool": (pools.get(pool_id or "", {}) or {}).get("name"),
                          "backend_protocol": sp.get("protocol"), "backend_port": sp.get("port"),
                          "backend_host_override": sp.get("hostName"),
                          "pick_host_from_backend": sp.get("pickHostNameFromBackendAddress"), "waf": waf}
            routes.append(leg | {"backends": tg})
            for t in tg:
                g.link(pip or gw["id"], t, "APPGW_ROUTES", uniq=f"{gw['id']}|{rule.get('name')}|{'|'.join(paths)}|{t}",
                       **{k: v for k, v in leg.items()})
    gw["props"].update({"listener_routes": routes, "waf_policy": gw_policy, "sku_tier": tier,
                        "ssl_policy": (p.get("sslPolicy") or {}).get("policyName") or (p.get("sslPolicy") or {}).get("policyType")})


# ------------------------------------------------------------ routes, hybrid
def _route_edges(g, rt: dict) -> None:
    for route in rt["props"].get("routes", []):
        if (route.get("next_hop_type") or "").lower() == "virtualappliance" and route.get("next_hop_ip"):
            for t in _ip_targets(g, route["next_hop_ip"]):
                g.link(rt["id"], t, "NEXT_HOP", uniq=route["name"], route=route["name"],
                       prefix=route["address_prefix"], next_hop_ip=route["next_hop_ip"])


def _connection(g, nid: str, p: dict) -> None:
    gw1 = _lid((p.get("virtualNetworkGateway1") or {}).get("id"))
    remote = [(_lid((p.get(k) or {}).get("id")), k) for k in ("localNetworkGateway2", "virtualNetworkGateway2", "peer")]
    remote = [(x, k) for x, k in remote if x]
    info = {"connection_type": p.get("connectionType"), "status": p.get("connectionStatus"),
            "enable_bgp": p.get("enableBgp"), "policy_based_selectors": p.get("usePolicyBasedTrafficSelectors"),
            "ipsec_policies": p.get("ipsecPolicies") or [], "routing_weight": p.get("routingWeight"),
            "connection_protocol": p.get("connectionProtocol"),
            "express_route_gateway_bypass": p.get("expressRouteGatewayBypass")}
    g.nodes[nid]["props"].update(info)
    if gw1:
        g.link(nid, gw1, "ATTACHED_TO")
    for rid, _ in remote:
        g.link(nid, rid, "ATTACHED_TO")
        if gw1:
            g.link(gw1, rid, "HYBRID_CONNECTION", uniq=nid, connection=g.nodes[nid]["name"],
                   **{k: v for k, v in info.items() if k != "ipsec_policies"})


# --------------------------------------------------------- per-kind parsing
def parse_kind(g, nid: str, r: dict, p: dict, arm: dict) -> None:
    """Called in pass 2 for edge-device kinds (after generic handlers)."""
    n = g.nodes[nid]
    kind = n["kind"]
    if kind == "ipgroup":
        n["props"]["ip_addresses"] = _l(p.get("ipAddresses"))
    elif kind == "fwpolicy":
        n["props"].update({"base_policy": _lid((p.get("basePolicy") or {}).get("id")),
                           "threat_intel_mode": p.get("threatIntelMode"),
                           "idps_mode": (p.get("intrusionDetection") or {}).get("mode"),
                           "dns_proxy": (p.get("dnsSettings") or {}).get("enableProxy"),
                           "policy_sku": (p.get("sku") or {}).get("tier")})
        if n["props"]["base_policy"]:
            g.link(nid, n["props"]["base_policy"], "INHERITS_FROM")
        item = (arm or {}).get("rule_collection_groups")
        if item is None:
            n["props"]["rule_groups_error"] = "not collected (scan ran without ARM enrichment)"
        elif "error" in item:
            n["props"]["rule_groups_error"] = f"ARM read failed (HTTP {item.get('status')})"
        else:
            n["props"]["rules"] = _parse_policy_groups(item["data"], n["name"])
            n["props"]["rules_source"] = f"arm {item['api']}"
            for rule in n["props"]["rules"]:
                for ipg in rule["source_ip_groups"] + rule["destination_ip_groups"]:
                    g.link(nid, ipg, "USES_IP_GROUP", uniq=f"{rule['collection']}|{rule['name']}|{ipg}", rule=rule["name"])
    elif kind == "wafpolicy":
        ps = p.get("policySettings") or {}
        n["props"].update({"waf_mode": ps.get("mode"), "waf_state": ps.get("state"),
                           "request_body_check": ps.get("requestBodyCheck"),
                           "managed_rule_sets": [f"{m.get('ruleSetType')} {m.get('ruleSetVersion')}"
                                                 for m in (p.get("managedRules") or {}).get("managedRuleSets") or []],
                           "custom_rule_count": len(p.get("customRules") or [])})
    elif kind == "firewall":
        n["props"]["threat_intel_mode"] = p.get("threatIntelMode")
        n["props"]["classic_rules"] = _parse_classic(p, n["name"])
        for rule in n["props"]["classic_rules"]:
            for ipg in rule["source_ip_groups"] + rule["destination_ip_groups"]:
                g.link(nid, ipg, "USES_IP_GROUP", uniq=f"{rule['collection']}|{rule['name']}|{ipg}", rule=rule["name"])
        hub = p.get("hubIPAddresses") or {}
        if hub.get("privateIPAddress"):
            g.index_ip(hub["privateIPAddress"], nid)
        for a in ((hub.get("publicIPs") or {}).get("addresses")) or []:
            g.index_ip(a.get("address"), nid)
        g.link(nid, _lid((p.get("virtualHub") or {}).get("id")), "IN_HUB")
    elif kind == "vnetgw":
        bgp = p.get("bgpSettings") or {}
        vpc = p.get("vpnClientConfiguration") or {}
        n["props"].update({"active_active": p.get("activeActive"), "enable_bgp": p.get("enableBgp"),
                           "bgp_asn": bgp.get("asn"), "bgp_peering_address": bgp.get("bgpPeeringAddress"),
                           "point_to_site": {
                               "address_pool": (vpc.get("vpnClientAddressPool") or {}).get("addressPrefixes", []),
                               "auth_types": vpc.get("vpnAuthenticationTypes"), "protocols": vpc.get("vpnClientProtocols"),
                               "aad_tenant": vpc.get("aadTenant"), "radius_server": vpc.get("radiusServerAddress"),
                           } if vpc else None})
    elif kind == "lng":
        bgp = p.get("bgpSettings") or {}
        n["props"].update({"gateway_ip": p.get("gatewayIpAddress"), "fqdn": p.get("fqdn"),
                           "address_prefixes": (p.get("localNetworkAddressSpace") or {}).get("addressPrefixes", []),
                           "bgp_asn": bgp.get("asn"), "bgp_peering_address": bgp.get("bgpPeeringAddress")})
    elif kind == "ercircuit":
        sp = p.get("serviceProviderProperties") or {}
        n["props"].update({"provider": sp.get("serviceProviderName"), "peering_location": sp.get("peeringLocation"),
                           "bandwidth_mbps": sp.get("bandwidthInMbps"),
                           "provider_state": p.get("serviceProviderProvisioningState"),
                           "circuit_state": p.get("circuitProvisioningState"),
                           "peerings": [{"type": (x.get("properties") or {}).get("peeringType"),
                                         "state": (x.get("properties") or {}).get("state"),
                                         "primary_prefix": (x.get("properties") or {}).get("primaryPeerAddressPrefix"),
                                         "secondary_prefix": (x.get("properties") or {}).get("secondaryPeerAddressPrefix"),
                                         "vlan": (x.get("properties") or {}).get("vlanId"),
                                         "peer_asn": (x.get("properties") or {}).get("peerASN")}
                                        for x in p.get("peerings") or []]})
    elif kind == "gwconnection":
        _connection(g, nid, p)
    elif kind == "vmss":
        prof = ((p.get("virtualMachineProfile") or {}).get("networkProfile") or {})
        public = False
        for cfg in prof.get("networkInterfaceConfigurations") or []:
            cp = cfg.get("properties") or {}
            g.link(nid, _lid((cp.get("networkSecurityGroup") or {}).get("id")), "PROTECTED_BY")
            for ic in cp.get("ipConfigurations") or []:
                icp = ic.get("properties") or {}
                g.link(nid, _lid((icp.get("subnet") or {}).get("id")), "IN_SUBNET")
                public |= bool(icp.get("publicIPAddressConfiguration"))
                for pool in icp.get("loadBalancerBackendAddressPools") or []:
                    g.link(_parent(pool["id"].lower()), nid, "BALANCES_TO")
                for pool in icp.get("applicationGatewayBackendAddressPools") or []:
                    g.link(_parent(pool["id"].lower()), nid, "BALANCES_TO")
        n["props"]["instance_public_ips"] = public
        n["props"]["capacity"] = (r.get("sku") or {}).get("capacity") if isinstance(r.get("sku"), dict) else None


def post_pass(g, rows: list[dict]) -> None:
    """After every node and IP is known: LB, App Gateway, DNAT, routes."""
    for n in g.nodes.values():
        for h in (n["props"].get("hostnames") or []):
            g.by_fqdn[h.lower()].add(n["id"])
    node_rg = {}
    for r in rows:
        if r["type"].lower() == "microsoft.containerservice/managedclusters":
            nrg = ((r.get("properties") or {}).get("nodeResourceGroup") or "").lower()
            if nrg:
                node_rg[(r["subscriptionId"].lower(), nrg)] = r["id"].lower()
    for r in rows:
        nid = r["id"].lower()
        kind = g.nodes[nid]["kind"]
        p = r.get("properties") or {}
        if kind == "lb":
            _lb_parse(g, g.nodes[nid], p)
            aks = node_rg.get((r["subscriptionId"].lower(), (r.get("resourceGroup") or "").lower()))
            if aks:
                an = g.nodes[aks]
                g.nodes[nid]["props"]["owning_aks"] = {
                    "cluster": an["name"], "power_state": an["props"].get("power_state"),
                    "because": "load balancer is in the cluster's nodeResourceGroup"}
                g.link(aks, nid, "MANAGES")
        elif kind == "appgw":
            _appgw_parse(g, g.nodes[nid], r, p)
    for n in list(g.nodes.values()):
        if n["kind"] == "firewall" and n["in_scan"]:
            _dnat_edges(g, n)
        elif n["kind"] == "routetable" and n["in_scan"]:
            _route_edges(g, n)
