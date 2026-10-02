"""Turns a raw Resource Graph snapshot into the infrastructure graph.

build_graph() is a pure function of the raw snapshot, so the graph can be
rebuilt (and extended in later phases) without re-scanning Azure.

All ids are lower-cased because ARM references differ in casing between
resources. Every node keeps its original-case id in `arm_id`.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any, Iterable

from . import __version__
from . import access as A
from . import edge as E
from .queries import KINDS

INTERNET_TOKENS = {"*", "internet", "0.0.0.0/0", "::/0", "any"}


# ---------------------------------------------------------------- helpers
def _lid(v: str | None) -> str | None:
    return v.lower() if v else None


def _ref(obj: Any) -> str | None:
    return _lid(obj.get("id")) if isinstance(obj, dict) else None


def _refs(items: Any) -> list[str]:
    return [r for r in (_ref(i) for i in (items or [])) if r]


def _parent(resource_id: str) -> str:
    """/subscriptions/s/resourceGroups/g/providers/ns/type/name[/child/...] -> top resource."""
    return "/".join(resource_id.split("/")[:9])


CHILD_KINDS = {"subnets": "subnet"}


def type_of(resource_id: str) -> str | None:
    """/subscriptions/s/resourcegroups/g/providers/ns/t1/n1/t2/n2 -> 'ns/t1/t2'."""
    parts = resource_id.lower().split("/")
    if len(parts) < 9 or parts[5] != "providers":
        return None
    return "/".join([parts[6]] + parts[7::2])


def kind_for(rtype: str) -> str:
    rtype = rtype.lower()
    if rtype in KINDS:
        return KINDS[rtype]
    last = rtype.split("/")[-1]
    if last in CHILD_KINDS:
        return CHILD_KINDS[last]
    return rtype.removeprefix("microsoft.")


def _kind_of(resource_id: str) -> str:
    parts = resource_id.lower().split("/")
    if len(parts) == 5 and parts[3] == "resourcegroups":
        return "resourcegroup"
    t = type_of(resource_id)
    return kind_for(t) if t else "resource"


def _listify(single: Any, many: Any) -> list[str]:
    out = list(many or [])
    if single:
        out.append(single)
    return [str(x) for x in out]


def _norm_rule(r: dict, default: bool) -> dict:
    p = r.get("properties", {})
    return {
        "name": r.get("name"),
        "priority": p.get("priority"),
        "direction": p.get("direction"),
        "access": p.get("access"),
        "protocol": p.get("protocol"),
        "source": _listify(p.get("sourceAddressPrefix"), p.get("sourceAddressPrefixes")),
        "source_asgs": _refs(p.get("sourceApplicationSecurityGroups")),
        "source_ports": _listify(p.get("sourcePortRange"), p.get("sourcePortRanges")),
        "destination": _listify(p.get("destinationAddressPrefix"), p.get("destinationAddressPrefixes")),
        "destination_asgs": _refs(p.get("destinationApplicationSecurityGroups")),
        "destination_ports": _listify(p.get("destinationPortRange"), p.get("destinationPortRanges")),
        "description": p.get("description"),
        "default": default,
    }


def _ip_configs(props: dict, key: str = "ipConfigurations") -> list[dict]:
    return [c.get("properties", {}) for c in props.get(key) or []]


# ------------------------------------------------------------------ graph
class InfraGraph:
    def __init__(self, meta: dict | None = None):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple] = set()
        self.out: dict[str, list[dict]] = defaultdict(list)
        self.inc: dict[str, list[dict]] = defaultdict(list)
        self.by_ip: dict[str, set[str]] = defaultdict(set)
        self.by_fqdn: dict[str, set[str]] = defaultdict(set)
        self.meta = meta or {}

    # ---- construction ----------------------------------------------------
    def add_node(self, nid: str, kind: str, name: str, **attrs) -> dict:
        node = self.nodes.get(nid)
        declared = attrs.get("in_scan", True)
        if node is None:
            node = {"id": nid, "kind": kind, "name": name, "in_scan": declared, "props": {}}
            self.nodes[nid] = node
        elif declared and not node["in_scan"]:
            # A placeholder made by an earlier reference is now declared for real
            # (e.g. a NIC processed before its VNet): promote it. Never downgrade.
            node.update(kind=kind, name=name, in_scan=True)
        node.update({k: v for k, v in attrs.items() if k not in ("props", "in_scan")})
        node["props"].update(attrs.get("props", {}))
        return node

    def ensure(self, nid: str | None) -> str | None:
        """Make sure a referenced id exists; unknown targets become external nodes."""
        if not nid:
            return None
        if nid not in self.nodes:
            name = nid.rstrip("/").split("/")[-1]
            self.add_node(nid, _kind_of(nid), name, in_scan=False)
        return nid

    def has_edge(self, a: str, b: str) -> bool:
        return any(e["dst"] == b for e in self.out.get(a, [])) or any(e["dst"] == a for e in self.out.get(b, []))

    def link(self, src: str | None, dst: str | None, rel: str, uniq: str | None = None, **attrs) -> None:
        src, dst = self.ensure(src), self.ensure(dst)
        key = (src, dst, rel, uniq)
        if not src or not dst or src == dst or key in self._edge_keys:
            return
        self._edge_keys.add(key)
        e = {"src": src, "dst": dst, "rel": rel, **attrs}
        if uniq:
            e["uniq"] = uniq
        self.edges.append(e)
        self.out[src].append(e)
        self.inc[dst].append(e)

    def index_ip(self, ip: str | None, nid: str) -> None:
        if ip:
            self.by_ip[ip].add(nid)
            ips = self.nodes[nid]["props"].setdefault("ips", []) if nid in self.nodes else []
            if ip not in ips:
                ips.append(ip)

    def containing_ranges(self, ip: str) -> list[dict]:
        """Declared address ranges that contain an IP: subnets, on-prem (local network gateway)
        prefixes and point-to-site client pools."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        hits = []
        for n in self.nodes.values():
            if n["kind"] == "subnet":
                cidrs, what = n["props"].get("address_prefixes", []), "subnet"
            elif n["kind"] == "lng":
                cidrs, what = n["props"].get("address_prefixes", []), "on-premises range (local network gateway)"
            elif n["kind"] == "vnetgw" and n["props"].get("point_to_site"):
                cidrs, what = n["props"]["point_to_site"].get("address_pool", []), "point-to-site client pool"
            else:
                continue
            for cidr in cidrs:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        hits.append({"node": n, "range": cidr, "what": what})
                except ValueError:
                    pass
        return hits

    # ---- navigation ------------------------------------------------------
    def neighbors(self, nid: str, rel: str | None = None, direction: str = "both") -> list[tuple[dict, dict]]:
        res = []
        if direction in ("out", "both"):
            res += [(e, self.nodes[e["dst"]]) for e in self.out.get(nid, []) if rel in (None, e["rel"])]
        if direction in ("in", "both"):
            res += [(e, self.nodes[e["src"]]) for e in self.inc.get(nid, []) if rel in (None, e["rel"])]
        return res

    def one(self, nid: str, rel: str, direction: str = "out", kind: str | None = None) -> dict | None:
        for _, n in self.neighbors(nid, rel, direction):
            if kind is None or n["kind"] == kind:
                return n
        return None

    def resolve(self, query: str, limit: int = 20) -> list[dict]:
        """Match by full id, IP address, exact name, then name substring."""
        q = query.strip()
        ql = q.lower()
        if ql in self.nodes:
            return [self.nodes[ql]]
        if q in self.by_ip:
            return [self.nodes[n] for n in sorted(self.by_ip[q])][:limit]
        exact = [n for n in self.nodes.values() if n["name"].lower() == ql]
        if exact:
            return exact[:limit]
        return [n for n in self.nodes.values() if ql in n["name"].lower()][:limit]

    def subnet_for_ip(self, ip: str) -> list[dict]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        hits = []
        for n in self.nodes.values():
            if n["kind"] != "subnet":
                continue
            for cidr in n["props"].get("address_prefixes", []):
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        hits.append(n)
                except ValueError:
                    pass
        return hits

    # ---- serialization ---------------------------------------------------
    def to_dict(self) -> dict:
        return {"meta": self.meta, "nodes": list(self.nodes.values()), "edges": self.edges}

    @classmethod
    def from_dict(cls, d: dict) -> "InfraGraph":
        g = cls(d.get("meta"))
        for n in d["nodes"]:
            g.nodes[n["id"]] = n
        for e in d["edges"]:
            g._edge_keys.add((e["src"], e["dst"], e["rel"], e.get("uniq")))
            g.edges.append(e)
            g.out[e["src"]].append(e)
            g.inc[e["dst"]].append(e)
        for n in g.nodes.values():
            for ip in n["props"].get("ips", []) + n["props"].get("private_ips", []) + [n["props"].get("ip_address")]:
                g.index_ip(ip, n["id"])
            for h in n["props"].get("hostnames") or []:
                g.by_fqdn[h.lower()].add(n["id"])
        return g


# ---------------------------------------------------------------- builder
INTERNET = "internet"
_ARM_ID = re.compile(r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/.+", re.I)
_SKIP_REF_KEYS = {"privateEndpointConnections"}


def _resource_scopes(nid: str) -> list[str]:
    """Resource id and its parent resources: .../servers/a/databases/b -> [db, server]."""
    parts = nid.split("/")
    out = []
    while len(parts) >= 9:
        out.append("/".join(parts))
        parts = parts[:-2]
    return out


def build_graph(raw: dict) -> InfraGraph:
    subs = {s["id"].lower(): s for s in raw.get("subscriptions", [])}
    g = InfraGraph(meta={
        "schema": raw.get("schema", 1),
        "collected_at": raw.get("collected_at"),
        "subscriptions": raw.get("subscriptions", []),
        "not_visible": raw.get("not_visible", []),
        "resource_rows": len(raw.get("resources", [])),
        "enriched": raw.get("enriched", False),
        "rbac_status": raw.get("rbac_status", "not collected (schema 1 snapshot)"),
        "rbac_coverage": raw.get("rbac_coverage", {"subscription_and_below": raw.get("rbac_status") == "ok",
                                                   "above_subscription": False}),
        "role_definitions": raw.get("role_definitions", {}),
        "builder_version": __version__,
        "errors": raw.get("errors", []),
        "enrichment_errors": [{"resource": rid, "call": k, "status": v.get("status")}
                              for rid, calls in sorted(raw.get("arm", {}).items())
                              for k, v in calls.items() if "error" in v],
    })

    for sid, s in subs.items():
        g.add_node(f"/subscriptions/{sid}", "subscription", s.get("name") or sid,
                   props={"state": s.get("state"), "tenant_id": s.get("tenantId")})
    for c in raw.get("containers", []):
        cid = _lid(c["id"])
        if c["type"].lower() == "microsoft.resources/subscriptions":
            chain = ((c.get("properties") or {}).get("managementGroupAncestorsChain")) or []
            if cid in g.nodes:
                g.nodes[cid]["props"]["management_groups"] = [
                    f"/providers/microsoft.management/managementgroups/{m['name'].lower()}" for m in chain]
        else:
            g.add_node(cid, "resourcegroup", c["name"], arm_id=c["id"], location=c.get("location"),
                       subscription=_lid(c.get("subscriptionId")), tags=c.get("tags") or {})
            g.link(f"/subscriptions/{_lid(c.get('subscriptionId'))}", cid, "CONTAINS")

    rows = raw.get("resources", [])
    arm = raw.get("arm", {})
    # Pass 1: every resource becomes a node before any link is drawn.
    for r in rows:
        nid = _lid(r["id"])
        ident = r.get("identity") or {}
        g.add_node(nid, kind_for(r["type"]), r["name"], arm_id=r["id"], type=r["type"].lower(),
                   location=r.get("location"), resource_group=r.get("resourceGroup"),
                   subscription=_lid(r.get("subscriptionId")), tags=r.get("tags") or {},
                   props={
                       "sku": (r.get("sku") or {}).get("name") if isinstance(r.get("sku"), dict) else r.get("sku"),
                       "kind": r.get("kind"),
                       "identity": {
                           "type": ident.get("type"),
                           "principal_id": _lid(ident.get("principalId")),
                           "user_assigned": sorted(_lid(k) for k in (ident.get("userAssignedIdentities") or {})),
                       } if ident else None,
                   })

    # Pass 2: containment, typed relationships, identity, access.
    for r in rows:
        nid = _lid(r["id"])
        p = r.get("properties") or {}
        scopes = _resource_scopes(nid)
        if len(scopes) > 1 and scopes[1] in g.nodes:
            g.link(scopes[1], nid, "CONTAINS")
        elif r.get("resourceGroup"):
            rg = f"/subscriptions/{_lid(r['subscriptionId'])}/resourcegroups/{r['resourceGroup'].lower()}"
            if rg in g.nodes:
                g.link(rg, nid, "CONTAINS")
        handler = _HANDLERS.get(g.nodes[nid]["kind"])
        if handler:
            handler(g, nid, r, p)
        E.parse_kind(g, nid, r, p, arm.get(nid))
        for uami in (g.nodes[nid]["props"].get("identity") or {}).get("user_assigned", []):
            g.link(nid, uami, "USES_IDENTITY")
        if r.get("managedBy"):
            g.link(nid, _lid(r["managedBy"]), "MANAGED_BY")
        prof = A.evaluate(r, arm.get(nid))
        if prof is not None:
            g.nodes[nid]["props"]["access"] = prof

    E.post_pass(g, rows)
    for n in g.nodes.values():  # Container Apps: the environment can override app ingress
        prof = n["props"].get("access")
        if prof and "_needs_env" in prof:
            env_node = g.nodes.get(prof.get("_needs_env") or "")
            env = env_node["props"].get("access") if env_node and env_node["in_scan"] else None
            A.finalize_container_app(prof, env, env_node["name"] if env_node else None)
    _access_edges(g)
    _rbac(g, raw)
    for r in rows:
        _generic_refs(g, _lid(r["id"]), r.get("properties") or {})
    return g


def _access_edges(g: InfraGraph) -> None:
    pips = [(int(ipaddress.IPv4Address(n["props"]["ip_address"])), n["id"])
            for n in g.nodes.values()
            if n["kind"] == "pip" and n["props"].get("ip_address") and ":" not in n["props"]["ip_address"]]
    open_states = {"all_networks", "all_networks_with_denies"}
    for n in list(g.nodes.values()):
        prof = n["props"].get("access")
        if not prof:
            continue
        for pe in prof["private_endpoints"]:
            g.link(pe["private_endpoint"], n["id"], "CONNECTS_TO", status=pe["status"])
        listed = {pe["private_endpoint"] for pe in prof["private_endpoints"]}
        for e in g.inc.get(n["id"], []):
            if e["rel"] == "CONNECTS_TO" and g.nodes[e["src"]]["kind"] == "pe" and e["src"] not in listed:
                prof["private_endpoints"].append({"private_endpoint": e["src"], "status": e.get("status"),
                                                  "source": "private endpoint resource (target lists none itself)"})
        state = prof["public_endpoint"]
        if state in open_states:
            if INTERNET not in g.nodes:
                g.add_node(INTERNET, "internet", "Internet (any IP)", in_scan=False)
            g.link(INTERNET, n["id"], "OPEN_TO_ALL_NETWORKS", because=prof["because"])
        if state == "restricted":  # for open resources an allow rule adds nothing, so no edge is drawn
            for sid in prof["allow_subnets"]:
                g.link(sid, n["id"], "VNET_RULE_ALLOWS")
            for spec in prof["allow_ip_ranges"]:
                rng = A.ip_range(spec) if "-" not in spec else A._pair(*spec.split("-", 1))
                if not rng:
                    continue
                for ip, pid in pips:
                    if rng[0] <= ip <= rng[1]:
                        g.link(pid, n["id"], "IP_RULE_ALLOWS", uniq=spec, rule=spec)


def _rbac(g: InfraGraph, raw: dict) -> None:
    defs = raw.get("role_definitions", {})
    by_principal: dict[str, str] = {}
    for n in g.nodes.values():
        pid = (n["props"].get("identity") or {}).get("principal_id")
        if pid and "systemassigned" in ((n["props"]["identity"] or {}).get("type") or "").lower():
            by_principal[pid] = n["id"]
    for r in raw.get("resources", []):
        if r["type"].lower() == "microsoft.managedidentity/userassignedidentities":
            pid = _lid((r.get("properties") or {}).get("principalId"))
            if pid:
                by_principal[pid] = _lid(r["id"])
                g.nodes[_lid(r["id"])]["props"]["principal_id"] = pid
    for a in raw.get("role_assignments", []):
        p = a.get("properties") or {}
        pid, scope = _lid(p.get("principalId")), _lid(p.get("scope"))
        if not pid or not scope:
            continue
        src = by_principal.get(pid)
        if not src:
            src = f"principal:{pid}"
            if src not in g.nodes:
                g.add_node(src, "principal", f"{p.get('principalType') or 'Principal'} {pid}",
                           props={"principal_id": pid, "principal_type": p.get("principalType")})
        if scope not in g.nodes:
            name = "root" if scope == "/" else scope.rstrip("/").split("/")[-1]
            kind = "managementgroup" if "/managementgroups/" in scope else ("root" if scope == "/" else _kind_of(scope))
            g.add_node(scope, kind, name, in_scan=False)
        guid = (p.get("roleDefinitionId") or "").rstrip("/").split("/")[-1].lower()
        d = defs.get(guid, {})
        g.link(src, scope, "HAS_ROLE", uniq=_lid(a["id"]),
               role=d.get("name"), role_type=d.get("type"), role_definition_id=guid,
               principal_id=pid, principal_type=p.get("principalType"),
               condition=p.get("condition"), assignment_id=a["id"])


def _generic_refs(g: InfraGraph, nid: str, props: dict, cap: int = 200) -> None:
    """Any ARM id written in a resource's properties is a declared reference. Record it
    with its property path, unless a typed relationship already links the two."""
    found: list[tuple[str, str]] = []

    def walk(v: Any, path: str, depth: int) -> None:
        if len(found) >= cap or depth > 12:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if k not in _SKIP_REF_KEYS:
                    walk(x, f"{path}.{k}", depth + 1)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]", depth + 1)
        elif isinstance(v, str) and _ARM_ID.match(v):
            found.append((v.lower(), path))

    walk(props, "properties", 0)
    for target, path in found:
        if target == nid or target.startswith(nid + "/"):
            continue
        parts = target.split("/")
        if target in g.nodes:
            t = target
        elif len(parts) >= 11 and parts[9] == "subnets":
            t = "/".join(parts[:11])
        else:
            t = _parent(target)
        if t == nid or t.startswith(nid + "/") or g.has_edge(nid, t):
            continue
        g.link(nid, t, "REFERENCES", uniq=path, path=path)


def _vnet(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.nodes[nid]["props"].update({
        "address_space": (p.get("addressSpace") or {}).get("addressPrefixes", []),
        "dns_servers": (p.get("dhcpOptions") or {}).get("dnsServers", []),
        "ddos_protection": p.get("enableDdosProtection", False),
    })
    for s in p.get("subnets") or []:
        sp = s.get("properties") or {}
        sid = _lid(s["id"])
        g.add_node(sid, "subnet", s["name"], arm_id=s["id"], location=r.get("location"),
                   resource_group=r.get("resourceGroup"), subscription=_lid(r.get("subscriptionId")),
                   props={
                       "address_prefixes": _listify(sp.get("addressPrefix"), sp.get("addressPrefixes")),
                       "delegations": [d.get("properties", {}).get("serviceName") for d in sp.get("delegations") or []],
                       "private_endpoint_network_policies": sp.get("privateEndpointNetworkPolicies"),
                       "default_outbound_access": sp.get("defaultOutboundAccess"),
                       "service_endpoints": [x.get("service") for x in sp.get("serviceEndpoints") or []],
                   })
        g.link(nid, sid, "CONTAINS")
        g.link(sid, _ref(sp.get("networkSecurityGroup")), "PROTECTED_BY")
        g.link(sid, _ref(sp.get("routeTable")), "ROUTES_VIA")
        g.link(sid, _ref(sp.get("natGateway")), "EGRESS_VIA")
    for peer in p.get("virtualNetworkPeerings") or []:
        pp = peer.get("properties") or {}
        g.link(nid, _ref(pp.get("remoteVirtualNetwork")), "PEERED_WITH",
               state=pp.get("peeringState"),
               allow_forwarded_traffic=pp.get("allowForwardedTraffic"),
               allow_gateway_transit=pp.get("allowGatewayTransit"),
               use_remote_gateways=pp.get("useRemoteGateways"))


def _nsg(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    rules = [_norm_rule(x, False) for x in p.get("securityRules") or []]
    rules += [_norm_rule(x, True) for x in p.get("defaultSecurityRules") or []]
    g.nodes[nid]["props"]["rules"] = rules
    for sid in _refs(p.get("subnets")):
        g.link(sid, nid, "PROTECTED_BY")
    for nic in _refs(p.get("networkInterfaces")):
        g.link(nic, nid, "PROTECTED_BY")
    for rule in rules:
        for asg in rule["source_asgs"] + rule["destination_asgs"]:
            g.link(nid, asg, "REFERENCES")


def _nic(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    ips = []
    for c in _ip_configs(p):
        ip = c.get("privateIPAddress")
        ips.append(ip)
        g.index_ip(ip, nid)
        g.link(nid, _ref(c.get("subnet")), "IN_SUBNET")
        g.link(nid, _ref(c.get("publicIPAddress")), "HAS_PUBLIC_IP")
        for asg in _refs(c.get("applicationSecurityGroups")):
            g.link(nid, asg, "MEMBER_OF")
        for pool in _refs(c.get("loadBalancerBackendAddressPools")):
            g.link(_parent(pool), nid, "BALANCES_TO")
        for pool in _refs(c.get("applicationGatewayBackendAddressPools")):
            g.link(_parent(pool), nid, "BALANCES_TO")
    g.nodes[nid]["props"].update({
        "private_ips": [i for i in ips if i],
        "ip_forwarding": p.get("enableIPForwarding", False),
        "accelerated_networking": p.get("enableAcceleratedNetworking", False),
    })
    g.link(nid, _ref(p.get("networkSecurityGroup")), "PROTECTED_BY")
    g.link(_ref(p.get("virtualMachine")), nid, "HAS_NIC")
    g.link(_ref(p.get("privateEndpoint")), nid, "HAS_NIC")


def _pip(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    ip = p.get("ipAddress")
    g.index_ip(ip, nid)
    g.nodes[nid]["props"].update({
        "ip_address": ip,
        "allocation": p.get("publicIPAllocationMethod"),
        "fqdn": (p.get("dnsSettings") or {}).get("fqdn"),
        "sku": (r.get("sku") or {}).get("name"),
    })
    if g.nodes[nid]["props"].get("fqdn"):
        g.nodes[nid]["props"]["hostnames"] = [g.nodes[nid]["props"]["fqdn"].lower()]
    owner = _ref(p.get("ipConfiguration"))
    if owner:
        g.link(_parent(owner), nid, "HAS_PUBLIC_IP")
    g.link(_ref(p.get("natGateway")), nid, "HAS_PUBLIC_IP")


def _vm(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.nodes[nid]["props"].update({
        "vm_size": (p.get("hardwareProfile") or {}).get("vmSize"),
        "os_type": ((p.get("storageProfile") or {}).get("osDisk") or {}).get("osType"),
        "power_state": (((p.get("extended") or {}).get("instanceView") or {}).get("powerState") or {}).get("code"),
    })
    for nic in _refs((p.get("networkProfile") or {}).get("networkInterfaces")):
        g.link(nid, nic, "HAS_NIC")


def _routetable(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.nodes[nid]["props"].update({
        "disable_bgp_route_propagation": p.get("disableBgpRoutePropagation", False),
        "routes": [{
            "name": x.get("name"),
            "address_prefix": x.get("properties", {}).get("addressPrefix"),
            "next_hop_type": x.get("properties", {}).get("nextHopType"),
            "next_hop_ip": x.get("properties", {}).get("nextHopIpAddress"),
        } for x in p.get("routes") or []],
    })
    for sid in _refs(p.get("subnets")):
        g.link(sid, nid, "ROUTES_VIA")


def _pe(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.link(nid, _ref(p.get("subnet")), "IN_SUBNET")
    groups = []
    for key in ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections"):
        for c in p.get(key) or []:
            cp = c.get("properties") or {}
            groups += cp.get("groupIds") or []
            target = _lid(cp.get("privateLinkServiceId"))
            g.link(nid, target, "CONNECTS_TO",
                   status=(cp.get("privateLinkServiceConnectionState") or {}).get("status"),
                   manual=key.startswith("manual"))
    g.nodes[nid]["props"]["group_ids"] = groups
    for nic in _refs(p.get("networkInterfaces")):
        g.link(nid, nic, "HAS_NIC")


def _frontends(g: InfraGraph, nid: str, configs: Iterable[dict]) -> list[str]:
    ips = []
    for c in configs:
        g.link(nid, _ref(c.get("subnet")), "IN_SUBNET")
        g.link(nid, _ref(c.get("publicIPAddress")), "HAS_PUBLIC_IP")
        ip = c.get("privateIPAddress")
        if ip:
            ips.append(ip)
            g.index_ip(ip, nid)
    return ips


def _lb(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    ips = _frontends(g, nid, _ip_configs(p, "frontendIPConfigurations"))
    g.nodes[nid]["props"].update({"private_ips": ips, "sku": (r.get("sku") or {}).get("name")})


def _appgw(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    _frontends(g, nid, _ip_configs(p, "gatewayIPConfigurations"))
    ips = _frontends(g, nid, _ip_configs(p, "frontendIPConfigurations"))
    g.nodes[nid]["props"].update({"private_ips": ips, "sku": (p.get("sku") or {}).get("tier")})


def _ipconf_resource(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    ips = _frontends(g, nid, _ip_configs(p))
    props = {"private_ips": ips}
    kind = g.nodes[nid]["kind"]
    if kind == "firewall":
        props.update(sku=(p.get("sku") or {}).get("tier"), policy=_ref(p.get("firewallPolicy")))
        if props["policy"]:
            g.link(nid, props["policy"], "USES_POLICY")
    if kind == "vnetgw":
        props.update(gateway_type=p.get("gatewayType"), vpn_type=p.get("vpnType"),
                     sku=(p.get("sku") or {}).get("name"))
    if kind == "bastion":
        props.update(sku=(r.get("sku") or {}).get("name"))
    g.nodes[nid]["props"].update(props)


def _natgw(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    for pip in _refs(p.get("publicIpAddresses")):
        g.link(nid, pip, "HAS_PUBLIC_IP")
    for sid in _refs(p.get("subnets")):
        g.link(sid, nid, "EGRESS_VIA")


def _in_subnets(g: InfraGraph, nid: str, subnet_ids: Iterable[str | None], rel: str = "IN_SUBNET") -> None:
    for sid in subnet_ids:
        if sid:
            g.link(nid, sid.lower(), rel)


def _aks(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.nodes[nid]["props"]["power_state"] = (p.get("powerState") or {}).get("code")
    g.nodes[nid]["props"]["node_resource_group"] = p.get("nodeResourceGroup")
    _in_subnets(g, nid, [a.get("vnetSubnetID") for a in p.get("agentPoolProfiles") or []])


def _subnet_prop(key: str):
    def h(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
        _in_subnets(g, nid, [p.get(key)])
    return h


def _flex_net(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    _in_subnets(g, nid, [(p.get("network") or {}).get("delegatedSubnetResourceId")])


def _webapp(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    g.nodes[nid]["props"]["hostnames"] = sorted({h.lower() for h in
                                                 [p.get("defaultHostName")] + (p.get("hostNames") or []) if h})
    _in_subnets(g, nid, [p.get("virtualNetworkSubnetId")], "VNET_INTEGRATION")
    g.link(nid, _lid(p.get("serverFarmId")), "HOSTED_ON")


def _aca_env(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    _in_subnets(g, nid, [(p.get("vnetConfiguration") or {}).get("infrastructureSubnetId")])


def _container_app(g: InfraGraph, nid: str, r: dict, p: dict) -> None:
    ing = (p.get("configuration") or {}).get("ingress") or {}
    names = [ing.get("fqdn"), p.get("latestRevisionFqdn")] + [d.get("name") for d in ing.get("customDomains") or []]
    g.nodes[nid]["props"]["hostnames"] = sorted({h.lower() for h in names if h})
    g.link(nid, _lid(p.get("managedEnvironmentId") or p.get("environmentId")), "HOSTED_ON")


_HANDLERS = {
    "aca-env": _aca_env, "containerapp": _container_app,
    "aks": _aks, "sql-mi": _subnet_prop("subnetId"), "redis": _subnet_prop("subnetId"),
    "postgres": _flex_net, "mysql": _flex_net, "webapp": _webapp,
    "vnet": _vnet, "nsg": _nsg, "nic": _nic, "pip": _pip, "vm": _vm,
    "routetable": _routetable, "pe": _pe, "lb": _lb, "appgw": _appgw,
    "firewall": _ipconf_resource, "bastion": _ipconf_resource, "vnetgw": _ipconf_resource,
    "natgw": _natgw,
}


# ------------------------------------------------------------ query layer
def summary(g: InfraGraph) -> dict:
    kinds = Counter(n["kind"] for n in g.nodes.values() if n["in_scan"])
    unattached_nsgs = [n["name"] for n in g.nodes.values()
                       if n["kind"] == "nsg" and not g.neighbors(n["id"], "PROTECTED_BY", "in")]
    unattached_pips = [n["name"] for n in g.nodes.values()
                       if n["kind"] == "pip" and not g.neighbors(n["id"], "HAS_PUBLIC_IP", "in")]
    exposure = Counter(n["props"]["access"]["public_endpoint"] for n in g.nodes.values() if n["props"].get("access"))
    return {
        "precision": "Facts come from Resource Graph ('arg') or direct ARM GETs ('arm <api>'). "
                     "Missing data is reported as unknown, never guessed.",
        "enriched": g.meta.get("enriched"),
        "rbac_status": g.meta.get("rbac_status"),
        "enrichment_error_count": len(g.meta.get("enrichment_errors", [])),
        "collection_errors": g.meta.get("errors", []),
        "public_endpoint_states": dict(sorted(exposure.items())),
        "internet_ingress_paths": dict(sorted(Counter(p["path"] for p in ingress_paths(g)["paths"]).items())),
        "internet_ingress_paths_note": "Same set that ingress_paths returns: public entry points only "
                                       "(firewall DNAT, public LB rules, public App Gateway listeners, public IPs on NICs).",
        "collected_at": g.meta.get("collected_at"),
        "subscriptions": [{"id": s["id"], "name": s.get("name")} for s in g.meta.get("subscriptions", [])],
        "not_visible": g.meta.get("not_visible", []),
        "counts": dict(sorted(kinds.items())),
        "edges": dict(sorted(Counter(e["rel"] for e in g.edges).items())),
        "outside_scan": dict(sorted(Counter(n["kind"] for n in g.nodes.values() if not n["in_scan"]).items())),
        "outside_scan_note": "Nodes that are referenced but were not collected in this scan. By kind: resources in "
                             "other subscriptions or deleted, management group / root scopes of role assignments, "
                             "IPs or FQDNs no scanned resource owns ('ip', 'fqdn'), and the Internet node. It is not "
                             "a count of cross-subscription references.",
        "unattached": {"nsgs": unattached_nsgs, "public_ips": unattached_pips},
    }


def brief(n: dict) -> dict:
    return {"id": n["id"], "kind": n["kind"], "name": n["name"],
            "resource_group": n.get("resource_group"), "in_scan": n["in_scan"]}


def node_view(g: InfraGraph, n: dict, depth: int = 1, cap: int = 150) -> dict:
    seen, frontier, rels = {n["id"]}, [n["id"]], []
    for _ in range(max(1, min(depth, 3))):
        nxt = []
        for nid in frontier:
            for e, other in g.neighbors(nid):
                rels.append({k: v for k, v in e.items()})
                if other["id"] not in seen:
                    seen.add(other["id"])
                    nxt.append(other["id"])
        frontier = nxt
    related = [brief(g.nodes[i]) for i in seen if i != n["id"]]
    return {"node": n, "related": related[:cap], "relationships": rels[: cap * 2],
            "truncated": len(related) > cap}


def _nics_for(g: InfraGraph, n: dict) -> list[dict]:
    if n["kind"] in ("nic", "vmss"):
        return [n]
    if n["kind"] in ("vm", "pe"):
        return [x for _, x in g.neighbors(n["id"], "HAS_NIC", "out")]
    if n["kind"] == "pip":
        owner = g.one(n["id"], "HAS_PUBLIC_IP", "in")
        return _nics_for(g, owner) if owner else []
    return []


def _sorted_rules(nsg: dict | None, direction: str) -> list[dict]:
    if not nsg:
        return []
    rules = [r for r in nsg["props"].get("rules", []) if (r["direction"] or "").lower() == direction]
    return sorted(rules, key=lambda r: r["priority"] or 0)


def _layer(g: InfraGraph, holder: dict | None, label: str, direction: str) -> dict:
    nsg = g.one(holder["id"], "PROTECTED_BY", "out", "nsg") if holder else None
    return {
        "layer": label,
        "attached_to": holder["name"] if holder else None,
        "nsg": nsg["name"] if nsg else None,
        "nsg_id": nsg["id"] if nsg else None,
        "note": None if nsg else "No NSG at this layer, so this layer does not filter traffic.",
        "rules": _sorted_rules(nsg, direction),
    }


def nsg_layers(g: InfraGraph, n: dict) -> dict:
    """Declared NSG rules on the path, in Azure evaluation order.

    Inbound: subnet NSG first, then NIC NSG. Outbound: NIC NSG first, then subnet NSG.
    Traffic must be allowed by both layers that exist.
    """
    if n["kind"] == "subnet":
        return {"target": brief(n), "subnet_only": True,
                "inbound": [_layer(g, n, "subnet", "inbound")],
                "outbound": [_layer(g, n, "subnet", "outbound")]}
    nics = _nics_for(g, n)
    if not nics:
        subnets = [x for _, x in g.neighbors(n["id"], "IN_SUBNET", "out") if x["kind"] == "subnet"]
        if subnets:
            return {"target": brief(n), "subnet_only": True,
                    "note": "Resource is placed in these subnets without NICs of its own; the subnet NSG applies.",
                    "subnets": [{"subnet": s["name"], "subnet_id": s["id"],
                                 "inbound": [_layer(g, s, "subnet", "inbound")],
                                 "outbound": [_layer(g, s, "subnet", "outbound")]} for s in subnets]}
        return {"target": brief(n), "error": f"No network interface found for this {n['kind']}. "
                "Load balancers, gateways and firewalls are filtered by their subnet NSG; query the subnet."}
    out = []
    for nic in nics:
        subnet = g.one(nic["id"], "IN_SUBNET", "out", "subnet")
        out.append({
            "nic": nic["name"],
            "private_ips": nic["props"].get("private_ips", []),
            "subnet": subnet["name"] if subnet else None,
            "inbound": [_layer(g, subnet, "subnet", "inbound"), _layer(g, nic, "nic", "inbound")],
            "outbound": [_layer(g, nic, "nic", "outbound"), _layer(g, subnet, "subnet", "outbound")],
        })
    return {"target": brief(n), "interfaces": out,
            "caveat": "Declared configuration. ASG membership and service tags are shown as written, not expanded."}


def _port_hit(ranges: list[str], port: int) -> bool:
    for r in ranges:
        r = r.strip()
        if r == "*":
            return True
        if "-" in r:
            lo, hi = r.split("-", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif r.isdigit() and int(r) == port:
            return True
    return False


def _addr_hit(prefixes: list[str], want: str) -> bool:
    w = want.strip().lower()
    toks = [p.lower() for p in prefixes]
    if w == "internet":
        return any(t in INTERNET_TOKENS for t in toks)
    if w in toks:
        return True
    try:
        net = ipaddress.ip_network(w, strict=False)
    except ValueError:
        return False
    for t in toks:
        if t in ("*", "any"):
            return True
        try:
            if net.overlaps(ipaddress.ip_network(t, strict=False)):
                return True
        except ValueError:
            continue
    return False


def search_rules(g: InfraGraph, port: int | None = None, source: str | None = None,
                 destination: str | None = None, access: str | None = None,
                 direction: str | None = None, protocol: str | None = None,
                 include_default: bool = False, limit: int = 200) -> dict:
    hits = []
    for nsg in (n for n in g.nodes.values() if n["kind"] == "nsg"):
        applies = [brief(x) for _, x in g.neighbors(nsg["id"], "PROTECTED_BY", "in")]
        for r in nsg["props"].get("rules", []):
            if r["default"] and not include_default:
                continue
            if access and (r["access"] or "").lower() != access.lower():
                continue
            if direction and (r["direction"] or "").lower() != direction.lower():
                continue
            if protocol and (r["protocol"] or "").lower() not in (protocol.lower(), "*"):
                continue
            if port is not None and not _port_hit(r["destination_ports"], port):
                continue
            if source and not _addr_hit(r["source"], source):
                continue
            if destination and not _addr_hit(r["destination"], destination):
                continue
            hits.append({"nsg": nsg["name"], "nsg_id": nsg["id"],
                         "resource_group": nsg.get("resource_group"),
                         "attached_to": applies, "rule": r})
    hits.sort(key=lambda h: (h["nsg"], h["rule"]["direction"] or "", h["rule"]["priority"] or 0))
    return {"match_count": len(hits), "matches": hits[:limit], "truncated": len(hits) > limit}


# ------------------------------------------------------- access and RBAC
OPEN = {"all_networks", "all_networks_with_denies"}


def access_view(g: InfraGraph, n: dict) -> dict:
    prof = n["props"].get("access")
    inbound = [{"from": brief(g.nodes[e["src"]]), "rel": e["rel"], **{k: v for k, v in e.items()
               if k not in ("src", "dst", "rel", "uniq")}}
               for e in g.inc.get(n["id"], [])
               if e["rel"] in ("OPEN_TO_ALL_NETWORKS", "VNET_RULE_ALLOWS", "IP_RULE_ALLOWS", "CONNECTS_TO")]
    return {"target": brief(n), "type": n.get("type"),
            "access": prof or {"public_endpoint": "no_network_surface",
                               "because": ["resource type has no publicNetworkAccess or private endpoint fields"]},
            "network_paths_declared": inbound,
            "note": "Resource-side network layer only. A client also needs DNS, routes and its own NSG/firewall to allow it."}


def exposure_list(g: InfraGraph, states: list[str] | None = None, kind: str | None = None,
                  limit: int = 300) -> dict:
    want = {s.lower() for s in states} if states else OPEN
    rows = []
    for n in g.nodes.values():
        prof = n["props"].get("access")
        if not prof or prof["public_endpoint"] not in want:
            continue
        if kind and n["kind"] != kind.lower():
            continue
        rows.append({**brief(n), "type": n.get("type"), "public_endpoint": prof["public_endpoint"],
                     "because": prof["because"], "private_endpoints": len(prof["private_endpoints"])})
    rows.sort(key=lambda x: (x["public_endpoint"], x["kind"], x["name"]))
    return {"states": sorted(want), "count": len(rows), "resources": rows[:limit], "truncated": len(rows) > limit}


def scope_chain(g: InfraGraph, n: dict) -> list[str]:
    chain = _resource_scopes(n["id"]) if n["id"].startswith("/subscriptions/") else [n["id"]]
    sub = n.get("subscription") or (n["id"].split("/")[2] if n["id"].startswith("/subscriptions/") else None)
    rg = n.get("resource_group")
    if not rg and n["id"].count("/") >= 4 and "/resourcegroups/" in n["id"]:
        rg = n["id"].split("/")[4]
    if sub and rg:
        chain.append(f"/subscriptions/{sub}/resourcegroups/{rg.lower()}")
    if sub:
        s = f"/subscriptions/{sub}"
        chain.append(s)
        chain += g.nodes.get(s, {}).get("props", {}).get("management_groups", [])  # parent -> root
    chain.append("/")
    seen, out = set(), []
    for c in chain:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _allowed(actions: list[str], not_actions: list[str], op: str) -> bool:
    """Azure RBAC action matching: '*' wildcards, case-insensitive; notActions subtract."""
    import fnmatch
    o = op.lower()
    return any(fnmatch.fnmatchcase(o, a.lower()) for a in actions) and \
        not any(fnmatch.fnmatchcase(o, n.lower()) for n in not_actions)


def capabilities(g: InfraGraph, role_guid: str, resource_type: str | None) -> dict:
    d = (g.meta.get("role_definitions") or {}).get(role_guid)
    if not d or "actions" not in d:
        return {"known": False, "reason": "role definition permissions not collected"}
    a, na = d.get("actions", []), d.get("not_actions", [])
    out = {"known": True, "assign_roles": _allowed(a, na, "Microsoft.Authorization/roleAssignments/write"),
           "source": "role definition actions / notActions"}
    if resource_type:
        out["write_resource"] = _allowed(a, na, f"{resource_type}/write")
        out["delete_resource"] = _allowed(a, na, f"{resource_type}/delete")
    out["data_actions"] = len(d.get("data_actions", []))
    return out


def _assignment(g: InfraGraph, e: dict, scope: str, target: dict) -> dict:
    who = g.nodes[e["src"]]
    cap = capabilities(g, e.get("role_definition_id") or "", target.get("type"))
    if e.get("condition") and cap.get("known"):
        cap["note"] = "assignment has a condition: effective permissions depend on it"
    return {"principal": brief(who), "principal_id": e.get("principal_id"), "principal_type": e.get("principal_type"),
            "role": e.get("role"), "role_definition_id": e.get("role_definition_id"), "role_type": e.get("role_type"),
            "scope": scope, "inherited": scope != target["id"], "condition": e.get("condition"),
            "assignment_id": e.get("assignment_id"), "capabilities": cap}


def who_has_access(g: InfraGraph, n: dict) -> dict:
    chain = scope_chain(g, n)
    rows = [_assignment(g, e, scope, n) for scope in chain for e in g.inc.get(scope, []) if e["rel"] == "HAS_ROLE"]
    prof = n["props"].get("access") or {}
    data_plane = {k: v for k, v in (prof.get("auth") or {}).items()}
    cov = g.meta.get("rbac_coverage") or {}
    scopes = [{"scope": c, "collected": bool(cov.get("above_subscription")) if (c == "/" or "/managementgroups/" in c)
               else bool(cov.get("subscription_and_below")),
               "assignments": sum(1 for r in rows if r["scope"] == c)} for c in chain]
    by_scope = {x["scope"]: x for x in scopes}
    for x in scopes:
        if not x["collected"]:
            x["assignments"] = None
            x["note"] = "not collected in this scan: unknown, not zero"
    who_assign = sorted({r["principal_id"] for r in rows if r["capabilities"].get("assign_roles")})
    return {"target": brief(n), "scopes_checked": chain, "scope_coverage": scopes,
            "rbac_status": g.meta.get("rbac_status"),
            "principals_that_can_assign_roles": {"count": len(who_assign), "principal_ids": who_assign,
                                                 "because": "role definition allows Microsoft.Authorization/roleAssignments/write"},
            "role_assignments": rows, "data_plane_auth": data_plane,
            "not_included": ["deny assignments", "PIM eligible (not activated) assignments",
                             "Entra ID group membership expansion", "names of users/groups/service principals"]}


def identity_permissions(g: InfraGraph, n: dict) -> dict:
    holders = [n] + [x for _, x in g.neighbors(n["id"], "USES_IDENTITY", "out")]
    rows = []
    for h in holders:
        for e in g.out.get(h["id"], []):
            if e["rel"] == "HAS_ROLE":
                rows.append({"via": "system-assigned" if h is n else f"user-assigned {h['name']}",
                             "role": e.get("role"), "role_definition_id": e.get("role_definition_id"),
                             "scope": e["dst"], "scope_node": brief(g.nodes[e["dst"]]),
                             "condition": e.get("condition")})
    return {"target": brief(n), "identity": n["props"].get("identity"), "rbac_status": g.meta.get("rbac_status"),
            "roles_held": rows,
            "note": "Roles at a scope apply to everything below it (subscription -> resource group -> resource)."}


# ---------------------------------------------------------- v0.3 queries
def firewall_view(g: InfraGraph, n: dict) -> dict:
    if n["kind"] == "fwpolicy":
        users = [x["name"] for _, x in g.neighbors(n["id"], "USES_POLICY", "in")]
        pseudo = {"name": n["name"], "props": {"policy": n["id"], "classic_rules": []}}
        return E.effective_firewall_rules(g, pseudo) | {"used_by_firewalls": users}
    if n["kind"] != "firewall":
        raise ValueError(f"{n['name']} is a {n['kind']}, not a firewall or firewall policy")
    return E.effective_firewall_rules(g, n)


def search_firewall_rules(g: InfraGraph, port: int | None = None, source: str | None = None,
                          destination: str | None = None, fqdn: str | None = None,
                          action: str | None = None, rule_type: str | None = None, limit: int = 200) -> dict:
    import fnmatch
    hits = []
    for fw in (x for x in g.nodes.values() if x["kind"] == "firewall" and x["in_scan"]):
        for r in E.effective_firewall_rules(g, fw)["rules"]:
            if rule_type and r["type"] != rule_type.lower():
                continue
            if action and (r["action"] or "").lower() != action.lower():
                continue
            if port is not None:
                ports = r["ports"] or [p.split(":")[-1] for p in r["protocols"] if ":" in p]
                if not _port_hit(ports, port):
                    continue
            if source and not _addr_hit(r["sources_expanded"], source):
                continue
            if destination and not _addr_hit(r["destinations_expanded"], destination):
                continue
            if fqdn:
                pats = r["target_fqdns"] + r["destination_fqdns"]
                if not any(fnmatch.fnmatch(fqdn.lower(), p.lower()) or p.lower() == fqdn.lower() for p in pats):
                    continue
            hits.append({"firewall": fw["name"], **r})
    return {"match_count": len(hits), "matches": hits[:limit], "truncated": len(hits) > limit}


def _port_match(value: Any, port: int) -> bool:
    if value is None:
        return False
    vals = value if isinstance(value, list) else [str(value)]
    return _port_hit([str(v) for v in vals], port) or any(str(v) == "0" for v in vals)


def ingress_paths(g: InfraGraph, target: dict | None = None, port: int | None = None,
                  include_private: bool = False) -> dict:
    rows = []
    for e in g.edges:
        rel = e["rel"]
        if rel == "DNAT_FORWARDS":
            ports = e.get("ports")
        elif rel == "LB_FORWARDS":
            if not e.get("public") and not include_private:
                continue
            ports = e.get("frontend_port")
        elif rel == "APPGW_ROUTES":
            if not e.get("public") and not include_private:
                continue
            ports = e.get("listener_port")
        elif rel == "HAS_PUBLIC_IP" and g.nodes[e["src"]]["kind"] == "nic":
            ports = None
        else:
            continue
        # Devices are matched by resource id: names repeat (every AKS load balancer is "kubernetes").
        if target and target["id"] not in (e["src"], e["dst"], e.get("lb_id"), e.get("firewall_id"),
                                           e.get("app_gateway_id")):
            continue
        if port is not None and rel != "HAS_PUBLIC_IP" and not _port_match(ports, port):
            continue
        if rel == "HAS_PUBLIC_IP":
            src, dst = g.nodes[e["dst"]], g.nodes[e["src"]]
            rows.append({"path": "public_ip_on_nic", "entry": brief(src),
                         "entry_ip": src["props"].get("ip_address"), "target": brief(dst),
                         "detail": {"note": "All ports reach the NIC at this layer; the NIC and subnet NSGs filter."}})
            continue
        detail = {k: v for k, v in e.items() if k not in ("src", "dst", "rel", "uniq")}
        if rel == "LB_FORWARDS":
            lbn = g.nodes.get(e.get("lb_id") or "")
            detail["owning_aks"] = lbn["props"].get("owning_aks") if lbn else None
        rows.append({"path": {"DNAT_FORWARDS": "firewall_dnat", "LB_FORWARDS": "load_balancer",
                              "APPGW_ROUTES": "app_gateway"}[rel],
                     "entry": brief(g.nodes[e["src"]]), "target": brief(g.nodes[e["dst"]]), "detail": detail})
    for lb in (x for x in g.nodes.values() if x["kind"] == "lb" and x["in_scan"]):
        for r in lb["props"].get("rules", []):
            if r.get("backend_instances") or not (r.get("public") or include_private):
                continue
            if target and target["id"] not in (lb["id"], r.get("entry")):
                continue
            if port is not None and not _port_match(r.get("frontend_port"), port):
                continue
            rows.append({"path": "load_balancer", "entry": brief(g.nodes[r["entry"]]), "target": None,
                         "detail": {"load_balancer": lb["name"], "lb_id": lb["id"], "rule": r["name"], "rule_kind": r["kind"],
                                    "frontend_ip": r.get("frontend_ip"), "public": r.get("public"),
                                    "protocol": r["protocol"], "frontend_port": r["frontend_port"],
                                    "backend_port": r["backend_port"], "backend_instances": 0,
                                    "owning_aks": lb["props"].get("owning_aks"),
                                    "note": "Frontend and rule are declared but the backend pool has no members, so "
                                            "nothing receives this traffic now. It forwards again as soon as members "
                                            "are added."}})
    return {"count": len(rows), "paths": rows,
            "note": "Declared ingress configuration. Backend NSGs, host firewalls and app auth are separate layers."}


def _subnets_of(g: InfraGraph, n: dict) -> list[dict]:
    if n["kind"] == "subnet":
        return [n]
    nics = _nics_for(g, n)
    holders = nics or [n]
    out = []
    for h in holders:
        out += [x for _, x in g.neighbors(h["id"], "IN_SUBNET", "out") if x["kind"] == "subnet"]
    return list({x["id"]: x for x in out}.values())


def route_view(g: InfraGraph, n: dict) -> dict:
    res = []
    for s in _subnets_of(g, n):
        rt = g.one(s["id"], "ROUTES_VIA", "out", "routetable")
        entry = {"subnet": s["name"], "subnet_id": s["id"], "route_table": rt["name"] if rt else None}
        if rt:
            hops = {e.get("uniq"): e for e in g.out.get(rt["id"], []) if e["rel"] == "NEXT_HOP"}
            entry["bgp_route_propagation_disabled"] = rt["props"].get("disable_bgp_route_propagation")
            entry["routes"] = []
            for r in rt["props"].get("routes", []):
                hop = hops.get(r["name"])
                entry["routes"].append({**r, "next_hop_resource": brief(g.nodes[hop["dst"]]) if hop else None,
                                        "drops_traffic": (r.get("next_hop_type") or "").lower() == "none"})
        else:
            entry["note"] = "No route table: only Azure system routes (and BGP routes) apply."
        egress = g.one(s["id"], "EGRESS_VIA", "out", "natgw")
        entry["nat_gateway"] = egress["name"] if egress else None
        res.append(entry)
    return {"target": brief(n), "subnets": res,
            "not_included": "System routes, BGP-learned routes and the Azure-computed effective route table "
                            "(needs Network Watcher / effectiveRouteTable, which Reader cannot call)."}


def hybrid_view(g: InfraGraph) -> dict:
    gws = []
    for gw in (x for x in g.nodes.values() if x["kind"] == "vnetgw" and x["in_scan"]):
        subnet = g.one(gw["id"], "IN_SUBNET", "out", "subnet")
        vnet = g.one(subnet["id"], "CONTAINS", "in", "vnet") if subnet else None
        conns = []
        for e in g.out.get(gw["id"], []):
            if e["rel"] == "HYBRID_CONNECTION":
                rem = g.nodes[e["dst"]]
                conns.append({"connection": e.get("connection"), "type": e.get("connection_type"),
                              "status": e.get("status"), "bgp": e.get("enable_bgp"), "remote": brief(rem),
                              "remote_ranges": rem["props"].get("address_prefixes"),
                              "remote_gateway_ip": rem["props"].get("gateway_ip"),
                              "er_peerings": rem["props"].get("peerings")})
        spokes = []
        if vnet:
            for e, other in g.neighbors(vnet["id"], "PEERED_WITH", "in"):
                if e.get("use_remote_gateways"):
                    spokes.append(other["name"])
        gws.append({"gateway": brief(gw), "vnet": vnet["name"] if vnet else None,
                    **{k: gw["props"].get(k) for k in ("gateway_type", "vpn_type", "sku", "active_active",
                                                       "enable_bgp", "bgp_asn", "point_to_site")},
                    "connections": conns, "spokes_using_this_gateway": spokes})
    circuits = [brief(x) | {k: x["props"].get(k) for k in ("provider", "peering_location", "bandwidth_mbps",
                                                          "provider_state", "circuit_state", "peerings")}
                for x in g.nodes.values() if x["kind"] == "ercircuit" and x["in_scan"]]
    return {"gateways": gws, "expressroute_circuits": circuits,
            "note": "Connection status is as recorded in resource properties at scan time."}
