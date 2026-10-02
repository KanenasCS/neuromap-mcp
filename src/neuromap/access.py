"""Deterministic access evaluation per resource type.

Contract (this is what "precise, not probable" means here):
  * Every verdict lists the exact fields and values it was derived from (`because`).
    `because` holds verdict evidence only. Documented defaults applied to other facts
    (auth, TLS) go in `notes`, so because[0] is always the network reason.
  * Every fact records where it came from (`sources`: "arg" or "arm <api-version>").
  * If a needed field is missing or could not be read, the verdict is "unknown"
    and the reason is recorded. Nothing is inferred from names, tags or strings.
  * Where Azure documents what an unset field means, the rule is applied and
    written into `because`, so the reader can check it.

public_endpoint values:
  disabled                 public endpoint off (private endpoint / VNet only)
  vnet_injected            resource lives in a delegated subnet, has no public endpoint
  all_networks             any source IP on the internet is allowed at this layer
  all_networks_with_denies any IP allowed except explicit deny rules
  restricted               public endpoint on, limited to listed IPs / subnets / services
  enabled_no_allow_rules   public endpoint on, but no rule allows anyone
  gated_by_nsg             public endpoint on, filtering is done by the subnet NSG
  perimeter_controlled     governed by a Network Security Perimeter (not evaluated)
  unknown                  required data missing; see `unknown`
  no_inbound_endpoint      the resource declares no inbound endpoint (no ingress / no HTTP trigger)
  decided_per_app          public entry exists; each child app's ingress decides (Container Apps env)
  not_evaluated            no evaluator for this type yet (raw facts still shown)

This is the resource's own network layer. It does not say a given client can
connect end to end (DNS, routes, NSGs and firewalls on the client side matter too).
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable

ANY_TOKENS = {"any", "*", "0.0.0.0/0", "::/0"}
# Logic Apps trigger types that receive inbound HTTP calls (Request, and webhook callbacks).
INBOUND_TRIGGERS = {"request", "apiconnectionwebhook", "httpwebhook"}
MAX_V4 = 0xFFFFFFFF


# ---------------------------------------------------------------- helpers
def _eq(a: Any, b: str) -> bool:
    return isinstance(a, str) and a.lower() == b.lower()


def _ids(items: Any, key: str = "id") -> list[str]:
    out = []
    for i in items or []:
        v = i.get(key) if isinstance(i, dict) else None
        if isinstance(v, dict):
            v = v.get("id")
        if v:
            out.append(v.lower())
    return out


def ip_range(spec: str) -> tuple[int, int] | None:
    """'1.2.3.4', '1.2.3.0/24' -> (start, end) as ints. IPv4 only; others -> None."""
    try:
        net = ipaddress.ip_network(spec.strip(), strict=False)
    except (ValueError, AttributeError):
        return None
    if net.version != 4:
        return None
    return int(net.network_address), int(net.broadcast_address)


def _pair(start: str, end: str) -> tuple[int, int] | None:
    try:
        a, b = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    except (ValueError, TypeError):
        return None
    return (a, b) if a <= b else (b, a)


def covers_all_ipv4(ranges: list[tuple[int, int]]) -> bool:
    cur = 0
    for a, b in sorted(ranges):
        if a > cur:
            return False
        cur = max(cur, b + 1)
        if cur > MAX_V4:
            return True
    return cur > MAX_V4


class Profile:
    def __init__(self, r: dict, evaluator: str | None):
        self.d: dict[str, Any] = {
            "evaluator": evaluator, "public_endpoint": "not_evaluated" if evaluator is None else "unknown",
            "because": [], "notes": [], "network": {}, "auth": {}, "transport": {},
            "allow_ip_ranges": [], "allow_subnets": [], "private_endpoints": [],
            "sources": {}, "unknown": [],
        }
        p = r.get("properties") or {}
        self.d["network"]["public_network_access"] = p.get("publicNetworkAccess")
        for c in p.get("privateEndpointConnections") or []:
            cp = c.get("properties") or {}
            pe = (cp.get("privateEndpoint") or {}).get("id")
            if pe:
                self.d["private_endpoints"].append({
                    "private_endpoint": pe.lower(),
                    "status": (cp.get("privateLinkServiceConnectionState") or {}).get("status")})

    def fact(self, section: str, key: str, value: Any, source: str = "arg") -> None:
        self.d[section][key] = value
        self.d["sources"][f"{section}.{key}"] = source

    def verdict(self, value: str, *because: str) -> dict:
        self.d["public_endpoint"] = value
        self.d["because"].extend(because)
        return self.d

    def unknown(self, field: str, reason: str) -> dict:
        self.d["unknown"].append({"field": field, "reason": reason})
        return self.verdict("unknown", f"{field}: {reason}")


def _arm(arm: dict, key: str) -> tuple[Any, str | None, str | None]:
    """-> (data, source label, error). data None with error None means enrichment was not run."""
    item = arm.get(key)
    if item is None:
        return None, None, "not collected (scan ran without ARM enrichment)"
    if "error" in item:
        return None, None, f"ARM read failed (HTTP {item.get('status')})"
    return item["data"], f"arm {item['api']}", None


def _firewall_verdict(pf: Profile, rules: list[tuple[str, str, str]], src: str,
                      empty_means: str, empty_rule: str) -> dict:
    """rules: [(name, start, end)]. Shared by SQL, PostgreSQL, MySQL, Redis."""
    pf.fact("network", "firewall_rules", [{"name": n, "start": s, "end": e} for n, s, e in rules], src)
    ranges = [x for x in (_pair(s, e) for _, s, e in rules) if x]
    azure_rule = any(s == "0.0.0.0" and e == "0.0.0.0" for _, s, e in rules)
    pf.fact("network", "allow_all_azure_services", azure_rule, src)
    real = [rg for rg in ranges if rg != (0, 0)]
    pf.d["allow_ip_ranges"] += [f"{ipaddress.IPv4Address(a)}-{ipaddress.IPv4Address(b)}" for a, b in real]
    if covers_all_ipv4(real):
        return pf.verdict("all_networks", "firewall rules together cover 0.0.0.0-255.255.255.255")
    if not rules and not pf.d["allow_subnets"]:
        return pf.verdict(empty_means, empty_rule)
    parts = [f"{len(real)} IP range rule(s)"]
    if azure_rule:
        parts.append("0.0.0.0-0.0.0.0 rule = all Azure services, including other customers' tenants")
    if pf.d["allow_subnets"]:
        parts.append(f"{len(pf.d['allow_subnets'])} VNet rule(s)")
    return pf.verdict("restricted", "public endpoint enabled; allowed: " + ", ".join(parts))


def _acl_facts(pf: Profile, acls: dict | None, ip_key: str, ip_field: str, vnet_key: str = "virtualNetworkRules"):
    if not acls:
        return None, [], []
    default = acls.get("defaultAction")
    ips = [x.get(ip_field) for x in acls.get(ip_key) or [] if x.get(ip_field)]
    subnets = _ids(acls.get(vnet_key))
    pf.fact("network", "default_action", default)
    pf.fact("network", "bypass", acls.get("bypass"))
    pf.fact("network", "ip_rules", ips)
    pf.fact("network", "vnet_rules", subnets)
    return default, ips, subnets


def _acl_verdict(pf: Profile, acls: dict, ip_key: str, ip_field: str, vnet_key: str = "virtualNetworkRules") -> dict:
    """Storage / Key Vault / Cognitive Services style networkAcls."""
    default, ips, subnets = _acl_facts(pf, acls, ip_key, ip_field, vnet_key)
    pf.d["allow_ip_ranges"] += ips
    pf.d["allow_subnets"] += subnets
    if _eq(default, "Allow"):
        return pf.verdict("all_networks", "networkAcls.defaultAction = Allow")
    if not _eq(default, "Deny"):
        return pf.unknown("networkAcls.defaultAction", f"unexpected value {default!r}")
    ranges = [x for x in (ip_range(i) for i in ips) if x]
    if covers_all_ipv4(ranges):
        return pf.verdict("all_networks", "defaultAction = Deny but IP rules cover all IPv4")
    if not ips and not subnets:
        extra = f"; bypass = {acls.get('bypass')}" if acls.get("bypass") else ""
        return pf.verdict("enabled_no_allow_rules", "defaultAction = Deny with no IP or VNet rules" + extra)
    return pf.verdict("restricted", f"defaultAction = Deny; {len(ips)} IP rule(s), {len(subnets)} VNet rule(s)")


# ------------------------------------------------------------- evaluators
def _storage(r, p, arm, pf: Profile):
    pf.fact("auth", "allow_shared_key_access", p.get("allowSharedKeyAccess"))
    if p.get("allowSharedKeyAccess") is None:
        pf.d["notes"].append("auth.allow_shared_key_access: unset = true (Storage API default)")
    pf.fact("auth", "allow_blob_public_access", p.get("allowBlobPublicAccess"))
    pf.fact("auth", "default_to_oauth", p.get("defaultToOAuthAuthentication"))
    pf.fact("transport", "https_only", p.get("supportsHttpsTrafficOnly"))
    pf.fact("transport", "min_tls", p.get("minimumTlsVersion"))
    acls = p.get("networkAcls")
    if acls:
        pf.fact("network", "resource_access_rules",
                [{"resource_id": x.get("resourceId"), "tenant_id": x.get("tenantId")} for x in acls.get("resourceAccessRules") or []])
    pna = p.get("publicNetworkAccess")
    _acl_facts(pf, acls, "ipRules", "value")
    if _eq(pna, "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if _eq(pna, "SecuredByPerimeter"):
        return pf.verdict("perimeter_controlled", "publicNetworkAccess = SecuredByPerimeter")
    if acls is None:
        return pf.unknown("networkAcls", "not present in resource properties")
    return _acl_verdict(pf, acls, "ipRules", "value")


def _keyvault(r, p, arm, pf: Profile):
    rbac = p.get("enableRbacAuthorization")
    pf.fact("auth", "rbac_authorization", rbac)
    pols = [{"object_id": a.get("objectId"), "tenant_id": a.get("tenantId"),
             "permissions": a.get("permissions")} for a in p.get("accessPolicies") or []]
    pf.fact("auth", "access_policies", pols)
    if not rbac:
        pf.d["notes"].append("auth.rbac_authorization false/unset: access policies grant data-plane access")
    pna = p.get("publicNetworkAccess")
    acls = p.get("networkAcls")
    _acl_facts(pf, acls, "ipRules", "value")
    if _eq(pna, "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if acls is None:
        return pf.verdict("all_networks", "networkAcls not set (Key Vault default: all networks allowed)")
    return _acl_verdict(pf, acls, "ipRules", "value")


def _cognitive(r, p, arm, pf: Profile):
    pf.fact("auth", "local_auth_disabled", p.get("disableLocalAuth"))
    pf.fact("network", "restrict_outbound", p.get("restrictOutboundNetworkAccess"))
    pna = p.get("publicNetworkAccess")
    acls = p.get("networkAcls")
    _acl_facts(pf, acls, "ipRules", "value")
    if _eq(pna, "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if acls is None:
        return pf.verdict("all_networks", "networkAcls not set (Azure AI services default: all networks)")
    return _acl_verdict(pf, acls, "ipRules", "value")


def _sql_entra(pf: Profile, sp: dict, src: str, arm: dict) -> None:
    """Entra admin and Entra-only auth. Authoritative sources are the servers/administrators and
    servers/azureADOnlyAuthentications child resources; the server object is the fallback."""
    admins, asrc, aerr = _arm(arm, "entra_admins")
    only, osrc, oerr = _arm(arm, "entra_only")
    adm = sp.get("administrators") or {}
    if admins is not None:
        a = (admins[0].get("properties") or {}) if admins else None
        pf.fact("auth", "entra_admin", {"login": a.get("login"), "type": a.get("administratorType"),
                                        "sid": a.get("sid")} if a else None, asrc)
        if not admins:
            pf.d["notes"].append(f"auth.entra_admin: servers/administrators returned an empty list, so no Entra admin is set [{asrc}]")
    elif adm:
        pf.fact("auth", "entra_admin", {"login": adm.get("login"), "type": adm.get("principalType"),
                                        "sid": adm.get("sid")}, src)
    else:
        pf.fact("auth", "entra_admin", None, src)
        pf.d["notes"].append("auth.entra_admin: the server object has no administrators block, and servers/administrators "
                             f"was not read ({aerr}), so whether an Entra admin exists is not confirmed")
    if only is not None:
        val = ((only[0].get("properties") or {}).get("azureADOnlyAuthentication")) if only else False
        pf.fact("auth", "entra_only", val, osrc)
        if not only:
            pf.d["notes"].append(f"auth.entra_only: servers/azureADOnlyAuthentications returned an empty list, so "
                                 f"Entra-only authentication is not enabled [{osrc}]")
        if val is False:
            pf.d["notes"].append(f"auth.entra_only = false: SQL authentication (logins/passwords) is accepted [{osrc}]")
    else:
        pf.fact("auth", "entra_only", adm.get("azureADOnlyAuthentication"), src)


def _sql_server(r, p, arm, pf: Profile):
    server, ssrc, _ = _arm(arm, "server")
    sp, src = ((server or {}).get("properties") or p), (ssrc or "arg")
    _sql_entra(pf, sp, src, arm)
    pf.fact("transport", "min_tls", sp.get("minimalTlsVersion"), src)
    pf.fact("network", "public_network_access", sp.get("publicNetworkAccess"), src)
    pf.fact("network", "restrict_outbound", sp.get("restrictOutboundNetworkAccess"), src)
    pna = sp.get("publicNetworkAccess")
    vnet, vsrc, verr = _arm(arm, "vnet_rules")
    fw, fsrc, ferr = _arm(arm, "firewall_rules")
    vrules = None if vnet is None else [
        {"name": v.get("name"), "subnet": (v.get("properties", {}).get("virtualNetworkSubnetId") or "").lower(),
         "state": v.get("properties", {}).get("state")} for v in vnet]
    frules = None if fw is None else [
        (f.get("name"), f["properties"].get("startIpAddress"), f["properties"].get("endIpAddress")) for f in fw]
    if vrules is not None:
        pf.fact("network", "vnet_rules", vrules, vsrc)
    elif verr:
        pf.d["unknown"].append({"field": "virtualNetworkRules", "reason": verr})
    if _eq(pna, "Disabled") or _eq(pna, "SecuredByPerimeter"):
        # Rules are still facts worth showing, but they do not apply.
        if frules is not None:
            pf.fact("network", "firewall_rules", [{"name": n, "start": a, "end": b} for n, a, b in frules], fsrc)
        pf.fact("network", "rules_in_effect", False, src)
        if _eq(pna, "Disabled"):
            return pf.verdict("disabled", f"publicNetworkAccess = Disabled ({src}); firewall and VNet rules are not applied")
        return pf.verdict("perimeter_controlled", "publicNetworkAccess = SecuredByPerimeter")
    if pna is None:
        return pf.unknown("publicNetworkAccess", "not returned by ARG or ARM")
    if frules is None:
        return pf.unknown("firewallRules", ferr)
    pf.d["allow_subnets"] += [x["subnet"] for x in vrules or [] if x["subnet"]]
    pf.fact("network", "rules_in_effect", True, src)
    return _firewall_verdict(pf, frules, fsrc, "enabled_no_allow_rules",
                             "publicNetworkAccess enabled, no firewall or VNet rules (SQL denies by default)")


def _sql_mi(r, p, arm, pf: Profile):
    adm = p.get("administrators") or {}
    pf.fact("auth", "entra_only", adm.get("azureADOnlyAuthentication"))
    pf.fact("transport", "min_tls", p.get("minimalTlsVersion"))
    pf.fact("network", "proxy_override", p.get("proxyOverride"))
    pf.fact("network", "subnet", (p.get("subnetId") or "").lower() or None)
    pde = p.get("publicDataEndpointEnabled")
    pf.fact("network", "public_data_endpoint", pde)
    if pde is False:
        return pf.verdict("disabled", "publicDataEndpointEnabled = false (VNet-local endpoint only)")
    if pde is True:
        return pf.verdict("gated_by_nsg", "publicDataEndpointEnabled = true; traffic on port 3342 is filtered by the "
                          "subnet NSG only (use nsg_rules_for on the MI subnet)")
    return pf.unknown("publicDataEndpointEnabled", "not present")


def _flex(label: str, fw_empty_rule: str):
    def ev(r, p, arm, pf: Profile):
        net = p.get("network") or {}
        auth = p.get("authConfig") or {}
        if auth:
            pf.fact("auth", "entra_auth", auth.get("activeDirectoryAuth"))
            pf.fact("auth", "password_auth", auth.get("passwordAuth"))
        delegated = (net.get("delegatedSubnetResourceId") or "").lower() or None
        pf.fact("network", "delegated_subnet", delegated)
        pf.fact("network", "public_network_access", net.get("publicNetworkAccess"))
        if delegated:
            return pf.verdict("vnet_injected", f"network.delegatedSubnetResourceId set ({label} private access mode)")
        if _eq(net.get("publicNetworkAccess"), "Disabled"):
            return pf.verdict("disabled", "network.publicNetworkAccess = Disabled")
        fw, src, err = _arm(arm, "firewall_rules")
        if fw is None:
            return pf.unknown("firewallRules", err)
        rules = [(f.get("name"), f["properties"].get("startIpAddress"), f["properties"].get("endIpAddress")) for f in fw]
        return _firewall_verdict(pf, rules, src, "enabled_no_allow_rules", fw_empty_rule)
    return ev


def _redis(r, p, arm, pf: Profile):
    pf.fact("auth", "access_key_auth_disabled", p.get("disableAccessKeyAuthentication"))
    pf.fact("transport", "non_ssl_port", p.get("enableNonSslPort"))
    pf.fact("transport", "min_tls", p.get("minimumTlsVersion"))
    subnet = (p.get("subnetId") or "").lower() or None
    pf.fact("network", "subnet", subnet)
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if subnet:
        return pf.verdict("vnet_injected", "subnetId set (VNet-injected cache)")
    fw, src, err = _arm(arm, "firewall_rules")
    if fw is None:
        return pf.unknown("firewallRules", err)
    rules = [(f.get("name"), f["properties"].get("startIP"), f["properties"].get("endIP")) for f in fw]
    if not rules:
        pf.fact("network", "firewall_rules", [], src)
        return pf.verdict("all_networks", "no firewall rules (Redis default: all client IPs allowed)")
    return _firewall_verdict(pf, rules, src, "all_networks", "")


def _cosmos(r, p, arm, pf: Profile):
    pf.fact("auth", "local_auth_disabled", p.get("disableLocalAuth"))
    pf.fact("transport", "min_tls", p.get("minimalTlsVersion"))
    ips = [x.get("ipAddressOrRange") for x in p.get("ipRules") or [] if x.get("ipAddressOrRange")]
    vfilter = p.get("isVirtualNetworkFilterEnabled")
    subnets = _ids(p.get("virtualNetworkRules"))
    pf.fact("network", "ip_rules", ips)
    pf.fact("network", "vnet_filter_enabled", vfilter)
    pf.fact("network", "vnet_rules", subnets)
    pf.fact("network", "acl_bypass", p.get("networkAclBypass"))
    pf.fact("network", "allow_azure_datacenters", "0.0.0.0" in ips)
    pf.d["allow_ip_ranges"] += [i for i in ips if i != "0.0.0.0"]
    pf.d["allow_subnets"] += subnets
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if vfilter is None:
        return pf.unknown("isVirtualNetworkFilterEnabled", "not present")
    if not ips and not vfilter:
        return pf.verdict("all_networks", "no ipRules and isVirtualNetworkFilterEnabled = false")
    return pf.verdict("restricted", f"{len(ips)} IP rule(s), VNet filter {vfilter}, {len(subnets)} VNet rule(s)")


def _web_rules(rules: list[dict], explicit_default: str | None) -> tuple[str, str]:
    """First-match evaluation of App Service access restrictions for an arbitrary internet IP."""
    ordered = sorted(rules, key=lambda x: x.get("priority") or 0)
    real = [x for x in ordered if not (_eq(x.get("name"), "Allow all") and _eq(x.get("ipAddress"), "Any"))]
    denies_before = 0
    for x in ordered:
        is_any = (x.get("ipAddress") or "").lower() in ANY_TOKENS and not x.get("headers") \
            and (x.get("tag") in (None, "Default", "IpAddress")) and not x.get("vnetSubnetResourceId")
        if is_any:
            if _eq(x.get("action"), "Allow"):
                if denies_before:
                    return "all_networks_with_denies", f"rule '{x.get('name')}' allows Any after {denies_before} deny rule(s)"
                return "all_networks", f"rule '{x.get('name')}' (priority {x.get('priority')}) allows Any"
            return ("restricted" if any(_eq(y.get("action"), "Allow") for y in real) else "enabled_no_allow_rules",
                    f"rule '{x.get('name')}' denies Any; earlier allow rules apply")
        if _eq(x.get("action"), "Deny"):
            denies_before += 1
    default = explicit_default or ("Deny" if real else "Allow")
    how = "ipSecurityRestrictionsDefaultAction" if explicit_default else "implicit (rules present -> deny others)"
    if _eq(default, "Allow"):
        return ("all_networks_with_denies" if denies_before else "all_networks"), f"default action Allow ({how})"
    if any(_eq(x.get("action"), "Allow") for x in real):
        return "restricted", f"{sum(1 for x in real if _eq(x.get('action'), 'Allow'))} allow rule(s), default Deny ({how})"
    return "enabled_no_allow_rules", f"no allow rules, default Deny ({how})"


def _norm_web_rule(x: dict) -> dict:
    return {k: x.get(k) for k in ("name", "priority", "action", "ipAddress", "tag", "vnetSubnetResourceId", "headers")}


def _webapp(r, p, arm, pf: Profile):
    pf.fact("network", "kind", r.get("kind"))
    pf.fact("transport", "https_only", p.get("httpsOnly"))
    pf.fact("auth", "client_cert_enabled", p.get("clientCertEnabled"))
    pf.fact("network", "outbound_vnet_integration", (p.get("virtualNetworkSubnetId") or "").lower() or None)
    for key, label in (("ftp_basic_auth", "ftp_basic_auth_allowed"), ("scm_basic_auth", "scm_basic_auth_allowed")):
        data, src, err = _arm(arm, key)
        if data is not None:
            pf.fact("auth", label, (data.get("properties") or {}).get("allow"), src)
        else:
            pf.d["unknown"].append({"field": key, "reason": err})
    cfg, src, err = _arm(arm, "site_config")
    c = (cfg or {}).get("properties") or {}
    main = c.get("ipSecurityRestrictions") or []
    if cfg is not None:
        pf.fact("transport", "min_tls", c.get("minTlsVersion"), src)
        pf.fact("transport", "ftps_state", c.get("ftpsState"), src)
        pf.fact("network", "route_all_outbound_via_vnet", c.get("vnetRouteAllEnabled"), src)
        pf.fact("network", "access_restrictions", [_norm_web_rule(x) for x in main], src)
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if p.get("publicNetworkAccess") is None and pf.d["private_endpoints"]:
        return pf.unknown("publicNetworkAccess", "unset while private endpoints exist; the platform default "
                          "differs by app age, so it is not assumed")
    if cfg is None:
        return pf.unknown("config/web ipSecurityRestrictions", err)
    for x in main:
        if _eq(x.get("action"), "Allow"):
            if x.get("vnetSubnetResourceId"):
                pf.d["allow_subnets"].append(x["vnetSubnetResourceId"].lower())
            elif (x.get("ipAddress") or "").lower() not in ANY_TOKENS and x.get("tag") in (None, "Default", "IpAddress"):
                pf.d["allow_ip_ranges"].append(x.get("ipAddress"))
    v, why = _web_rules(main, c.get("ipSecurityRestrictionsDefaultAction"))
    if c.get("scmIpSecurityRestrictionsUseMain"):
        pf.fact("network", "scm_endpoint", {"public_endpoint": v, "because": "scmIpSecurityRestrictionsUseMain = true"}, src)
    else:
        scm = c.get("scmIpSecurityRestrictions") or []
        sv, swhy = _web_rules(scm, c.get("scmIpSecurityRestrictionsDefaultAction"))
        pf.fact("network", "scm_endpoint", {"public_endpoint": sv, "because": swhy,
                                             "rules": [_norm_web_rule(x) for x in scm]}, src)
    return pf.verdict(v, f"{why} [{src}]")


def _acr(r, p, arm, pf: Profile):
    sku = (r.get("sku") or {}).get("name")
    pf.fact("auth", "admin_user_enabled", p.get("adminUserEnabled"))
    pf.fact("auth", "anonymous_pull", p.get("anonymousPullEnabled"))
    pf.fact("network", "sku", sku)
    rs = p.get("networkRuleSet")
    _acl_facts(pf, rs, "ipRules", "value")
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if rs is None:
        if sku and not _eq(sku, "Premium"):
            return pf.verdict("all_networks", f"sku = {sku}; network rules exist only on Premium")
        return pf.unknown("networkRuleSet", "not present on a Premium registry")
    pf.fact("network", "bypass", p.get("networkRuleBypassOptions"))
    return _acl_verdict(pf, rs, "ipRules", "value")


def _aks(r, p, arm, pf: Profile):
    api = p.get("apiServerAccessProfile") or {}
    aad = p.get("aadProfile") or {}
    net = p.get("networkProfile") or {}
    pf.fact("auth", "entra_integration", bool(aad))
    pf.fact("auth", "azure_rbac", aad.get("enableAzureRBAC"))
    pf.fact("auth", "local_accounts_disabled", p.get("disableLocalAccounts"))
    pf.fact("network", "power_state", (p.get("powerState") or {}).get("code"))
    pf.fact("network", "plugin", net.get("networkPlugin"))
    pf.fact("network", "policy", net.get("networkPolicy"))
    pf.fact("network", "outbound_type", net.get("outboundType"))
    pf.fact("network", "node_subnets", sorted({(a.get("vnetSubnetID") or "").lower()
                                                for a in p.get("agentPoolProfiles") or [] if a.get("vnetSubnetID")}))
    ranges = api.get("authorizedIPRanges") or []
    pf.fact("network", "api_authorized_ip_ranges", ranges)
    pf.fact("network", "private_cluster", api.get("enablePrivateCluster"))
    pf.d["allow_ip_ranges"] += ranges
    priv = api.get("enablePrivateCluster")
    if priv:
        return pf.verdict("disabled", "apiServerAccessProfile.enablePrivateCluster = true (API server private)")
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    priv_txt = ("enablePrivateCluster = false" if priv is False
                else "enablePrivateCluster unset (AKS default: public API server)")
    if ranges:
        if covers_all_ipv4([x for x in (ip_range(i) for i in ranges) if x]):
            return pf.verdict("all_networks", f"{priv_txt}; authorizedIPRanges cover all IPv4")
        return pf.verdict("restricted", f"{priv_txt}; API server limited to {len(ranges)} authorizedIPRanges")
    rtxt = "authorizedIPRanges = []" if api.get("authorizedIPRanges") == [] else "authorizedIPRanges unset"
    return pf.verdict("all_networks", f"{priv_txt}; {rtxt}")


def _messaging(r, p, arm, pf: Profile):
    pf.fact("auth", "local_auth_disabled", p.get("disableLocalAuth"))
    pf.fact("transport", "min_tls", p.get("minimumTlsVersion"))
    rs, src, err = _arm(arm, "network_rule_set")
    q = (rs or {}).get("properties") or {}
    if rs is not None:
        pf.fact("network", "default_action", q.get("defaultAction"), src)
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        if rs is not None:
            pf.fact("network", "ip_rules", [x.get("ipMask") for x in q.get("ipRules") or []], src)
            pf.fact("network", "vnet_rules", [(x.get("subnet") or {}).get("id", "").lower() for x in q.get("virtualNetworkRules") or []], src)
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if rs is None:
        return pf.unknown("networkRuleSets/default", err)
    ips = [x.get("ipMask") for x in q.get("ipRules") or [] if _eq(x.get("action") or "Allow", "Allow")]
    subnets = [(x.get("subnet") or {}).get("id", "").lower() for x in q.get("virtualNetworkRules") or []]
    pf.fact("network", "default_action", q.get("defaultAction"), src)
    pf.fact("network", "ip_rules", ips, src)
    pf.fact("network", "vnet_rules", [s for s in subnets if s], src)
    pf.fact("network", "trusted_services", q.get("trustedServiceAccessEnabled"), src)
    pf.d["allow_ip_ranges"] += ips
    pf.d["allow_subnets"] += [s for s in subnets if s]
    if _eq(q.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", f"networkRuleSet.publicNetworkAccess = Disabled [{src}]")
    if _eq(q.get("defaultAction"), "Allow"):
        return pf.verdict("all_networks", f"networkRuleSet.defaultAction = Allow [{src}]")
    if _eq(q.get("defaultAction"), "Deny"):
        if not ips and not subnets:
            return pf.verdict("enabled_no_allow_rules", f"defaultAction = Deny, no rules [{src}]")
        return pf.verdict("restricted", f"defaultAction = Deny; {len(ips)} IP, {len(subnets)} VNet rule(s) [{src}]")
    return pf.unknown("networkRuleSet.defaultAction", f"unexpected value {q.get('defaultAction')!r}")


def _search(r, p, arm, pf: Profile):
    pf.fact("auth", "local_auth_disabled", p.get("disableLocalAuth"))
    ips = [x.get("value") for x in (p.get("networkRuleSet") or {}).get("ipRules") or [] if x.get("value")]
    pf.fact("network", "ip_rules", ips)
    pf.d["allow_ip_ranges"] += ips
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = disabled")
    if not ips:
        return pf.verdict("all_networks", "no networkRuleSet.ipRules (Search default: all networks)")
    return pf.verdict("restricted", f"{len(ips)} IP rule(s)")


def _disk(r, p, arm, pf: Profile):
    pol, state = p.get("networkAccessPolicy"), p.get("diskState")
    pf.fact("network", "network_access_policy", pol)
    pf.fact("network", "disk_access", (p.get("diskAccessId") or "").lower() or None)
    pf.fact("network", "disk_state", state)
    pf.fact("network", "active_export_sas", state in ("ActiveSAS", "ActiveSASFrozen") if state else None)
    pf.fact("auth", "data_access_auth_mode", p.get("dataAccessAuthMode"))
    scope = "scope: disk export/import through a SAS URL (someone with beginGetAccess must create it)"
    live = [f"diskState = {state}: an export SAS is active now"] if state in ("ActiveSAS", "ActiveSASFrozen") else []
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled", scope)
    if pol is None:
        return pf.unknown("networkAccessPolicy", "not present in disk properties")
    if _eq(pol, "DenyAll"):
        return pf.verdict("disabled", "networkAccessPolicy = DenyAll (export/import denied)", scope)
    if _eq(pol, "AllowPrivate"):
        return pf.verdict("disabled", "networkAccessPolicy = AllowPrivate (only through the disk access private endpoint)", scope)
    if _eq(pol, "AllowAll"):
        return pf.verdict("all_networks", "networkAccessPolicy = AllowAll", *live, scope)
    return pf.unknown("networkAccessPolicy", f"unexpected value {pol!r}")


def _purview(r, p, arm, pf: Profile):
    pna = p.get("publicNetworkAccess")
    pf.fact("network", "managed_resources_public_network_access", p.get("managedResourcesPublicNetworkAccess"))
    if _eq(pna, "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    if _eq(pna, "Enabled"):
        return pf.verdict("all_networks", "publicNetworkAccess = Enabled")
    return pf.unknown("publicNetworkAccess", f"value {pna!r} has no documented meaning to apply")


def _automation(r, p, arm, pf: Profile):
    v = p.get("publicNetworkAccess")
    pf.fact("auth", "local_auth_disabled", p.get("disableLocalAuth"))
    scope = "scope: non-ARM endpoints (webhooks, Hybrid Runbook Worker / agent)"
    if v is True:
        return pf.verdict("all_networks", "publicNetworkAccess = true (boolean)", scope)
    if v is False:
        return pf.verdict("disabled", "publicNetworkAccess = false (boolean)", scope)
    return pf.unknown("publicNetworkAccess", f"value {v!r} is not a boolean")


def _aca_env(r, p, arm, pf: Profile):
    vc = p.get("vnetConfiguration") or {}
    internal = vc.get("internal")
    pf.fact("network", "internal", internal)
    pf.fact("network", "infrastructure_subnet", (vc.get("infrastructureSubnetId") or "").lower() or None)
    pf.fact("network", "static_ip", p.get("staticIp"))
    pf.fact("transport", "peer_mtls", ((p.get("peerAuthentication") or {}).get("mtls") or {}).get("enabled"))
    if internal is True:
        return pf.verdict("vnet_injected", "vnetConfiguration.internal = true (internal load balancer only)")
    if _eq(p.get("publicNetworkAccess"), "Disabled"):
        return pf.verdict("disabled", "publicNetworkAccess = Disabled")
    why = "vnetConfiguration.internal = false" if internal is False else \
        "vnetConfiguration.internal unset (Container Apps default: external environment)"
    return pf.verdict("decided_per_app", why, "each container app's ingress decides its own exposure")


def _container_app(r, p, arm, pf: Profile):
    ing = (p.get("configuration") or {}).get("ingress")
    env = (p.get("managedEnvironmentId") or p.get("environmentId") or "").lower() or None
    pf.fact("network", "environment", env)
    pf.d["_needs_env"] = env
    if not ing:
        return pf.verdict("no_inbound_endpoint", "configuration.ingress not set")
    rules = ing.get("ipSecurityRestrictions") or []
    pf.fact("network", "external", ing.get("external"))
    pf.fact("network", "target_port", ing.get("targetPort"))
    pf.fact("network", "ip_restrictions", [{k: x.get(k) for k in ("name", "action", "ipAddressRange")} for x in rules])
    pf.fact("transport", "allow_insecure_http", ing.get("allowInsecure"))
    pf.fact("transport", "transport", ing.get("transport"))
    pf.fact("auth", "client_certificate_mode", ing.get("clientCertificateMode"))
    if not ing.get("external"):
        pf.d["_needs_env"] = None
        return pf.verdict("disabled", "ingress.external = false (reachable only inside the environment)")
    actions = {(x.get("action") or "").lower() for x in rules}
    if not rules:
        return pf.verdict("all_networks", "ingress.external = true, no ipSecurityRestrictions")
    if actions == {"allow"}:
        pf.d["allow_ip_ranges"] += [x.get("ipAddressRange") for x in rules if x.get("ipAddressRange")]
        if covers_all_ipv4([y for y in (ip_range(x.get("ipAddressRange") or "") for x in rules) if y]):
            return pf.verdict("all_networks", "Allow rules cover all IPv4")
        return pf.verdict("restricted", f"{len(rules)} Allow rule(s); all other sources denied")
    if actions == {"deny"}:
        return pf.verdict("all_networks_with_denies", f"{len(rules)} Deny rule(s); all other sources allowed")
    return pf.unknown("ipSecurityRestrictions", "mixed Allow and Deny rules, which Container Apps does not define")


def finalize_container_app(prof: dict, env: dict | None, env_name: str | None) -> None:
    """Second step once the environment is known: an internal environment has no public entry."""
    env_id = prof.pop("_needs_env", None)
    if env_id is None or prof["public_endpoint"] in ("no_inbound_endpoint", "disabled", "unknown"):
        return
    if env is None:
        prof["unknown"].append({"field": "environment", "reason": "environment not in scan"})
        prof["public_endpoint"] = "unknown"
        prof["because"].append("environment not in scan, so internal/external is unknown")
        return
    state = env["public_endpoint"]
    if state in ("vnet_injected", "disabled"):
        prof["public_endpoint"] = "disabled"
        prof["because"].append(f"environment {env_name}: {env['because'][0]} (overrides external ingress)")
        prof["allow_ip_ranges"] = []
    elif state == "decided_per_app":
        prof["because"].append(f"environment {env_name}: {env['because'][0]}")
    else:
        prof["public_endpoint"] = "unknown"
        prof["unknown"].append({"field": "environment", "reason": f"environment verdict is {state}"})


def _logic_app(r, p, arm, pf: Profile):
    if "definition" not in p:
        return pf.unknown("definition", "workflow definition not in resource properties")
    all_trig = {k: ((v or {}).get("type") or "?") for k, v in ((p.get("definition") or {}).get("triggers") or {}).items()}
    trig = {k: t for k, t in all_trig.items() if t.lower() in INBOUND_TRIGGERS}
    ac = (p.get("accessControl") or {}).get("triggers")
    pf.fact("network", "http_triggers", sorted(trig))
    pf.fact("network", "workflow_state", p.get("state"))
    pols = (((ac or {}).get("openAuthenticationPolicies") or {}).get("policies")) or {}
    pf.fact("auth", "oauth_policies", sorted(pols))
    if _eq(p.get("state"), "Disabled"):
        pf.d["notes"].append("workflow state = Disabled: triggers are not callable while disabled")
    pf.fact("network", "trigger_types", all_trig)
    if not all_trig:
        return pf.verdict("no_inbound_endpoint", "definition has no triggers")
    if not trig:
        kinds = ", ".join(f"{k} ({t})" for k, t in sorted(all_trig.items()))
        return pf.verdict("no_inbound_endpoint", f"triggers: {kinds}; none receive inbound calls")
    names = ", ".join(f"{k} ({t})" for k, t in sorted(trig.items()))
    if ac is None or "allowedCallerIpAddresses" not in ac:
        pf.fact("network", "allowed_caller_ranges", None)
        return pf.verdict("all_networks", f"inbound trigger(s) {names}; accessControl.triggers.allowedCallerIpAddresses "
                          "not set (any IP)", "callers still need the trigger SAS or a matching OAuth policy")
    ranges = [x.get("addressRange") for x in ac.get("allowedCallerIpAddresses") or [] if x.get("addressRange")]
    pf.fact("network", "allowed_caller_ranges", ranges)
    pf.d["allow_ip_ranges"] += ranges
    if not ranges:
        return pf.verdict("restricted", "allowedCallerIpAddresses = [] (only other Logic Apps can call)")
    if covers_all_ipv4([y for y in (ip_range(x) if "-" not in x else _pair(*x.split("-", 1)) for x in ranges) if y]):
        return pf.verdict("all_networks", "allowedCallerIpAddresses cover all IPv4")
    return pf.verdict("restricted", f"inbound trigger(s) {names}; {len(ranges)} allowed caller range(s)")


def _monitor_endpoints(auth_key: str | None):
    def ev(r, p, arm, pf: Profile):
        ing, q = p.get("publicNetworkAccessForIngestion"), p.get("publicNetworkAccessForQuery")
        pf.fact("network", "ingestion", ing)
        pf.fact("network", "query", q)
        if auth_key:
            val = (p.get("features") or {}).get(auth_key) if auth_key == "disableLocalAuth" else p.get(auth_key)
            pf.fact("auth", "local_auth_disabled", val)
        if ing is None and q is None:
            return pf.unknown("publicNetworkAccessForIngestion/ForQuery", "not present")
        both = f"publicNetworkAccessForIngestion = {ing}, publicNetworkAccessForQuery = {q}"
        if _eq(ing, "Enabled") or _eq(q, "Enabled"):
            return pf.verdict("all_networks", both, "verdict is the most open of the two endpoints")
        if _eq(ing, "SecuredByPerimeter") or _eq(q, "SecuredByPerimeter"):
            return pf.verdict("perimeter_controlled", both)
        if _eq(ing, "Disabled") and _eq(q, "Disabled"):
            return pf.verdict("disabled", both)
        return pf.unknown("publicNetworkAccessForIngestion/ForQuery", f"unexpected values: {both}")
    return ev


def _dce(r, p, arm, pf: Profile):
    v = (p.get("networkAcls") or {}).get("publicNetworkAccess")
    pf.fact("network", "public_network_access", v)
    if _eq(v, "Disabled"):
        return pf.verdict("disabled", "networkAcls.publicNetworkAccess = Disabled")
    if _eq(v, "SecuredByPerimeter"):
        return pf.verdict("perimeter_controlled", "networkAcls.publicNetworkAccess = SecuredByPerimeter")
    if _eq(v, "Enabled"):
        return pf.verdict("all_networks", "networkAcls.publicNetworkAccess = Enabled (logs and configuration endpoints)")
    return pf.unknown("networkAcls.publicNetworkAccess", f"value {v!r}")


EVALUATORS: dict[str, Callable] = {
    "microsoft.compute/disks": _disk,
    "microsoft.purview/accounts": _purview,
    "microsoft.automation/automationaccounts": _automation,
    "microsoft.app/managedenvironments": _aca_env,
    "microsoft.app/containerapps": _container_app,
    "microsoft.logic/workflows": _logic_app,
    "microsoft.operationalinsights/workspaces": _monitor_endpoints("disableLocalAuth"),
    "microsoft.insights/components": _monitor_endpoints("DisableLocalAuth"),
    "microsoft.insights/datacollectionendpoints": _dce,
    "microsoft.storage/storageaccounts": _storage,
    "microsoft.keyvault/vaults": _keyvault,
    "microsoft.cognitiveservices/accounts": _cognitive,
    "microsoft.sql/servers": _sql_server,
    "microsoft.sql/managedinstances": _sql_mi,
    "microsoft.dbforpostgresql/flexibleservers": _flex("PostgreSQL", "no firewall rules (PostgreSQL denies by default)"),
    "microsoft.dbformysql/flexibleservers": _flex("MySQL", "no firewall rules (MySQL denies by default)"),
    "microsoft.cache/redis": _redis,
    "microsoft.documentdb/databaseaccounts": _cosmos,
    "microsoft.web/sites": _webapp,
    "microsoft.containerregistry/registries": _acr,
    "microsoft.containerservice/managedclusters": _aks,
    "microsoft.servicebus/namespaces": _messaging,
    "microsoft.eventhub/namespaces": _messaging,
    "microsoft.search/searchservices": _search,
}


def evaluate(r: dict, arm: dict | None) -> dict | None:
    """Return an access profile, or None for types with no network surface of their own."""
    rtype = r["type"].lower()
    p = r.get("properties") or {}
    fn = EVALUATORS.get(rtype)
    if fn is None:
        if "publicNetworkAccess" not in p and not p.get("privateEndpointConnections"):
            return None
        pf = Profile(r, None)
        pf.d["because"].append("no evaluator for this type yet; raw publicNetworkAccess and private endpoints shown")
        return pf.d
    pf = Profile(r, rtype)
    out = fn(r, p, arm or {}, pf)
    state = out["public_endpoint"]
    if state in ("disabled", "vnet_injected", "perimeter_controlled"):
        # Rules recorded above still exist but do not apply; they return if access is re-enabled.
        out["network"].setdefault("rules_in_effect", False)
        out["allow_ip_ranges"], out["allow_subnets"] = [], []
    elif state in ("all_networks", "all_networks_with_denies", "restricted", "enabled_no_allow_rules"):
        out["network"].setdefault("rules_in_effect", True)
    if "local_auth_disabled" in out["auth"] and out["auth"]["local_auth_disabled"] is None:
        out["auth"]["local_auth_disabled"] = False
        out["notes"].append("auth.local_auth_disabled: the disable flag is not set, so local (key / shared key / "
                            "SAS) authentication is not disabled")
    out["allow_subnets"] = sorted(set(out["allow_subnets"]))
    return out
