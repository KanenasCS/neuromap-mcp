"""Offline selftest. No Azure access needed.

The fixture mimics Resource Graph rows for a small hub-spoke estate:
  hub-vnet (10.0.0.0/16): AzureFirewallSubnet (firewall + pip), AzureBastionSubnet (bastion)
  spoke-vnet (10.1.0.0/16): web subnet (nsg-web, route to firewall), data subnet (nsg-data)
  vm-web01 with NIC-level NSG + public IP; private endpoint to a storage account (outside scan)
  a leftover NSG and public IP that nothing uses
Note the deliberate casing differences in references, like real ARM data.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import json
import os
import sys
import tempfile

SUB = "00000000-1111-2222-3333-444444444444"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-net/providers"


def _rule(name, pri, direction, access, src, dport, proto="Tcp", asg_dst=None):
    p = {"priority": pri, "direction": direction, "access": access, "protocol": proto,
         "sourceAddressPrefix": src, "sourcePortRange": "*", "destinationPortRange": dport,
         "destinationAddressPrefix": "*"}
    if asg_dst:
        p.pop("destinationAddressPrefix")
        p["destinationApplicationSecurityGroups"] = [{"id": asg_dst}]
    return {"name": name, "properties": p}


DEFAULTS = [_rule("AllowVnetInBound", 65000, "Inbound", "Allow", "VirtualNetwork", "*", "*"),
            _rule("DenyAllInBound", 65500, "Inbound", "Deny", "*", "*", "*"),
            _rule("AllowInternetOutBound", 65001, "Outbound", "Allow", "*", "*", "*")]


def row(rtype, name, props, sku=None):
    return {"id": f"{RG}/{rtype}/{name}", "name": name, "type": rtype, "location": "westeurope",
            "resourceGroup": "rg-net", "subscriptionId": SUB, "tags": {}, "sku": sku, "properties": props}


def fixture() -> dict:
    N = "Microsoft.Network"
    hub, spoke = f"{RG}/{N}/virtualNetworks/hub-vnet", f"{RG}/{N}/virtualNetworks/spoke-vnet"
    asg_web = f"{RG}/{N}/applicationSecurityGroups/asg-web"
    res = [
        row(f"{N}/virtualNetworks", "hub-vnet", {
            "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
            "subnets": [
                {"id": f"{hub}/subnets/AzureFirewallSubnet", "name": "AzureFirewallSubnet",
                 "properties": {"addressPrefix": "10.0.1.0/26"}},
                {"id": f"{hub}/subnets/AzureBastionSubnet", "name": "AzureBastionSubnet",
                 "properties": {"addressPrefix": "10.0.2.0/26"}}],
            "virtualNetworkPeerings": [{"name": "hub-to-spoke", "properties": {
                "remoteVirtualNetwork": {"id": spoke.upper().replace("/SUBSCRIPTIONS", "/subscriptions")},
                "peeringState": "Connected", "allowGatewayTransit": True}}]}),
        row(f"{N}/virtualNetworks", "spoke-vnet", {
            "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
            "subnets": [
                {"id": f"{spoke}/subnets/web", "name": "web", "properties": {
                    "addressPrefix": "10.1.1.0/24",
                    "networkSecurityGroup": {"id": f"{RG}/{N}/networkSecurityGroups/nsg-web"},
                    "routeTable": {"id": f"{RG}/{N}/routeTables/rt-spoke"}}},
                {"id": f"{spoke}/subnets/data", "name": "data", "properties": {
                    "addressPrefix": "10.1.2.0/24",
                    "networkSecurityGroup": {"id": f"{RG}/{N}/networkSecurityGroups/NSG-DATA"}}}],
            "virtualNetworkPeerings": [{"name": "spoke-to-hub", "properties": {
                "remoteVirtualNetwork": {"id": hub}, "peeringState": "Connected", "useRemoteGateways": False}}]}),
        row(f"{N}/networkSecurityGroups", "nsg-web", {
            "securityRules": [
                _rule("Allow-HTTPS-In", 100, "Inbound", "Allow", "Internet", "443", asg_dst=asg_web),
                _rule("Allow-RDP-Any", 200, "Inbound", "Allow", "*", "3389"),
                _rule("Allow-Mgmt-Range", 300, "Inbound", "Allow", "203.0.113.0/24", "5985-5986")],
            "defaultSecurityRules": DEFAULTS,
            "subnets": [{"id": f"{spoke}/subnets/web"}]}),
        row(f"{N}/networkSecurityGroups", "nsg-data", {
            "securityRules": [_rule("Allow-SQL-From-Web", 100, "Inbound", "Allow", "10.1.1.0/24", "1433")],
            "defaultSecurityRules": DEFAULTS, "subnets": [{"id": f"{spoke}/subnets/data"}]}),
        row(f"{N}/networkSecurityGroups", "nsg-vm-web01", {
            "securityRules": [_rule("Deny-RDP-In", 100, "Inbound", "Deny", "*", "3389")],
            "defaultSecurityRules": DEFAULTS,
            "networkInterfaces": [{"id": f"{RG}/{N}/networkInterfaces/vm-web01-nic"}]}),
        row(f"{N}/networkSecurityGroups", "nsg-orphan", {"securityRules": [], "defaultSecurityRules": DEFAULTS}),
        row(f"{N}/applicationSecurityGroups", "asg-web", {}),
        row(f"{N}/networkInterfaces", "vm-web01-nic", {
            "ipConfigurations": [{"name": "ipconfig1", "properties": {
                "privateIPAddress": "10.1.1.4", "subnet": {"id": f"{spoke}/subnets/web"},
                "publicIPAddress": {"id": f"{RG}/{N}/publicIPAddresses/pip-web01"},
                "applicationSecurityGroups": [{"id": asg_web}]}}],
            "networkSecurityGroup": {"id": f"{RG}/{N}/networkSecurityGroups/nsg-vm-web01"},
            "virtualMachine": {"id": f"{RG}/Microsoft.Compute/virtualMachines/vm-web01"}}),
        row("Microsoft.Compute/virtualMachines", "vm-web01", {
            "hardwareProfile": {"vmSize": "Standard_B2s"},
            "storageProfile": {"osDisk": {"osType": "Windows"}},
            "networkProfile": {"networkInterfaces": [{"id": f"{RG}/{N}/networkInterfaces/vm-web01-nic"}]},
            "extended": {"instanceView": {"powerState": {"code": "PowerState/running"}}}}),
        row(f"{N}/publicIPAddresses", "pip-web01", {
            "ipAddress": "20.50.60.70", "publicIPAllocationMethod": "Static",
            "ipConfiguration": {"id": f"{RG}/{N}/networkInterfaces/vm-web01-nic/ipConfigurations/ipconfig1"}},
            sku={"name": "Standard"}),
        row(f"{N}/publicIPAddresses", "pip-fw", {
            "ipAddress": "20.50.60.80",
            "ipConfiguration": {"id": f"{RG}/{N}/azureFirewalls/fw-hub/azureFirewallIpConfigurations/cfg"}}),
        row(f"{N}/publicIPAddresses", "pip-orphan", {"ipAddress": "20.50.60.99"}),
        row(f"{N}/azureFirewalls", "fw-hub", {
            "sku": {"tier": "Premium"},
            "ipConfigurations": [{"name": "cfg", "properties": {
                "privateIPAddress": "10.0.1.4", "subnet": {"id": f"{hub}/subnets/AzureFirewallSubnet"},
                "publicIPAddress": {"id": f"{RG}/{N}/publicIPAddresses/pip-fw"}}}]}),
        row(f"{N}/bastionHosts", "bas-hub", {
            "ipConfigurations": [{"name": "cfg", "properties": {
                "subnet": {"id": f"{hub}/subnets/AzureBastionSubnet"}}}]}, sku={"name": "Standard"}),
        row(f"{N}/routeTables", "rt-spoke", {
            "routes": [{"name": "default-to-fw", "properties": {
                "addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.1.4"}}],
            "subnets": [{"id": f"{spoke}/subnets/web"}]}),
        row(f"{N}/privateEndpoints", "pe-storage", {
            "subnet": {"id": f"{spoke}/subnets/data"},
            "privateLinkServiceConnections": [{"name": "c", "properties": {
                "privateLinkServiceId": f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata01",
                "groupIds": ["blob"], "privateLinkServiceConnectionState": {"status": "Approved"}}}],
            "networkInterfaces": [{"id": f"{RG}/{N}/networkInterfaces/pe-storage-nic"}]}),
        row(f"{N}/networkInterfaces", "pe-storage-nic", {
            "ipConfigurations": [{"name": "p", "properties": {
                "privateIPAddress": "10.1.2.5", "subnet": {"id": f"{spoke}/subnets/data"}}}],
            "privateEndpoint": {"id": f"{RG}/{N}/privateEndpoints/pe-storage"}}),
    ]
    return {"schema": 1, "collected_at": "2026-09-29T09:00:00+00:00",
            "subscriptions": [{"id": SUB, "name": "sub-demo", "state": "Enabled"}],
            "not_visible": [], "resources": res}


def run() -> int:
    tmp = tempfile.mkdtemp(prefix="neuromap-selftest-")
    os.environ["NEUROMAP_HOME"] = tmp
    from . import graph as G, store
    from . import __version__
    from .visualize import render_html

    ok = fail = 0

    def check(name, cond, detail=""):
        nonlocal ok, fail
        ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
        print(("  PASS " if cond else "  FAIL ") + name + ("" if cond else f"  -> {detail}"))

    print("graph build")
    stamp, g = store.save(fixture())
    s = G.summary(g)
    check("counts by kind", s["counts"].get("vnet") == 2 and s["counts"].get("subnet") == 4
          and s["counts"].get("nsg") == 4 and s["counts"].get("pip") == 3, s["counts"])
    check("peering both ways despite ID casing", sum(1 for e in g.edges if e["rel"] == "PEERED_WITH") == 2)
    check("NSG ref with different casing merges", "nsg-data" not in [n["name"] for n in g.nodes.values() if not n["in_scan"]])
    check("unattached found", s["unattached"] == {"nsgs": ["nsg-orphan"], "public_ips": ["pip-orphan"]}, s["unattached"])
    check("private link target kept as external node",
          any(n["name"] == "stdata01" and not n["in_scan"] for n in g.nodes.values()))
    check("firewall public IP via ipConfiguration parent",
          g.one(g.resolve("fw-hub")[0]["id"], "HAS_PUBLIC_IP")["name"] == "pip-fw")

    print("lookup")
    check("resolve private IP", [n["name"] for n in g.resolve("10.1.1.4")] == ["vm-web01-nic"])
    check("resolve public IP", [n["name"] for n in g.resolve("20.50.60.70")] == ["pip-web01"])
    check("subnet containing IP", [n["name"] for n in g.subnet_for_ip("10.1.2.200")] == ["data"])

    print("nsg layers")
    L = G.nsg_layers(g, g.resolve("vm-web01")[0])
    iface = L["interfaces"][0]
    check("inbound order subnet then nic", [x["nsg"] for x in iface["inbound"]] == ["nsg-web", "nsg-vm-web01"])
    check("outbound order nic then subnet", [x["nsg"] for x in iface["outbound"]] == ["nsg-vm-web01", "nsg-web"])
    check("rules priority sorted", [r["priority"] for r in iface["inbound"][0]["rules"]][:3] == [100, 200, 300])
    L2 = G.nsg_layers(g, g.resolve("pip-web01")[0])
    check("public IP resolves to its NIC", L2["interfaces"][0]["nic"] == "vm-web01-nic")
    L3 = G.nsg_layers(g, g.resolve("pe-storage")[0])
    check("private endpoint: nic layer empty, noted", L3["interfaces"][0]["inbound"][1]["nsg"] is None
          and L3["interfaces"][0]["inbound"][1]["note"])

    print("rule search")
    r = G.search_rules(g, port=3389, source="internet", access="Allow")
    check("3389 allow from internet ('*')", [m["rule"]["name"] for m in r["matches"]] == ["Allow-RDP-Any"], r)
    check("match reports attachment", r["matches"][0]["attached_to"][0]["name"] == "web")
    check("port range 5985-5986", G.search_rules(g, port=5986)["match_count"] == 1)
    check("CIDR overlap on source", [m["rule"]["name"] for m in G.search_rules(g, source="10.1.1.10")["matches"]]
          == ["Allow-SQL-From-Web", "Deny-RDP-In", "Allow-RDP-Any"])
    check("defaults excluded unless asked", G.search_rules(g, include_default=True)["match_count"] > G.search_rules(g)["match_count"])

    print("persistence and map")
    st, g2 = store.load()
    check("reload equals build", len(g2.nodes) == len(g.nodes) and len(g2.edges) == len(g.edges))
    check("IP index rebuilt on load", [n["name"] for n in g2.resolve("20.50.60.80")] == ["pip-fw"])
    html = render_html(g2)
    check("map is self-contained (no external scripts)", "<script src" not in html and len(html) > 400_000)

    print("v0.2: access verdicts (precise, sourced)")
    from .fixture_v2 import fixture_v2
    os.environ["NEUROMAP_HOME"] = tempfile.mkdtemp(prefix="neuromap-selftest-v2-")
    _, g = store.save(fixture_v2())
    acc = lambda name: g.resolve(name)[0]["props"].get("access") or {}
    rel = lambda a, b, r: any(e["rel"] == r and e["dst"] == g.resolve(b)[0]["id"] for e in g.out.get(g.resolve(a)[0]["id"], []))
    expect = {"stdata01": "restricted", "kv-app": "all_networks", "sql-prod": "restricted", "sql-open": "all_networks",
              "sql-private": "disabled", "sql-noenrich": "unknown", "web-app01": "restricted", "web-open": "all_networks",
              "web-denyfirst": "all_networks_with_denies", "cosmos-app": "all_networks", "aks-prod": "disabled",
              "acrstd": "all_networks", "redis-a": "unknown", "sb-ns": "enabled_no_allow_rules",
              "pg-private": "vnet_injected", "appcs": "not_evaluated"}
    got = {k: acc(k).get("public_endpoint") for k in expect}
    check("16 verdicts exactly as expected", got == expect, {k: (got[k], v) for k, v in expect.items() if got[k] != v})
    check("every decided verdict cites fields", all(acc(k)["because"] for k in expect))
    check("SQL: union of split rules = all IPv4", "cover 0.0.0.0-255.255.255.255" in acc("sql-open")["because"][0])
    check("SQL: 0.0.0.0 rule flagged as all Azure services", acc("sql-prod")["network"]["allow_all_azure_services"] is True)
    check("SQL: Entra-only from ARM with api version", acc("sql-prod")["auth"]["entra_only"] is True
          and acc("sql-prod")["sources"]["auth.entra_only"] == "arm 2021-11-01")
    check("SQL: not enriched -> unknown with reason", "not collected" in acc("sql-noenrich")["unknown"][0]["reason"])
    check("Redis: ARM 403 -> unknown, not guessed", "HTTP 403" in acc("redis-a")["unknown"][0]["reason"])
    check("Storage: unset shared key default goes to notes, not verdict evidence",
          any("unset = true" in b for b in acc("stdata01")["notes"])
          and not any("SharedKey" in b for b in acc("stdata01")["because"]))
    check("because[0] is always network evidence", all(
        not acc(k)["because"][0].startswith(("auth.", "allowSharedKey", "enableRbac")) for k in expect))
    check("Web: Deny-all last + allow rules -> restricted", "earlier allow rules" in acc("web-app01")["because"][0])
    check("Web: SCM uses main rules", acc("web-app01")["network"]["scm_endpoint"]["public_endpoint"] == "restricted")
    check("Web: SCM explicit Deny, no rules", acc("web-denyfirst")["network"]["scm_endpoint"]["public_endpoint"]
          == "enabled_no_allow_rules")
    check("Web: basic auth facts", acc("web-app01")["auth"]["ftp_basic_auth_allowed"] is False
          and acc("web-app01")["auth"]["scm_basic_auth_allowed"] is True)
    check("ACR: Standard sku rule cited", "only on Premium" in acc("acrstd")["because"][0])
    sp = acc("sql-private")
    check("SQL disabled: firewall rules still shown, marked not in effect",
          [r["name"] for r in sp["network"]["firewall_rules"]] == ["office"] and sp["network"]["rules_in_effect"] is False)
    check("SQL disabled: no allow edges from its rules", not sp["allow_subnets"] and not sp["allow_ip_ranges"])
    check("SQL: empty administrators list -> explicit 'no Entra admin', sourced",
          sp["auth"]["entra_admin"] is None and any("empty list" in n for n in sp["notes"])
          and sp["sources"]["auth.entra_admin"] == "arm 2021-11-01")
    check("SQL: Entra-only false -> SQL auth accepted note", sp["auth"]["entra_only"] is False
          and any("SQL authentication" in n for n in sp["notes"]))
    check("SQL: admin from servers/administrators", acc("sql-prod")["auth"]["entra_admin"]["login"] == "sql-admins")
    check("SQL: admin not read -> 'not confirmed', never assumed absent",
          any("not confirmed" in n for n in acc("sql-noenrich")["notes"]))

    print("v0.2: connections")
    check("pip allowlisted on storage IP rule", rel("pip-web01", "stdata01", "IP_RULE_ALLOWS"))
    check("subnet VNet rule -> storage", rel("web", "stdata01", "VNET_RULE_ALLOWS"))
    check("subnet VNet rule -> SQL", rel("data", "sql-prod", "VNET_RULE_ALLOWS"))
    check("no VNet-rule edge when public access disabled", not rel("data", "sql-private", "VNET_RULE_ALLOWS"))
    check("private endpoint -> storage", rel("pe-storage", "stdata01", "CONNECTS_TO"))
    check("internet -> open Key Vault", rel("internet", "kv-app", "OPEN_TO_ALL_NETWORKS"))
    check("SQL server contains database", rel("sql-prod", "appdb", "CONTAINS"))
    check("web app VNet integration + plan", rel("web-app01", "web", "VNET_INTEGRATION") and rel("web-app01", "plan-1", "HOSTED_ON"))
    check("AKS nodes in subnet", rel("aks-prod", "web", "IN_SUBNET"))
    check("PostgreSQL delegated subnet", rel("pg-private", "data", "IN_SUBNET"))
    check("web app uses UAMI", rel("web-app01", "uami-app", "USES_IDENTITY"))
    la = [e for e in g.out[g.resolve("la-sync")[0]["id"]] if e["rel"] == "REFERENCES"]
    check("generic reference keeps exact property path", len(la) == 1
          and la[0]["path"] == "properties.parameters.$connections.value.sql.connectionId", la)
    L = G.nsg_layers(g, g.resolve("aks-prod")[0])
    check("AKS NSG view = subnet layer", L.get("subnet_only") and L["subnets"][0]["inbound"][0]["nsg"] == "nsg-web")

    print("v0.2: RBAC")
    w = G.who_has_access(g, g.resolve("kv-app")[0])
    roles = sorted((a["role"] or a["role_definition_id"], a["inherited"], a["principal"]["name"]) for a in w["role_assignments"])
    check("kv-app: direct + RG + sub + MG assignments", roles == sorted([
        ("99999999-9999-9999-9999-999999999999", False, f"User {'cccccccc-0000-0000-0000-000000000003'}"),
        ("Key Vault Secrets User", True, "uami-app"),
        ("Owner", True, "User cccccccc-0000-0000-0000-000000000003"),
        ("Reader", True, "Group dddddddd-0000-0000-0000-000000000004"),
        ("User Access Administrator", True, "Group dddddddd-0000-0000-0000-000000000004")]), roles)
    cap = {(a["role"] or "?"): a["capabilities"] for a in w["role_assignments"]}
    check("capabilities from actions: Owner and UAA can assign roles, Reader cannot",
          cap["Owner"]["assign_roles"] and cap["User Access Administrator"]["assign_roles"] and not cap["Reader"]["assign_roles"])
    check("capabilities: unknown role definition -> known=False, never guessed", cap["?"]["known"] is False)
    check("capabilities: write/delete on the target's own type", cap["Owner"]["write_resource"] and cap["Owner"]["delete_resource"]
          and not cap["Reader"]["write_resource"] and not cap["User Access Administrator"]["write_resource"])
    cw = {a["role"]: a["capabilities"] for a in G.who_has_access(g, g.resolve("stdata01")[0])["role_assignments"]}
    check("capabilities: Contributor notActions remove role assignment", cw["Contributor"]["assign_roles"] is False
          and cw["Contributor"]["write_resource"] is True)
    check("who can assign roles on kv-app: counted with evidence", w["principals_that_can_assign_roles"]["count"] == 2)
    check("scope coverage: every scope collected in a full scan",
          all(x["collected"] for x in w["scope_coverage"]) and [x["scope"] for x in w["scope_coverage"]][-1] == "/")
    raw_partial = fixture_v2()
    raw_partial["rbac_coverage"] = {"subscription_and_below": True, "above_subscription": False}
    raw_partial["role_assignments"] = [a for a in raw_partial["role_assignments"]
                                       if a["properties"]["scope"].lower().startswith("/subscriptions/")]
    wp = G.who_has_access(G.build_graph(raw_partial), G.build_graph(raw_partial).resolve("kv-app")[0])
    above = [x for x in wp["scope_coverage"] if x["scope"] == "/" or "/managementgroups/" in x["scope"]]
    check("scope coverage: MG and root not collected -> unknown, not zero",
          len(above) == 3 and all(x["collected"] is False and x["assignments"] is None and "not zero" in x["note"]
                                  for x in above), above)
    check("unresolved role keeps GUID, name None", any(a["role"] is None and a["role_definition_id"].startswith("9999")
                                                       for a in w["role_assignments"]))
    check("KV access policies in data-plane auth", len(w["data_plane_auth"]["access_policies"]) == 1)
    ip = G.identity_permissions(g, g.resolve("web-app01")[0])
    check("web-app01 identities -> roles", sorted((r["via"], r["role"]) for r in ip["roles_held"]) == [
        ("system-assigned", "Storage Blob Data Reader"), ("user-assigned uami-app", "Key Vault Secrets User")], ip)
    ex = G.exposure_list(g)
    check("exposure list = 6 open resources", sorted(r["name"] for r in ex["resources"]) ==
          ["acrstd", "cosmos-app", "kv-app", "sql-open", "web-denyfirst", "web-open"], ex)
    st2, g2 = store.load()
    check("v2 reload keeps multi-edges", sum(e["rel"] == "HAS_ROLE" for e in g2.edges) == 7)
    html2 = render_html(g2)

    print("collector against a mocked Azure API")
    import httpx
    from .collector import ARM, AzureCollector
    from urllib.parse import unquote
    owner_guid = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

    def mk(scope, n):
        return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/m{n}", "properties": {
            "principalId": f"p{n}", "principalType": "User", "scope": scope,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{owner_guid}"}}

    def azure(fail_above: bool):
        def handler(req: httpx.Request) -> httpx.Response:
            u = unquote(str(req.url))
            if u.startswith(f"{ARM}/subscriptions?"):
                return httpx.Response(200, json={"value": [{"subscriptionId": SUB, "displayName": "s", "state": "Enabled"}]})
            if "Microsoft.ResourceGraph" in u:
                q = json.loads(req.content)["query"]
                return httpx.Response(200, json={"data": [mk(f"/subscriptions/{SUB}", 1)] if "AuthorizationResources" in q else []})
            if "roleAssignments" in u and "$filter=atScope()" in u:
                if fail_above:
                    return httpx.Response(403, json={"error": {"code": "AuthorizationFailed"}})
                return httpx.Response(200, json={"value": [mk(f"/subscriptions/{SUB}", 1), mk("/providers/Microsoft.Management/managementGroups/mg1", 2), mk("", 3) | {"properties": mk("/", 3)["properties"]}]})
            if "roleDefinitions" in u:
                return httpx.Response(200, json={"value": [{"name": owner_guid, "properties": {
                    "roleName": "Owner", "type": "BuiltInRole", "permissions": [{"actions": ["*"], "notActions": []}]}}]})
            return httpx.Response(404, json={})
        return handler

    class Cred:
        def get_token(self, *a):
            return type("T", (), {"token": "x"})()
    col = AzureCollector(credential=Cred())
    col._http = httpx.Client(transport=httpx.MockTransport(azure(False)))
    rawc = col.collect(enrich=False)
    scopes = sorted(a["properties"]["scope"] for a in rawc["role_assignments"])
    check("collector: MG and root assignments added via atScope(), subscription one not duplicated",
          scopes == ["/", "/providers/Microsoft.Management/managementGroups/mg1", f"/subscriptions/{SUB}"], scopes)
    check("collector: coverage recorded", rawc["rbac_coverage"] == {"subscription_and_below": True, "above_subscription": True})
    check("collector: role permissions captured", rawc["role_definitions"][owner_guid]["actions"] == ["*"])
    col._http = httpx.Client(transport=httpx.MockTransport(azure(True)))
    rawf = col.collect(enrich=False)
    check("collector: 403 above subscription -> coverage false + error, scan still succeeds",
          rawf["rbac_coverage"]["above_subscription"] is False and rawf["errors"][0]["status"] == 403
          and len(rawf["role_assignments"]) == 1)

    print("stale data can never be served")
    os.environ["NEUROMAP_HOME"] = tempfile.mkdtemp(prefix="neuromap-selftest-stale-")
    st, gs = store.save(fixture_v2())
    gp = store.home() / "snapshots" / f"{st}.graph.json"
    d = json.loads(gp.read_text(encoding="utf-8"))
    d["meta"]["builder_version"] = "0.0.1"
    for n in d["nodes"]:
        n["in_scan"] = False
    gp.write_text(json.dumps(d), encoding="utf-8")
    _, gl = store.load()
    check("graph from another version is rebuilt from raw on load", gl.meta["builder_version"] == __version__
          and all(n["in_scan"] for n in gl.nodes.values() if n["kind"] == "subnet"))
    for e in gs.edges:
        e.pop("lb_id", None)
    try:
        G.ingress_paths(gs); ok_noid = True
    except Exception:
        ok_noid = False
    check("ingress_paths tolerates edges without lb_id (no crash)", ok_noid)

    print("order independence (found by the first live scan)")
    import random
    base = G.build_graph(fixture_v2())
    sig = lambda gr: (sorted((n["id"], n["kind"], n["in_scan"]) for n in gr.nodes.values()),
                      sorted((e["src"], e["dst"], e["rel"], e.get("uniq") or "") for e in gr.edges))
    same = True
    for seed in range(5):
        raw = fixture_v2()
        random.Random(seed).shuffle(raw["resources"])
        same &= sig(G.build_graph(raw)) == sig(base)
    check("5 shuffled row orders build identical graphs", same)
    raw = fixture_v2()
    raw["resources"].sort(key=lambda r: 0 if r["type"].endswith("networkInterfaces") else 1)
    gr = G.build_graph(raw)
    check("NIC before VNet: every subnet still in scan",
          all(n["in_scan"] for n in gr.nodes.values() if n["kind"] == "subnet")
          and G.summary(gr)["counts"]["subnet"] == 4)

    print("v0.3: firewalls")
    from .fixture_v3 import fixture_v3
    os.environ["NEUROMAP_HOME"] = tempfile.mkdtemp(prefix="neuromap-selftest-v3-")
    _, g = store.save(fixture_v3())
    node = lambda name: g.resolve(name)[0]
    edges = lambda a, b, r: [e for e in g.out.get(node(a)["id"], []) if e["rel"] == r and e["dst"] == node(b)["id"]]
    fw = G.firewall_view(g, node("fw-hub"))
    check("processing order DNAT > network > app, parent first, by priority",
          [(r["type"], r["name"]) for r in fw["rules"]] == [("dnat", "rdp-to-vm"), ("dnat", "ssh-office"),
          ("network", "no-telnet"), ("network", "spoke-https"), ("application", "ms-updates")], fw["rules"])
    check("inherited rule marked", [r["inherited"] for r in fw["rules"] if r["name"] == "no-telnet"] == [True])
    check("IP group expanded", [r["sources_expanded"] for r in fw["rules"] if r["name"] == "ssh-office"] == [["203.0.113.0/24"]])
    check("policy settings win (threat intel Deny, IDPS, DNS proxy)", fw["settings"]["threat_intel_mode"] == "Deny"
          and fw["settings"]["idps_mode"] == "Alert" and fw["settings"]["dns_proxy"] is True, fw["settings"])
    check("policy chain", fw["policy_chain"] == ["fwp-hub", "fwp-parent"])
    check("policy -> IP group edge", len(edges("fwp-hub", "ipg-office", "USES_IP_GROUP")) == 1)
    check("policy view lists its firewalls", G.firewall_view(g, node("fwp-hub"))["used_by_firewalls"] == ["fw-hub"])
    check("classic rules parsed", [(r["type"], r["name"]) for r in G.firewall_view(g, node("fw-legacy"))["rules"]]
          == [("dnat", "web-8080"), ("network", "dns-out")])
    d = edges("pip-fw", "vm-web01-nic", "DNAT_FORWARDS")
    check("DNAT any-source to VM NIC", len(d) == 1 and d[0]["any_source"] is True and d[0]["ports"] == ["3389"], d)
    check("Internet -> firewall public IP only for any-source DNAT", len(edges("internet", "pip-fw", "INGRESS_ANY_SOURCE")) == 1
          and not edges("internet", "pip-legacy", "INGRESS_ANY_SOURCE"))
    d2 = edges("pip-fw", "ip:10.1.2.50", "DNAT_FORWARDS")
    check("DNAT to unowned IP -> explicit ip node, sources from IP group", len(d2) == 1 and d2[0]["any_source"] is False
          and not node("ip:10.1.2.50")["in_scan"], d2)
    check("classic DNAT from one IP", edges("pip-legacy", "vm-web01-nic", "DNAT_FORWARDS")[0]["sources"] == ["198.51.100.7"])
    sr = G.search_firewall_rules(g, port=3389, source="internet")
    check("search: 3389 from internet", [m["name"] for m in sr["matches"]] == ["rdp-to-vm"], sr)
    check("search: FQDN wildcard", [m["name"] for m in G.search_firewall_rules(g, fqdn="update.microsoft.com")["matches"]]
          == ["ms-updates"])
    check("search: app rule by protocol port", [m["name"] for m in G.search_firewall_rules(g, port=443, rule_type="application")["matches"]]
          == ["ms-updates"])

    print("v0.3: load balancer, VMSS, App Gateway + WAF")
    lbe = edges("pip-lb", "vm-web01-nic", "LB_FORWARDS")
    check("LB rule + NAT v1 to NIC", sorted((e["rule"], e["frontend_port"], e["backend_port"]) for e in lbe)
          == [("https", 443, 8443), ("ssh-vm", 50001, 22)], lbe)
    v = edges("pip-lb", "vmss-api", "LB_FORWARDS")
    check("NAT v2 port range to VMSS", len(v) == 1 and v[0]["frontend_port"] == "50100-50199", v)
    check("LB: node listed twice in a pool counts once", [e["backend_instances"] for e in lbe if e["rule"] == "https"] == [1])
    empty = [p for p in G.ingress_paths(g)["paths"] if p["path"] == "load_balancer" and p["target"] is None]
    check("LB: stopped-cluster rules listed as declared entry points, not dropped",
          sorted(p["detail"]["frontend_port"] for p in empty) == [80, 443]
          and all(p["detail"]["backend_instances"] == 0 and p["entry"]["name"] == "k8s-pip" for p in empty), empty)
    check("LB: owning AKS from nodeResourceGroup, with power state", empty[0]["detail"]["owning_aks"] ==
          {"cluster": "aks-stopped", "power_state": "Stopped", "because": "load balancer is in the cluster's nodeResourceGroup"}
          and [e["dst"] for e in g.out[node("aks-stopped")["id"]] if e["rel"] == "MANAGES"]
          == [f"/subscriptions/{SUB}/resourcegroups/mc_rg-net_aks-stopped_westeurope/providers/microsoft.network/loadbalancers/kubernetes"])
    check("LB: non-AKS load balancer gets no AKS owner", "owning_aks" not in node("lb-web-pub")["props"])
    run_lb = f"/subscriptions/{SUB}/resourcegroups/mc_rg-net_aks-run_westeurope/providers/microsoft.network/loadbalancers/kubernetes"
    stop_lb = f"/subscriptions/{SUB}/resourcegroups/mc_rg-net_aks-stopped_westeurope/providers/microsoft.network/loadbalancers/kubernetes"
    run_paths = G.ingress_paths(g, g.nodes[run_lb])["paths"]
    check("LB: active paths also carry owning_aks (running cluster)", len(run_paths) == 1
          and run_paths[0]["detail"]["owning_aks"]["cluster"] == "aks-run"
          and run_paths[0]["detail"]["owning_aks"]["power_state"] == "Running", run_paths)
    check("LB: a name shared by two load balancers is ambiguous, never silently picked",
          len(g.resolve("kubernetes")) == 2)
    check("LB: two load balancers both named 'kubernetes' are kept apart by id",
          len(G.ingress_paths(g, g.nodes[stop_lb])["paths"]) == 2
          and all(p["detail"]["lb_id"] == stop_lb for p in G.ingress_paths(g, g.nodes[stop_lb])["paths"]))
    check("AppGW: Container App FQDN backend resolves to the app", len(edges("pip-agw", "ca-open", "APPGW_ROUTES")) == 1)
    check("LB probe captured", [r["probe"]["name"] for r in node("lb-web-pub")["props"]["rules"] if r["name"] == "https"] == ["hp"])
    check("VMSS subnet + NIC-config NSG", edges("vmss-api", "web", "IN_SUBNET") and edges("vmss-api", "nsg-vm-web01", "PROTECTED_BY"))
    L = G.nsg_layers(g, node("vmss-api"))
    check("VMSS NSG layers", [x["nsg"] for x in L["interfaces"][0]["inbound"]] == ["nsg-web", "nsg-vm-web01"], L)
    a1 = edges("pip-agw", "web-app01", "APPGW_ROUTES")
    check("AppGW FQDN backend resolved to web app, listener WAF", len(a1) == 1 and a1[0]["waf"]["source"] == "listener"
          and a1[0]["waf"]["mode"] == "Prevention" and a1[0]["listener_port"] == 443, a1)
    a2 = edges("pip-agw", "vm-web01-nic", "APPGW_ROUTES")
    check("AppGW default path uses gateway WAF (Detection)", len(a2) == 1 and a2[0]["waf"]["source"] == "gateway"
          and a2[0]["waf"]["mode"] == "Detection" and a2[0]["paths"] == ["(default)"], a2)
    a3 = edges("pip-agw", "ip:10.77.0.9", "APPGW_ROUTES")
    check("AppGW path rule WAF override", len(a3) == 1 and a3[0]["waf"]["source"] == "path rule"
          and a3[0]["waf"]["mode"] == "Prevention" and a3[0]["paths"] == ["/api/*"], a3)

    print("v0.3: routes and hybrid")
    rv = G.route_view(g, node("vm-web01"))["subnets"][0]
    hop = {r["name"]: r for r in rv["routes"]}
    check("0/0 next hop resolved to firewall", hop["default-to-fw"]["next_hop_resource"]["name"] == "fw-hub")
    check("unowned next hop is explicit, not guessed", hop["to-nva"]["next_hop_resource"]["id"] == "ip:10.9.9.9"
          and hop["to-nva"]["next_hop_resource"]["in_scan"] is False)
    check("blackhole route flagged", hop["blackhole"]["drops_traffic"] is True)
    hv = G.hybrid_view(g)
    vg = next(x for x in hv["gateways"] if x["gateway"]["name"] == "vgw-hub")
    check("S2S connection with on-prem ranges + status", vg["connections"][0]["remote"]["name"] == "lng-dc1"
          and vg["connections"][0]["remote_ranges"] == ["192.168.0.0/16"] and vg["connections"][0]["status"] == "Connected", vg)
    check("spoke uses remote gateway", vg["spokes_using_this_gateway"] == ["spoke-vnet"])
    check("P2S pool + auth", vg["point_to_site"]["address_pool"] == ["172.16.200.0/24"] and vg["point_to_site"]["auth_types"] == ["AAD"])
    eg = next(x for x in hv["gateways"] if x["gateway"]["name"] == "ergw-hub")
    check("ER connection -> circuit with peerings", eg["connections"][0]["remote"]["name"] == "er-ams"
          and eg["connections"][0]["er_peerings"][0]["vlan"] == 100, eg)
    check("on-prem IP resolves to local network gateway", [h["node"]["name"] for h in g.containing_ranges("192.168.10.5")] == ["lng-dc1"])
    check("P2S client IP resolves to gateway pool", [h["what"] for h in g.containing_ranges("172.16.200.9")]
          == ["point-to-site client pool"])

    stc = node("st-closed")["props"]["access"]
    check("disabled storage: IP rules still shown, marked not in effect", stc["public_endpoint"] == "disabled"
          and stc["network"]["ip_rules"] == ["20.50.60.70"] and stc["network"]["rules_in_effect"] is False)
    check("disabled storage: its IP rule draws no allow edge", not edges("pip-web01", "st-closed", "IP_RULE_ALLOWS"))
    wc = node("web-closed")["props"]["access"]
    check("disabled web app: access restrictions still shown, not in effect",
          wc["public_endpoint"] == "disabled" and wc["network"]["access_restrictions"][0]["name"] == "Allow all"
          and wc["network"]["rules_in_effect"] is False, wc["network"])
    check("private endpoint known only from its own side is listed on the target",
          [(x["private_endpoint"].split("/")[-1], x["status"]) for x in wc["private_endpoints"]] == [("pe-web", "Approved")]
          and "private endpoint resource" in wc["private_endpoints"][0]["source"])
    cg = node("cog-noflag")["props"]["access"]
    check("local auth flag not set -> 'not disabled', with the reason", cg["auth"]["local_auth_disabled"] is False
          and any("not set, so local" in x for x in cg["notes"]))
    check("open resources say rules_in_effect true", node("stdata01")["props"]["access"]["network"]["rules_in_effect"] is True)
    so = node("sql-open")["props"].get("access") or {}
    check("SQL: empty azureADOnlyAuthentications -> Entra-only not enabled, stated", so["auth"]["entra_only"] is False
          and any("Entra-only authentication is not enabled" in n for n in so["notes"]), so["notes"])
    print("v0.3: ingress paths")
    ing = G.ingress_paths(g)
    kinds = Counter(p["path"] for p in ing["paths"])
    check("13 declared ingress paths (incl. 2 empty-pool LB rules)", kinds == Counter(firewall_dnat=3, load_balancer=6,
          app_gateway=4, public_ip_on_nic=1), kinds)
    check("filter by target NIC", G.ingress_paths(g, node("vm-web01-nic"))["count"] == 6)
    check("filter by port inside NAT range", sorted(p["path"] for p in G.ingress_paths(g, port=50150)["paths"])
          == ["load_balancer", "public_ip_on_nic"])
    print("v0.3.3: evaluators found missing by the live scan")
    acc3 = lambda name: node(name)["props"].get("access") or {}
    exp3 = {"disk-sas": "all_networks", "disk-priv": "disabled", "disk-nopol": "unknown", "pv-open": "all_networks",
            "pv-ns": "unknown", "aa-open": "all_networks", "aa-closed": "disabled", "cae-ext": "decided_per_app",
            "cae-int": "vnet_injected", "ca-open": "all_networks", "ca-allow": "restricted", "ca-on-internal": "disabled",
            "ca-noingress": "no_inbound_endpoint", "ca-mixed": "unknown", "la-http": "all_networks", "la-ip": "restricted",
            "la-onlyla": "restricted", "la-recur": "no_inbound_endpoint", "la-sync": "unknown",
            "la-webhook": "all_networks", "la-notrig": "no_inbound_endpoint", "law-ing": "all_networks",
            "law-closed": "disabled", "ai-query": "all_networks", "dce-open": "all_networks", "dce-amp": "perimeter_controlled",
            "aks-unset": "all_networks", "aks-false": "all_networks"}
    got3 = {k: acc3(k).get("public_endpoint") for k in exp3}
    check("28 new verdicts exactly as expected", got3 == exp3, {k: (got3[k], v) for k, v in exp3.items() if got3[k] != v})
    check("disk: live export SAS is verdict evidence", any("ActiveSAS" in b for b in acc3("disk-sas")["because"])
          and acc3("disk-sas")["network"]["active_export_sas"] is True)
    check("disk: missing policy -> unknown, not assumed", acc3("disk-nopol")["unknown"][0]["field"] == "networkAccessPolicy")
    check("automation: boolean true understood", acc3("aa-open")["because"][0] == "publicNetworkAccess = true (boolean)")
    check("ACA: internal environment overrides external ingress",
          any("overrides external ingress" in b for b in acc3("ca-on-internal")["because"]))
    check("ACA: app hosted on env + env in subnet", edges("ca-open", "cae-ext", "HOSTED_ON") and edges("cae-int", "data", "IN_SUBNET"))
    check("ACA: no helper keys leak into saved profile", not any("_needs_env" in (n["props"].get("access") or {})
                                                                 for n in g.nodes.values()))
    check("Logic App: empty allow list = only other Logic Apps", "only other Logic Apps" in acc3("la-onlyla")["because"][0])
    check("Logic App: webhook trigger counts as inbound, type cited",
          acc3("la-webhook")["public_endpoint"] == "all_networks" and "(ApiConnectionWebhook)" in acc3("la-webhook")["because"][0])
    check("Logic App: no triggers vs non-inbound triggers worded exactly",
          acc3("la-notrig")["because"][0] == "definition has no triggers"
          and acc3("la-recur")["because"][0] == "triggers: r (Recurrence); none receive inbound calls")
    check("Logic App: disabled state noted, not used as verdict", any("Disabled" in x for x in acc3("la-onlyla")["notes"]))
    check("Log Analytics: both endpoints cited", acc3("law-ing")["because"][0] ==
          "publicNetworkAccessForIngestion = Enabled, publicNetworkAccessForQuery = Disabled")
    check("AKS: unset vs false worded differently", acc3("aks-unset")["because"][0].startswith("enablePrivateCluster unset")
          and acc3("aks-false")["because"][0].startswith("enablePrivateCluster = false"))
    import random
    sig3 = lambda gr: (sorted((n["id"], n["kind"], n["in_scan"], (n["props"].get("access") or {}).get("public_endpoint") or "")
                              for n in gr.nodes.values()),
                       sorted((e["src"], e["dst"], e["rel"], e.get("uniq") or "") for e in gr.edges))
    base3, same3 = sig3(G.build_graph(fixture_v3())), True
    for seed in range(5):
        raw3 = fixture_v3()
        random.Random(seed).shuffle(raw3["resources"])
        same3 &= sig3(G.build_graph(raw3)) == base3
    check("full v0.3 estate: 5 shuffled orders -> identical nodes, verdicts, edges", same3)
    sm = G.summary(g)
    check("summary ingress = exactly what ingress_paths returns",
          sm["internet_ingress_paths"] == dict(Counter(p["path"] for p in G.ingress_paths(g)["paths"]))
          == {"app_gateway": 4, "firewall_dnat": 3, "load_balancer": 6, "public_ip_on_nic": 1}, sm["internet_ingress_paths"])
    check("summary outside_scan broken down by kind, not called cross-subscription",
          "external_references" not in sm and {"internet", "ip", "managementgroup"} <= set(sm["outside_scan"]) and "fqdn" not in sm["outside_scan"]
          and "not a count of cross-subscription" in sm["outside_scan_note"], sm["outside_scan"])
    _, g3 = store.load()
    check("v3 reload: IPs and FQDNs re-indexed", g3.resolve("10.0.1.5")[0]["name"] == "fw-legacy"
          and g3.by_fqdn.get("web-app01.azurewebsites.net"))
    html2 = render_html(g3)

    print("mcp tools (in-process)")

    async def mcp_checks():
        from .server import mcp
        from . import server
        server._cache.clear()
        tools = {t.name for t in await mcp.list_tools()}
        check("16 tools registered", tools == {"scan_infrastructure", "infra_summary", "find_resource", "get_node",
                                               "nsg_rules_for", "search_nsg_rules", "export_map", "get_access",
                                               "list_public_exposure", "who_has_access", "identity_permissions",
                                               "firewall_rules", "search_firewall_rules", "ingress_paths", "route_for",
                                               "hybrid_connectivity"}, tools)
        res = await mcp.call_tool("ingress_paths", {"target": "fw-hub"})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("call_tool ingress_paths via firewall", payload["count"] == 2, payload)
        res = await mcp.call_tool("find_resource", {"query": "192.168.1.1"})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("call_tool find_resource on-prem IP", payload["ranges_containing_ip"][0]["name"] == "lng-dc1", payload)
        res = await mcp.call_tool("get_access", {"target": "sql-prod"})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("call_tool get_access", payload["access"]["public_endpoint"] == "restricted", payload)
        res = await mcp.call_tool("who_has_access", {"target": "stdata01"})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("call_tool who_has_access", any(a["role"] == "Storage Blob Data Reader" and a["principal"]["name"] == "web-app01"
                                               for a in payload["role_assignments"]), payload)
        res = await mcp.call_tool("search_nsg_rules", {"port": 3389, "source": "internet", "access": "Allow"})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("call_tool search_nsg_rules", payload["match_count"] == 1, payload)
        with open(payload_path := os.path.join(os.environ["NEUROMAP_HOME"], "maps", "v2.html"), "w", encoding="utf-8") as f:
            f.write(html2)
        from .fixture_v2 import fixture_v2 as fx2
        server._cache.clear()
        r1 = await mcp.call_tool("infra_summary", {})
        before = (r1.structured_content or json.loads(r1.content[0].text))["counts"].get("containerapp", 0)
        store.save(fx2())  # a new scan lands while the server is running
        r2 = await mcp.call_tool("infra_summary", {})
        after = (r2.structured_content or json.loads(r2.content[0].text))["counts"].get("containerapp", 0)
        check("server picks up a newer snapshot without restart", before > 0 and after == 0, (before, after))
        res = await mcp.call_tool("export_map", {})
        payload = res.structured_content or json.loads(res.content[0].text)
        check("export_map writes file", os.path.exists(payload["path"]), payload)

    asyncio.run(mcp_checks())
    print(f"\n{ok} passed, {fail} failed  (NEUROMAP_HOME={tmp})")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(run())
