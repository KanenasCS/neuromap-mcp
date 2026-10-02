"""Azure NeuroMap MCP server (mcp v2 SDK, MCPServer API).

Every Azure call is read-only (Resource Graph + subscription list).
The only thing written is the local snapshot/map folder (NEUROMAP_HOME).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import anyio
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from . import graph as G
from . import store
from .visualize import render_html

INSTRUCTIONS = """Azure NeuroMap builds a graph of the user's Azure network: subscriptions,
VNets, subnets, NSGs and their rules, NICs, VMs, public IPs, route tables, private
endpoints, load balancers, gateways, firewalls, bastions, NAT gateways and ASGs.

Workflow: call infra_summary first. If there is no snapshot or it is stale, call
scan_infrastructure. Use find_resource to turn a name or IP into a node id, get_node
to walk relationships, nsg_rules_for to see the NSG layers on a VM/NIC/IP/subnet, and
search_nsg_rules to answer questions like "what allows 3389 from the Internet".

Resource access: get_access gives a resource's public-endpoint verdict (disabled, restricted,
all_networks, ...) with the exact fields it came from, plus auth and TLS facts.
list_public_exposure lists resources by verdict. who_has_access lists Azure RBAC role
assignments that apply to a resource (direct and inherited). identity_permissions lists
what a resource's managed identities can do.

Edge devices: firewall_rules shows an Azure Firewall's (or policy's) rules in processing
order with parent-policy inheritance and IP groups expanded. search_firewall_rules searches
them. ingress_paths lists every declared way in from the internet: firewall DNAT, public load
balancer rules and NAT rules, App Gateway listeners (with the effective WAF mode per route),
and public IPs directly on NICs. route_for shows a resource's UDRs with each next hop resolved
to the resource that owns that IP. hybrid_connectivity lists VPN/ExpressRoute gateways,
connections, on-prem ranges, point-to-site pools and which spokes use each gateway.

Precision rules: quote the `because` and `sources` fields when you state a conclusion.
Do not infer from counts (e.g. "4 flow logs" does not mean "on 4 watchers"), from names
(e.g. "probably left over", "looks like a test"), or from what a field name seems to mean:
use the tool's own note fields (outside_scan_note, internet_ingress_paths_note, notes).
Keep facts and suggestions apart: label any recommendation as a suggestion.
Anything not taken from tool output (general Azure behaviour, SKU capabilities, failover,
defaults) must be labelled "general Azure knowledge, not from this scan", never presented
as a finding.
If a value is unknown, say it is unknown and why. Never infer access from resource names,
tags or naming conventions. Do not claim end-to-end reachability: client-side DNS, routes,
NSGs and firewalls are separate layers."""

mcp = MCPServer(name="azure-neuromap", title="Azure NeuroMap", version="0.3.8",
                instructions=INSTRUCTIONS)

AZURE_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                             idempotent_hint=True, open_world_hint=True)
LOCAL_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                             idempotent_hint=True, open_world_hint=False)

_cache: dict = {}


def _graph() -> G.InfraGraph:
    """Serve the latest graph. Reload when a newer scan or a rebuild has been written since the
    last call, so the server never answers from stale data."""
    stamp = store.latest_stamp()
    key = (stamp, store.graph_mtime(stamp))
    if _cache.get("key") != key or "g" not in _cache:
        loaded = store.load()
        if not loaded:
            raise ValueError("No snapshot yet. Run scan_infrastructure first.")
        _cache["stamp"], _cache["g"] = loaded
        _cache["key"] = (loaded[0], store.graph_mtime(loaded[0]))
    return _cache["g"]


def _one(ref: str) -> dict:
    g = _graph()
    hits = g.resolve(ref, limit=10)
    if not hits:
        raise ValueError(f"Nothing matches '{ref}'. Try find_resource with a partial name.")
    if len(hits) > 1:
        raise ValueError("Ambiguous, pass one of these ids: " +
                         json.dumps([G.brief(h) for h in hits]))
    return hits[0]


@mcp.tool(annotations=AZURE_READ)
async def scan_infrastructure(subscription_ids: list[str] | None = None, enrich: bool = True) -> dict:
    """Scan Azure (read-only) and rebuild the graph: every resource, resource groups, RBAC role
    assignments, and access settings.

    Uses DefaultAzureCredential (az login, managed identity, env vars). Needs Reader.
    subscription_ids: limit the scan; omit to scan every enabled subscription visible.
    enrich: also read child settings Resource Graph lacks (SQL/PostgreSQL/MySQL/Redis firewall
    rules, App Service access restrictions, Service Bus/Event Hubs network rules). Without it
    those verdicts are 'unknown'.
    """
    from .collector import AzureCollector

    def run():
        raw = AzureCollector().collect(subscription_ids, enrich=enrich)
        return store.save(raw)

    stamp, g = await anyio.to_thread.run_sync(run)
    _cache.update(stamp=stamp, g=g, key=(stamp, store.graph_mtime(stamp)))
    return {"snapshot": stamp, **G.summary(g)}


@mcp.tool(annotations=LOCAL_READ)
def infra_summary() -> dict:
    """Counts by resource kind and relationship, scan time, subscriptions, unattached NSGs and public IPs."""
    g = _graph()
    return {"snapshot": _cache["stamp"], "snapshots_available": store.list_snapshots(), **G.summary(g)}


@mcp.tool(annotations=LOCAL_READ)
def find_resource(query: str, kind: str | None = None, limit: int = 20) -> dict:
    """Find nodes by full resource id, IP address (private or public), exact or partial name.

    kind filters results: network kinds (vnet, subnet, nsg, nic, vm, vmss, pip, pe, lb, appgw, firewall,
    fwpolicy, wafpolicy, ipgroup, vnetgw, lng, ercircuit, gwconnection, ...), data/PaaS kinds (storage, keyvault, sql-server, sql-db, sql-mi, postgres, mysql, cosmos,
    webapp, aks, acr, redis, servicebus, eventhub, cognitive, search, uami), or the short type of any
    other resource (e.g. 'logic/workflows'). For an IP, declared ranges containing it are also returned
    (subnets, on-premises ranges from local network gateways, point-to-site pools).
    """
    g = _graph()
    hits = g.resolve(query, limit=500)
    if kind:
        hits = [h for h in hits if h["kind"] == kind.lower()]
    res = {"matches": [G.brief(h) for h in hits[:limit]], "truncated": len(hits) > limit}
    containing = g.containing_ranges(query)
    if containing:
        res["ranges_containing_ip"] = [G.brief(h["node"]) | {"range": h["range"], "what": h["what"]}
                                       for h in containing]
    return res


@mcp.tool(annotations=LOCAL_READ)
def get_node(ref: str, depth: int = 1) -> dict:
    """Full detail of one node plus everything linked to it, up to depth 3.

    ref: resource id, IP or unique name. Relationships include CONTAINS, IN_SUBNET,
    PROTECTED_BY, HAS_NIC, HAS_PUBLIC_IP, PEERED_WITH, ROUTES_VIA, EGRESS_VIA,
    CONNECTS_TO, MEMBER_OF, BALANCES_TO, USES_POLICY, VNET_INTEGRATION, HOSTED_ON, USES_IDENTITY,
    MANAGED_BY, HAS_ROLE, OPEN_TO_ALL_NETWORKS, VNET_RULE_ALLOWS, IP_RULE_ALLOWS, and REFERENCES
    (any other ARM id found in properties, with its exact property path).
    """
    return G.node_view(_graph(), _one(ref), depth)


@mcp.tool(annotations=LOCAL_READ)
def nsg_rules_for(target: str) -> dict:
    """Every NSG layer on a VM, NIC, private endpoint, public IP or subnet, in Azure evaluation order.

    Inbound shows subnet NSG then NIC NSG. Outbound shows NIC NSG then subnet NSG.
    Rules are sorted by priority, default rules included.
    """
    return G.nsg_layers(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def search_nsg_rules(port: int | None = None, source: str | None = None,
                     destination: str | None = None, access: str | None = None,
                     direction: str | None = None, protocol: str | None = None,
                     include_default: bool = False, limit: int = 200) -> dict:
    """Search NSG rules across the whole estate, with what each NSG is attached to.

    port: destination port, matched against single ports, ranges and '*'.
    source/destination: a CIDR or IP (overlap match), a service tag like 'VirtualNetwork',
      or 'internet' to match Internet, *, 0.0.0.0/0 and ::/0.
    access: Allow or Deny. direction: Inbound or Outbound. protocol: Tcp, Udp, Icmp.
    """
    return G.search_rules(_graph(), port, source, destination, access, direction,
                          protocol, include_default, limit)


@mcp.tool(annotations=LOCAL_READ)
def get_access(target: str) -> dict:
    """Network access verdict for one resource (SQL, Storage, Key Vault, Cosmos, App Service,
    AKS, ACR, Redis, PostgreSQL, MySQL, Service Bus, Event Hubs, AI services, Search, ...).

    Returns public_endpoint (disabled | vnet_injected | restricted | all_networks | ...),
    `because` (exact fields used), network rules, allowed IPs/subnets, private endpoints,
    auth settings (Entra-only, local auth, shared key), TLS, per-fact sources, and unknowns.
    """
    return G.access_view(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def list_public_exposure(states: list[str] | None = None, kind: str | None = None, limit: int = 300) -> dict:
    """List resources by public-endpoint verdict. Default: all_networks and all_networks_with_denies.

    states: any of disabled, vnet_injected, restricted, all_networks, all_networks_with_denies,
    enabled_no_allow_rules, gated_by_nsg, perimeter_controlled, no_inbound_endpoint, decided_per_app,
    unknown, not_evaluated.
    kind: e.g. storage, keyvault, sql-server, webapp, cosmos, aks, acr, redis, disk, containerapp,
    aca-env, logicapp, loganalytics, appinsights, dce, automation, purview.
    """
    return G.exposure_list(_graph(), states, kind, limit)


@mcp.tool(annotations=LOCAL_READ)
def who_has_access(target: str) -> dict:
    """Active Azure RBAC role assignments that apply to a resource: on the resource, its parent
    resources, its resource group, subscription, management groups and root, marked inherited or
    direct. scope_coverage says per scope whether assignments were collected (a scope that was not
    collected is unknown, never zero). Each assignment has capabilities computed from the role
    definition's actions/notActions: assign_roles, write_resource, delete_resource. Also returns
    data-plane auth facts (Key Vault access policies, SQL Entra admin, ...)."""
    return G.who_has_access(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def identity_permissions(target: str) -> dict:
    """What a resource's system-assigned and user-assigned managed identities hold: roles and scopes."""
    return G.identity_permissions(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def firewall_rules(target: str) -> dict:
    """Azure Firewall (or Firewall Policy) rules in processing order: DNAT, network, application.
    Parent-policy rule collection groups come first. IP groups are expanded. Includes threat intel,
    IDPS and DNS proxy settings, and classic (non-policy) rules. Missing policy data is listed as unknown."""
    return G.firewall_view(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def search_firewall_rules(port: int | None = None, source: str | None = None, destination: str | None = None,
                          fqdn: str | None = None, action: str | None = None, rule_type: str | None = None,
                          limit: int = 200) -> dict:
    """Search every firewall's effective rules.

    port: destination port (ranges and '*' match). source/destination: IP, CIDR, service tag or
    'internet' (matches *, 0.0.0.0/0). fqdn: matched against target FQDN patterns (wildcards honored).
    action: Allow, Deny or DNAT. rule_type: dnat, network or application.
    """
    return G.search_firewall_rules(_graph(), port, source, destination, fqdn, action, rule_type, limit)


@mcp.tool(annotations=LOCAL_READ)
def ingress_paths(target: str | None = None, port: int | None = None, include_private: bool = False) -> dict:
    """Every declared ingress path: firewall DNAT (with allowed sources), public load balancer rules and
    inbound NAT rules, App Gateway listener -> backend routes (with effective WAF mode), and public IPs
    attached directly to NICs.

    target: limit to paths into or through one resource (VM, NIC, firewall, LB, App Gateway, IP).
    port: limit to a frontend port. include_private: also show internal LB / private App Gateway listeners.
    """
    g = _graph()
    return G.ingress_paths(g, _one(target) if target else None, port, include_private)


@mcp.tool(annotations=LOCAL_READ)
def route_for(target: str) -> dict:
    """User-defined routes that apply to a subnet, NIC, VM, VMSS or subnet-injected service, with each
    VirtualAppliance next hop resolved to the resource that owns that IP (firewall, NVA, internal LB),
    or to an explicit 'ip:x' node when no scanned resource owns it."""
    return G.route_view(_graph(), _one(target))


@mcp.tool(annotations=LOCAL_READ)
def hybrid_connectivity() -> dict:
    """VPN and ExpressRoute: each gateway with its VNet, SKU, BGP and point-to-site settings, its
    connections (type, status, BGP) and remote side (on-prem ranges, gateway IP, ER peerings), and
    the spoke VNets that use it through peering."""
    return G.hybrid_view(_graph())


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                      idempotent_hint=False, open_world_hint=False))
def export_map() -> dict:
    """Write the interactive offline 'neurosystem' HTML map of the current snapshot and return its path."""
    g = _graph()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = store.home() / "maps" / f"neuromap-{stamp}.html"
    path.write_text(render_html(g), encoding="utf-8")
    return {"path": str(path), "nodes": len(g.nodes), "edges": len(g.edges),
            "note": "This file describes your network in detail. Keep it private."}


@mcp.resource("neuromap://summary", name="summary", mime_type="application/json",
              description="Summary of the latest snapshot")
def summary_resource() -> str:
    return json.dumps(G.summary(_graph()), indent=2)


@mcp.prompt(name="map_my_infra", title="Map my Azure network")
def map_my_infra() -> str:
    return ("Check infra_summary. If there is no snapshot, run scan_infrastructure. "
            "Then describe the topology: hubs and spokes (peerings), subnets per VNet, which "
            "subnets and NICs have NSGs, what has a public IP, and anything unattached. "
            "Finish by calling export_map and give me the path.")


@mcp.prompt(name="access_review", title="Review public exposure and access")
def access_review() -> str:
    return ("Call list_public_exposure. For each resource open to all networks, call get_access and "
            "who_has_access. Report per resource: verdict with the exact `because` fields, auth settings, "
            "private endpoints, and role assignments (direct vs inherited). Then list anything 'unknown' "
            "and why. State facts only, with their sources.")


@mcp.prompt(name="internet_ingress_review", title="Review every way in from the internet")
def internet_ingress_review() -> str:
    return ("Call ingress_paths. Group the paths by entry point (firewall DNAT, load balancer, App Gateway, "
            "public IP on NIC). For each: entry IP and port, allowed sources, target, and for App Gateway the "
            "WAF mode and where it comes from. Then call list_public_exposure for PaaS open to all networks. "
            "Quote the exact rule names. Do not claim the backend is reachable end to end; say which NSG to "
            "check with nsg_rules_for.")


@mcp.prompt(name="explain_resource", title="Explain one resource's network position")
def explain_resource(target: str) -> str:
    return (f"For '{target}': use find_resource, then get_node with depth 2 and nsg_rules_for. "
            "Explain where it sits (subscription, VNet, subnet), how it reaches or is reached from "
            "outside (public IP, load balancer, peering, private endpoint), and list the inbound "
            "rules in the order Azure evaluates them.")


def main() -> None:
    mcp.run()  # stdio


if __name__ == "__main__":
    main()
