# Azure NeuroMap MCP

[![ci](https://github.com/KanenasCS/azure-neuromap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/KanenasCS/azure-neuromap-mcp/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**A read-only MCP server that maps your Azure estate as a graph and tells you, precisely and
with evidence, what is exposed, how it is connected, and who can access it.**

Every answer cites the exact Azure fields it came from. If something cannot be read, it says
*unknown* and why. It never guesses. See the [demo map](docs/demo-map.html) (synthetic data).

A read-only MCP server that scans Azure and turns **every resource** into a connected graph:
networking (VNets, subnets, NSGs and every rule, NICs, IPs, peerings, routes, gateways,
firewalls), data and PaaS (SQL, Managed Instance, PostgreSQL, MySQL, Cosmos DB, Storage,
Key Vault, App Service and Functions, AKS, ACR, Redis, Service Bus, Event Hubs, AI services,
Search), edge devices (Azure Firewall and policies, Load Balancer, Application Gateway and WAF,
VPN / ExpressRoute), managed identities and **Azure RBAC**. For each resource it states its network
access and auth settings precisely, with the source of every fact.

## Precision contract

1. Every fact records its source: `arg` (Resource Graph) or `arm <api-version>` (direct GET).
2. Every verdict lists the exact fields and values it was derived from (`because`).
3. Missing or unreadable data gives `unknown` with the reason (for example `ARM read failed (HTTP 403)`).
4. Where Azure documents what an unset field means (Key Vault without `networkAcls` allows all
   networks, SQL with no firewall rules denies all), that rule is applied and written into `because`.
5. Nothing is inferred from names, tags, naming conventions or connection strings.
6. No secrets are read: no `listKeys`, no app settings, no connection strings. Only GET and Resource Graph.
7. Rules are shown even when they do not apply. A resource with public access disabled still lists
   its firewall, IP and VNet rules, marked `rules_in_effect: false`, because they come back the moment
   access is re-enabled. No allow edges are drawn for them.
8. A "disable" flag that is not set is reported as not disabled (for example `local_auth_disabled`),
   with the reason in `notes`.

## How it works

```
Azure Resource Graph (1 KQL query, paged)  ->  raw snapshot  ->  graph builder  ->  MCP tools
                                                   |                   |
                                           ~/.neuromap/snapshots     HTML "neurosystem" map
```

Only two Azure calls exist, both read-only: list subscriptions, and query Resource Graph.
The raw snapshot is kept so later phases can re-derive new views without re-scanning.

## Install

**Windows** (use one fixed path, so the AI client config never changes on upgrade):

```powershell
python -m venv C:\Tools\neuromap\.venv
C:\Tools\neuromap\.venv\Scripts\python.exe -m pip install git+https://github.com/KanenasCS/azure-neuromap-mcp
C:\Tools\neuromap\.venv\Scripts\neuromap.exe selftest      # offline, no Azure needed
```

**Linux / macOS:**

```bash
python3 -m venv ~/.neuromap-venv
~/.neuromap-venv/bin/pip install git+https://github.com/KanenasCS/azure-neuromap-mcp
~/.neuromap-venv/bin/neuromap selftest
```

## First scan

```bash
az login --tenant <tenant-id>                 # or managed identity / AZURE_* env vars
neuromap scan -s <subscription-id>            # read-only; prints a summary
neuromap map                                  # offline HTML map, prints the path
neuromap rebuild                              # re-derive the graph from the saved scan (no Azure calls)
```

Permission needed: **Reader** on the subscriptions you scan. In the summary check
`enrichment_error_count: 0` and `collection_errors: []`.

## Connect an AI client

**Claude Desktop.** Add to `claude_desktop_config.json`:

```json
{ "mcpServers": { "azure-neuromap": {
    "command": "C:\\Tools\\neuromap\\.venv\\Scripts\\neuromap-mcp.exe" } } }
```

On Windows the Claude Desktop installer is an MSIX package, and the file it reads is
`%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json`
(not only `%APPDATA%\Claude\...`). Quit Claude Desktop from the tray before editing, and
check Settings > Developer shows the server as running.

**VS Code** (`.vscode/mcp.json`):

```json
{ "servers": { "azure-neuromap": { "type": "stdio",
  "command": "C:\\Tools\\neuromap\\.venv\\Scripts\\neuromap-mcp.exe" } } }
```

## Upgrade

Quit the AI client first (Windows cannot replace a running `.exe`), then:

```powershell
C:\Tools\neuromap\.venv\Scripts\python.exe -m pip install --upgrade --no-deps --force-reinstall git+https://github.com/KanenasCS/azure-neuromap-mcp
```

Saved graphs from an older version are rebuilt from the raw scan automatically.

## Tools

| Tool | What it answers |
|---|---|
| `scan_infrastructure` | Scan now: all resources, RGs, RBAC, access settings (`enrich=false` skips ARM child reads) |
| `infra_summary` | Counts by kind, public-endpoint states, RBAC status, enrichment errors |
| `find_resource` | Name, partial name, resource ID or IP to node, plus the subnet that contains an IP |
| `get_node` | One resource plus everything linked to it (depth 1 to 3) |
| `get_access` | Public-endpoint verdict, `because`, rules, allowed IPs/subnets, private endpoints, auth, TLS, sources, unknowns |
| `list_public_exposure` | Resources by verdict (default: open to all networks) |
| `who_has_access` | RBAC role assignments applying to a resource, direct and inherited (resource, RG, subscription, management groups, root), per-scope coverage (uncollected = unknown, never zero), capabilities from each role's actions/notActions (assign roles, write, delete), plus data-plane auth |
| `identity_permissions` | Roles held by a resource's system and user-assigned identities |
| `firewall_rules` | Azure Firewall or policy rules in processing order, parent policy inheritance, IP groups expanded, threat intel / IDPS / DNS proxy |
| `search_firewall_rules` | Search all firewalls by port, source, destination, FQDN (wildcards), action, rule type |
| `ingress_paths` | Every declared way in: firewall DNAT, public LB rules and NAT rules, App Gateway routes with effective WAF, public IPs on NICs |
| `route_for` | UDRs for a subnet/NIC/VM/VMSS with each next hop resolved to the resource that owns the IP |
| `hybrid_connectivity` | VPN/ER gateways, connections and status, on-prem ranges, ER peerings, P2S pools, spokes using the gateway |
| `nsg_rules_for` | NSG layers on a VM/NIC/PE/public IP/subnet (or the subnet of AKS, MI, ...) in evaluation order |
| `search_nsg_rules` | Estate-wide NSG rule search, e.g. port 3389 + source `internet` + Allow |
| `export_map` | Writes the offline interactive map and returns the path |

Prompts: `map_my_infra`, `explain_resource`, `access_review`, `internet_ingress_review`. Resource: `neuromap://summary`.

## Access verdicts

`public_endpoint` is one of `disabled`, `vnet_injected`, `restricted`, `all_networks`,
`all_networks_with_denies`, `enabled_no_allow_rules`, `gated_by_nsg`, `perimeter_controlled`,
`no_inbound_endpoint`, `decided_per_app`, `unknown`, `not_evaluated`.

| Type | Fields evaluated | Extra ARM reads |
|---|---|---|
| Storage | publicNetworkAccess, networkAcls (default action, IP, VNet, resource rules, bypass), shared key, blob public access, TLS | none |
| Key Vault | publicNetworkAccess, networkAcls, RBAC mode, access policies | none |
| SQL server | publicNetworkAccess, firewall rules (union checked for full IPv4), 0.0.0.0 Azure rule, VNet rules (shown but marked not in effect when public access is disabled), Entra admin and Entra-only from their own child resources, TLS | server, firewallRules, virtualNetworkRules, administrators, azureADOnlyAuthentications (2021-11-01) |
| SQL Managed Instance | publicDataEndpointEnabled, subnet, proxy, Entra-only, TLS | none |
| PostgreSQL / MySQL flexible | delegated subnet, publicNetworkAccess, firewall rules, Entra/password auth | firewallRules (2022-12-01 / 2021-05-01) |
| Cosmos DB | publicNetworkAccess, IP rules, VNet filter and rules, bypass, local auth, TLS | none |
| App Service / Functions | publicNetworkAccess, access restrictions (first-match, default action), SCM site, VNet integration, FTP/SCM basic auth, TLS, FTPS | config/web, basicPublishingCredentialsPolicies (2023-01-01) |
| AKS | private cluster, authorized IP ranges, node subnets, Entra/Azure RBAC, local accounts, network plugin/policy | none |
| ACR | publicNetworkAccess, network rule set, SKU rule, admin user, anonymous pull | none |
| Redis | publicNetworkAccess, VNet injection, firewall rules, access-key auth, non-SSL port, TLS | firewallRules (2022-06-01) |
| Service Bus / Event Hubs | publicNetworkAccess, network rule set, trusted services, local auth, TLS | networkRuleSets/default (2021-11-01) |
| AI services / OpenAI | publicNetworkAccess, networkAcls, local auth, outbound restriction | none |
| AI Search | publicNetworkAccess, IP rules, local auth | none |
| Managed disks | publicNetworkAccess, networkAccessPolicy (AllowAll / AllowPrivate / DenyAll), disk access, live export SAS (`diskState = ActiveSAS`), data access auth mode. Scope is export/import through SAS URLs | none |
| Container Apps | Environment internal/external (internal overrides any app's external ingress), infrastructure subnet, app ingress external, IP restrictions (all-Allow or all-Deny semantics), insecure HTTP, client certs | none |
| Logic Apps (Consumption) | Inbound triggers in the definition (Request, ApiConnectionWebhook, HttpWebhook), with trigger types cited, accessControl.triggers.allowedCallerIpAddresses (`[]` = only other Logic Apps), OAuth policies, workflow state | none |
| Log Analytics / App Insights | publicNetworkAccessForIngestion and ForQuery (verdict = most open endpoint, both cited), local auth | none |
| Data Collection Endpoints | networkAcls.publicNetworkAccess (Enabled / Disabled / SecuredByPerimeter) | none |
| Automation | publicNetworkAccess (boolean) for webhooks and Hybrid Worker endpoints, local auth | none |
| Purview | publicNetworkAccess, managed resources public access | none |
| Any other type | raw publicNetworkAccess and private endpoint connections, marked `not_evaluated` | none |

## Edge devices

| Device | What is turned into facts and edges | Extra ARM reads |
|---|---|---|
| Azure Firewall | Policy chain (base policies), rule collection groups, DNAT/network/application rules in processing order, IP groups expanded, classic rule collections, threat intel, IDPS, DNS proxy, vWAN hub IPs. DNAT rules become `DNAT_FORWARDS` edges to the translated target, and `INGRESS_ANY_SOURCE` from the Internet only when the rule accepts any source | ruleCollectionGroups (2023-09-01) |
| Load Balancer | Frontends, backend pools (NIC, VMSS and IP-based members, deduplicated when Azure lists a node twice), owning AKS cluster and its power state (from the cluster's nodeResourceGroup), LB rules (incl. HA ports, floating IP), inbound NAT rules (single port and port-range v2), outbound rules, probes. Each rule becomes `LB_FORWARDS` frontend to member; public rules whose pool is empty (for example a stopped cluster) are still listed by `ingress_paths` with 0 backend instances | none |
| Application Gateway | Listeners (port, protocol, host names), basic and path-based routing, redirects, backend pools (NIC, IP, FQDN matched to web app and Container App host names), HTTP settings, SSL policy. WAF per route, resolved in order: path rule policy, listener policy, gateway policy, legacy WAF config, and "not available" when the SKU tier is not WAF | none |
| Route tables | Each `VirtualAppliance` next hop IP resolved to the firewall, NVA NIC or internal LB that owns it (`NEXT_HOP`). Blackhole routes (`None`) flagged | none |
| VPN / ExpressRoute | Gateway type, SKU, active-active, BGP, point-to-site pool and auth, S2S / VNet-to-VNet / ER connections with status and BGP, local network gateway on-prem ranges, ER circuit provider and peerings, spokes that use the gateway through peering | none |
| VM Scale Sets | Subnet, NIC-configuration NSG, LB and App Gateway pool membership, instance public IPs flag | none |

Anything referenced but not owned by a scanned resource becomes an explicit node such as
`ip:10.9.9.9` or `fqdn:api.example.com`, marked outside scan, never matched by guesswork.
Connection shared keys and certificates are never read.

A verdict describes the resource's own network layer. It does not claim a given client can
connect end to end, because client-side DNS, routes, NSGs and firewalls are separate layers.

## Relationship types

Network: `CONTAINS` `IN_SUBNET` `PROTECTED_BY` `HAS_NIC` `HAS_PUBLIC_IP` `PEERED_WITH`
`ROUTES_VIA` `EGRESS_VIA` `CONNECTS_TO` `MEMBER_OF` `BALANCES_TO` `USES_POLICY`

Access: `OPEN_TO_ALL_NETWORKS` (Internet node to resource), `IP_RULE_ALLOWS` (a scanned public IP
is inside an allow rule), `VNET_RULE_ALLOWS` (subnet allowed by a VNet rule). Allow edges are
drawn only for `restricted` resources, where they actually change who can connect.

Platform and identity: `VNET_INTEGRATION` `HOSTED_ON` `USES_IDENTITY` `MANAGED_BY` `HAS_ROLE`
(one edge per role assignment).

Edge: `DNAT_FORWARDS` `LB_FORWARDS` `APPGW_ROUTES` `NEXT_HOP` `HYBRID_CONNECTION`
`INGRESS_ANY_SOURCE` `INHERITS_FROM` `USES_IP_GROUP` `ATTACHED_TO` `IN_HUB`

Generic: `REFERENCES` for any other resource ID written in a resource's properties, with the
exact property path (for example `properties.parameters.$connections.value.sql.connectionId`).

## Data handling

Snapshots and maps describe your network in detail. They live in `~/.neuromap`
(change with `NEUROMAP_HOME`). Treat that folder as sensitive and do not commit it.
The map HTML embeds Cytoscape.js (MIT, see `static/cytoscape.LICENSE`) and makes no
network calls.

## Known limits

- RBAC: assignments above the subscription are read with `roleAssignments?$filter=atScope()` (Reader is enough); if that call fails, those scopes are reported as not collected. Active assignments only. Deny assignments, PIM eligible roles and group membership are not
  expanded, and users/groups/service principals are shown by object ID (no Microsoft Graph calls).
- Networking is declared configuration. Service tags and ASG membership are not expanded, and
  routes and firewalls are not evaluated for end-to-end reachability.
- Not evaluated yet: Azure-computed effective routes and system/BGP routes (needs the
  effectiveRouteTable action, which Reader cannot call), NSG flow logs, Front Door, Traffic Manager,
  Virtual WAN routing intent, App Gateway rewrite rules and per-URI WAF policies on path maps
  beyond the path rule level.
- ARM enrichment makes a few GETs per SQL server, web app, flexible server, Redis cache and
  Service Bus/Event Hubs namespace. Failures become `unknown`, never guesses.
- Map rendering takes around 15 seconds at 8,000+ nodes. Use the legend to hide noisy kinds.
- **Validation.** 151 offline checks (synthetic fixtures shaped like Resource Graph and ARM responses,
  a mocked Azure API for the collector, and order-independence tests) run on Linux and Windows,
  Python 3.10 to 3.14. Every evaluator was also compared field by field with the Azure CLI on a live
  estate of 100+ resources; the fixes that produced are in [CHANGELOG.md](CHANGELOG.md).

## Roadmap

- **Phase 2, security overlay:** Defender for Cloud plan coverage and recommendations,
  DDoS, WAF mode, NSG flow logs, diagnostic settings, per node.
- **Phase 3, reasoning:** chain the declared layers (DNAT or LB, then UDR, then firewall rule,
  then NSG) into end-to-end path verdicts, blast radius, and snapshot diffs ("what changed since last week").

## Security and contributing

Read [SECURITY.md](SECURITY.md) before your first scan. Scans describe your environment in
detail and must never be shared. Contributions follow the precision contract in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Cytoscape.js is vendored under its own MIT license (`src/neuromap/static/cytoscape.LICENSE`).
