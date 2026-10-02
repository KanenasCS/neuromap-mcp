# Changelog

All fixes from 0.3.1 onward were found by validating against a live Azure estate
(100+ resources, 30+ types) and comparing every result with the Azure CLI / ARM.

## 0.3.8
- Rules are always recorded; any disabled-type verdict marks them `rules_in_effect: false` (7 evaluators).
- Private endpoints known only from the endpoint's side are listed on the target.
- Unset "disable" flags (e.g. `disableLocalAuth`) reported as *not disabled*, with the reason.
- Server instructions: general Azure knowledge must be labelled as such, never as a scan finding.

## 0.3.7
- RBAC above the subscription (management groups, root) via `roleAssignments?$filter=atScope()`.
- Per-scope coverage: an uncollected scope is *unknown*, never zero.
- Capabilities per assignment from role actions/notActions: assign roles, write, delete.
- Graphs built by another version are rebuilt automatically; the server reloads newer scans.

## 0.3.6
- Ingress devices identified by resource id (names repeat, e.g. every AKS LB is `kubernetes`).
- `owning_aks` on every load balancer path.

## 0.3.5
- Public LB rules with empty backend pools (stopped AKS clusters) listed as declared entry points.
- LB pool members deduplicated (Azure lists nodes twice).
- LB to AKS ownership from the cluster's declared `nodeResourceGroup`.
- Container Apps ingress FQDNs indexed; SQL empty Entra-only list stated explicitly.

## 0.3.4
- SQL: firewall/VNet rules shown when public access is disabled; Entra admin and Entra-only
  read from their own child resources.
- Logic Apps: webhook triggers count as inbound; trigger types cited.
- Summary: precise `internet_ingress_paths` and `outside_scan` fields.

## 0.3.3
- Evaluators for managed disks (export SAS), Container Apps, Logic Apps, Log Analytics,
  Application Insights, Data Collection Endpoints, Automation and Purview.

## 0.3.2
- Placeholder nodes promoted when declared later (processing-order bug); order-independence tests.
- `because` holds verdict evidence only; defaults applied to other facts go to `notes`.
- `neuromap rebuild`.

## 0.3.1
- Windows: explicit UTF-8 everywhere.

## 0.3.0
- Azure Firewall (policy inheritance, IP groups, DNAT), Load Balancer, Application Gateway + WAF,
  route next hops, VPN / ExpressRoute, VM Scale Sets. `ingress_paths`.

## 0.2.0
- All resource types, RBAC, access evaluators with sourced verdicts, ARM enrichment.

## 0.1.0
- Network graph (VNets, subnets, NSGs, NICs, IPs), MCP server, offline map.
