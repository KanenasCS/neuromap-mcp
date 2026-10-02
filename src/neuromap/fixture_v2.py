"""v0.2 fixture: PaaS access, enrichment results (including a failure), RBAC and containers.

Each resource targets one evaluator rule so the selftest can check it exactly.
"""
from __future__ import annotations

from .selftest import SUB, fixture

N = "Microsoft.Network"
RGS = {"rg-net": f"/subscriptions/{SUB}/resourceGroups/rg-net",
       "rg-data": f"/subscriptions/{SUB}/resourceGroups/rg-data"}
SPOKE = f"{RGS['rg-net']}/providers/{N}/virtualNetworks/spoke-vnet"
WEB_SUBNET, DATA_SUBNET = f"{SPOKE}/subnets/web", f"{SPOKE}/subnets/data"
PRINCIPAL_WEB = "aaaaaaaa-0000-0000-0000-000000000001"
PRINCIPAL_UAMI = "bbbbbbbb-0000-0000-0000-000000000002"
USER, GROUP = "cccccccc-0000-0000-0000-000000000003", "dddddddd-0000-0000-0000-000000000004"
ROLE = {"contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c", "uaa": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "blobreader": "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", "kvsecrets": "4633458b-17de-408a-b874-0445c86b69e6",
        "owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "unknown": "99999999-9999-9999-9999-999999999999"}


def rid(rg: str, rtype: str, name: str) -> str:
    return f"{RGS[rg]}/providers/{rtype}/{name}"


def res(rg, rtype, name, props, sku=None, identity=None, kind=None):
    return {"id": rid(rg, rtype, name), "name": name, "type": rtype, "kind": kind, "location": "westeurope",
            "resourceGroup": rg, "subscriptionId": SUB, "tags": {}, "sku": sku, "identity": identity,
            "managedBy": None, "properties": props}


def fw(name, start, end, redis=False):
    k = ("startIP", "endIP") if redis else ("startIpAddress", "endIpAddress")
    return {"name": name, "properties": {k[0]: start, k[1]: end}}


def ok(api, data):
    return {"api": api, "data": data}


def web_cfg(rules, **extra):
    return ok("2023-01-01", {"properties": {"ipSecurityRestrictions": rules, "minTlsVersion": "1.2",
                                            "ftpsState": "Disabled", **extra}})


ALLOW_ALL = {"name": "Allow all", "priority": 2147483647, "action": "Allow", "ipAddress": "Any"}


def fixture_v2() -> dict:
    raw = fixture()
    SQL, WEB = "Microsoft.Sql/servers", "Microsoft.Web/sites"
    uami_id = rid("rg-data", "Microsoft.ManagedIdentity/userAssignedIdentities", "uami-app")
    sql_prod = rid("rg-data", SQL, "sql-prod")
    raw["resources"] += [
        res("rg-data", "Microsoft.Storage/storageAccounts", "stdata01", {
            "networkAcls": {"defaultAction": "Deny", "bypass": "AzureServices",
                            "ipRules": [{"value": "20.50.60.70"}, {"value": "198.51.100.0/24"}],
                            "virtualNetworkRules": [{"id": WEB_SUBNET}]},
            "supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": False,
            "privateEndpointConnections": [{"properties": {
                "privateEndpoint": {"id": f"{RGS['rg-net']}/providers/{N}/privateEndpoints/pe-storage"},
                "privateLinkServiceConnectionState": {"status": "Approved"}}}]}, sku={"name": "Standard_LRS"}),
        res("rg-data", "Microsoft.KeyVault/vaults", "kv-app", {
            "publicNetworkAccess": "Enabled", "enableRbacAuthorization": False,
            "accessPolicies": [{"objectId": USER, "tenantId": "t", "permissions": {"secrets": ["get", "list"]}}]}),
        res("rg-data", SQL, "sql-prod", {"publicNetworkAccess": "Enabled"}),
        res("rg-data", f"{SQL}/databases", "sql-prod/appdb", {"status": "Online"}) | {"id": f"{sql_prod}/databases/appdb"},
        res("rg-data", SQL, "sql-open", {"publicNetworkAccess": "Enabled"}),
        res("rg-data", SQL, "sql-private", {"publicNetworkAccess": "Disabled"}),
        res("rg-data", SQL, "sql-noenrich", {"publicNetworkAccess": "Enabled"}),
        res("rg-data", "Microsoft.Web/serverfarms", "plan-1", {}),
        res("rg-data", WEB, "web-app01", {
            "httpsOnly": True, "virtualNetworkSubnetId": WEB_SUBNET,
            "serverFarmId": rid("rg-data", "Microsoft.Web/serverfarms", "plan-1")}, kind="app",
            identity={"type": "SystemAssigned, UserAssigned", "principalId": PRINCIPAL_WEB,
                      "userAssignedIdentities": {uami_id: {"principalId": PRINCIPAL_UAMI}}}),
        res("rg-data", WEB, "web-open", {"httpsOnly": False}, kind="app"),
        res("rg-data", WEB, "web-denyfirst", {}, kind="app"),
        res("rg-data", "Microsoft.DocumentDB/databaseAccounts", "cosmos-app", {
            "publicNetworkAccess": "Enabled", "ipRules": [], "isVirtualNetworkFilterEnabled": False,
            "disableLocalAuth": False}),
        res("rg-data", "Microsoft.ContainerService/managedClusters", "aks-prod", {
            "apiServerAccessProfile": {"enablePrivateCluster": True},
            "agentPoolProfiles": [{"name": "sys", "vnetSubnetID": WEB_SUBNET}],
            "aadProfile": {"managed": True, "enableAzureRBAC": True}, "disableLocalAccounts": True,
            "networkProfile": {"networkPlugin": "azure", "networkPolicy": "cilium", "outboundType": "userDefinedRouting"}}),
        res("rg-data", "Microsoft.ContainerRegistry/registries", "acrstd", {
            "adminUserEnabled": True, "publicNetworkAccess": "Enabled"}, sku={"name": "Standard"}),
        res("rg-data", "Microsoft.Cache/redis", "redis-a", {"publicNetworkAccess": "Enabled", "enableNonSslPort": False}),
        res("rg-data", "Microsoft.ServiceBus/namespaces", "sb-ns", {"disableLocalAuth": True, "minimumTlsVersion": "1.2"}),
        res("rg-data", "Microsoft.DBforPostgreSQL/flexibleServers", "pg-private", {
            "network": {"delegatedSubnetResourceId": DATA_SUBNET, "publicNetworkAccess": "Disabled"},
            "authConfig": {"activeDirectoryAuth": "Enabled", "passwordAuth": "Disabled"}}),
        res("rg-data", "Microsoft.ManagedIdentity/userAssignedIdentities", "uami-app", {"principalId": PRINCIPAL_UAMI}),
        res("rg-data", "Microsoft.Logic/workflows", "la-sync", {
            "parameters": {"$connections": {"value": {"sql": {"connectionId": sql_prod}}}}}),
        res("rg-data", "Microsoft.AppConfiguration/configurationStores", "appcs", {"publicNetworkAccess": "Enabled"}),
    ]
    L = lambda rg, t, n: rid(rg, t, n).lower()
    raw["arm"] = {
        L("rg-data", SQL, "sql-prod"): {
            "server": ok("2021-11-01", {"properties": {"publicNetworkAccess": "Enabled", "minimalTlsVersion": "1.2",
                                                       "administrators": {"azureADOnlyAuthentication": True,
                                                                          "login": "sql-admins", "principalType": "Group"}}}),
            "firewall_rules": ok("2021-11-01", [fw("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0"),
                                                fw("office", "203.0.113.10", "203.0.113.20")]),
            "vnet_rules": ok("2021-11-01", [{"name": "data", "properties": {"virtualNetworkSubnetId": DATA_SUBNET,
                                                                            "state": "Ready"}}]),
            "entra_admins": ok("2021-11-01", [{"name": "ActiveDirectory", "properties": {
                "administratorType": "ActiveDirectory", "login": "sql-admins", "sid": "g-1"}}])},
        L("rg-data", SQL, "sql-open"): {
            "server": ok("2021-11-01", {"properties": {"publicNetworkAccess": "Enabled"}}),
            "firewall_rules": ok("2021-11-01", [fw("low", "0.0.0.0", "127.255.255.255"),
                                                fw("high", "128.0.0.0", "255.255.255.255")]),
            "vnet_rules": ok("2021-11-01", [])},
        L("rg-data", SQL, "sql-private"): {
            "server": ok("2021-11-01", {"properties": {"publicNetworkAccess": "Disabled"}}),
            "firewall_rules": ok("2021-11-01", [fw("office", "203.0.113.10", "203.0.113.20")]),
            "vnet_rules": ok("2021-11-01", [{"name": "d", "properties": {"virtualNetworkSubnetId": DATA_SUBNET}}]),
            "entra_admins": ok("2021-11-01", []),
            "entra_only": ok("2021-11-01", [{"name": "Default", "properties": {"azureADOnlyAuthentication": False}}])},
        L("rg-data", WEB, "web-app01"): {
            "site_config": web_cfg([
                {"name": "office", "priority": 100, "action": "Allow", "ipAddress": "203.0.113.0/24", "tag": "Default"},
                {"name": "afd", "priority": 200, "action": "Allow", "ipAddress": "AzureFrontDoor.Backend",
                 "tag": "ServiceTag", "headers": {"x-azure-fdid": ["1111"]}},
                {"name": "Deny all", "priority": 2147483647, "action": "Deny", "ipAddress": "Any"}],
                scmIpSecurityRestrictionsUseMain=True, vnetRouteAllEnabled=True),
            "ftp_basic_auth": ok("2023-01-01", {"properties": {"allow": False}}),
            "scm_basic_auth": ok("2023-01-01", {"properties": {"allow": True}})},
        L("rg-data", WEB, "web-open"): {
            "site_config": web_cfg([ALLOW_ALL], scmIpSecurityRestrictions=[ALLOW_ALL]),
            "ftp_basic_auth": ok("2023-01-01", {"properties": {"allow": True}}),
            "scm_basic_auth": ok("2023-01-01", {"properties": {"allow": True}})},
        L("rg-data", WEB, "web-denyfirst"): {
            "site_config": web_cfg([{"name": "bad-ip", "priority": 100, "action": "Deny", "ipAddress": "192.0.2.1/32"},
                                    {"name": "any", "priority": 200, "action": "Allow", "ipAddress": "Any"}],
                                   scmIpSecurityRestrictions=[], scmIpSecurityRestrictionsDefaultAction="Deny")},
        L("rg-data", "Microsoft.Cache/redis", "redis-a"): {
            "firewall_rules": {"api": "2022-06-01", "error": "GET ... -> 403: AuthorizationFailed", "status": 403}},
        L("rg-data", "Microsoft.ServiceBus/namespaces", "sb-ns"): {
            "network_rule_set": ok("2021-11-01", {"properties": {"defaultAction": "Deny", "publicNetworkAccess": "Enabled",
                                                                 "ipRules": [], "virtualNetworkRules": []}})},
    }
    raw["schema"], raw["enriched"], raw["rbac_status"] = 2, True, "ok"
    raw["containers"] = [
        {"id": f"/subscriptions/{SUB}", "name": "sub-demo", "type": "microsoft.resources/subscriptions",
         "subscriptionId": SUB, "properties": {"managementGroupAncestorsChain": [
             {"name": "mg-prod", "displayName": "Prod"}, {"name": "tenant-root", "displayName": "Tenant Root Group"}]}},
        *[{"id": v, "name": k, "type": "microsoft.resources/subscriptions/resourcegroups", "subscriptionId": SUB,
           "location": "westeurope", "properties": {}} for k, v in RGS.items()]]

    def ra(n, principal, ptype, role, scope):
        return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/ra{n}", "properties": {
            "principalId": principal, "principalType": ptype, "scope": scope,
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLE[role]}"}}
    raw["role_assignments"] = [
        ra(1, PRINCIPAL_WEB, "ServicePrincipal", "blobreader", rid("rg-data", "Microsoft.Storage/storageAccounts", "stdata01")),
        ra(2, PRINCIPAL_UAMI, "ServicePrincipal", "kvsecrets", RGS["rg-data"]),
        ra(3, USER, "User", "owner", f"/subscriptions/{SUB}"),
        ra(4, GROUP, "Group", "reader", "/providers/Microsoft.Management/managementGroups/mg-prod"),
        ra(5, USER, "User", "unknown", rid("rg-data", "Microsoft.KeyVault/vaults", "kv-app")),
        ra(6, USER, "User", "contributor", rid("rg-data", "Microsoft.Storage/storageAccounts", "stdata01")),
        {"id": "/providers/Microsoft.Authorization/roleAssignments/ra7", "properties": {
            "principalId": GROUP, "principalType": "Group", "scope": "/",
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{ROLE['uaa']}"}},
    ]
    raw["rbac_coverage"] = {"subscription_and_below": True, "above_subscription": True}
    perm = lambda name, a=(), na=(), da=(): {"name": name, "type": "BuiltInRole", "actions": list(a),
                                             "not_actions": list(na), "data_actions": list(da), "not_data_actions": []}
    raw["role_definitions"] = {
        ROLE["blobreader"]: perm("Storage Blob Data Reader", ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                                 da=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        ROLE["kvsecrets"]: perm("Key Vault Secrets User", da=["Microsoft.KeyVault/vaults/secrets/getSecret/action"]),
        ROLE["owner"]: perm("Owner", ["*"]),
        ROLE["reader"]: perm("Reader", ["*/read"]),
        ROLE["contributor"]: perm("Contributor", ["*"], ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write",
                                                         "Microsoft.Authorization/elevateAccess/Action"]),
        ROLE["uaa"]: perm("User Access Administrator", ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"])}
    return raw
