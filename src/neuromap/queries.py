"""Azure Resource Graph queries and ARM enrichment calls.

v0.2 collects every resource (not only networking), plus resource groups,
subscriptions with their management-group chain, and RBAC role assignments.

Some access settings are not in Resource Graph because they live in child
resources (SQL firewall rules, App Service access restrictions, Service Bus
network rule sets, ...). Those are read with direct ARM GETs at pinned API
versions, listed in ENRICH. Only GET is ever used. Secrets are never read:
no listKeys, no app settings, no connection strings.
"""

# Short, stable names for the types the graph understands in depth.
KINDS: dict[str, str] = {
    # network
    "microsoft.network/virtualnetworks": "vnet",
    "microsoft.network/networksecuritygroups": "nsg",
    "microsoft.network/networkinterfaces": "nic",
    "microsoft.network/publicipaddresses": "pip",
    "microsoft.compute/virtualmachines": "vm",
    "microsoft.network/routetables": "routetable",
    "microsoft.network/privateendpoints": "pe",
    "microsoft.network/loadbalancers": "lb",
    "microsoft.network/applicationgateways": "appgw",
    "microsoft.network/azurefirewalls": "firewall",
    "microsoft.network/bastionhosts": "bastion",
    "microsoft.network/virtualnetworkgateways": "vnetgw",
    "microsoft.network/natgateways": "natgw",
    "microsoft.network/applicationsecuritygroups": "asg",
    # data and PaaS
    "microsoft.storage/storageaccounts": "storage",
    "microsoft.keyvault/vaults": "keyvault",
    "microsoft.sql/servers": "sql-server",
    "microsoft.sql/servers/databases": "sql-db",
    "microsoft.sql/managedinstances": "sql-mi",
    "microsoft.dbforpostgresql/flexibleservers": "postgres",
    "microsoft.dbformysql/flexibleservers": "mysql",
    "microsoft.documentdb/databaseaccounts": "cosmos",
    "microsoft.web/sites": "webapp",
    "microsoft.web/serverfarms": "appplan",
    "microsoft.containerregistry/registries": "acr",
    "microsoft.containerservice/managedclusters": "aks",
    "microsoft.servicebus/namespaces": "servicebus",
    "microsoft.eventhub/namespaces": "eventhub",
    "microsoft.cache/redis": "redis",
    "microsoft.cognitiveservices/accounts": "cognitive",
    "microsoft.search/searchservices": "search",
    "microsoft.managedidentity/userassignedidentities": "uami",
    "microsoft.compute/disks": "disk",
    # edge devices and hybrid (v0.3)
    "microsoft.network/firewallpolicies": "fwpolicy",
    "microsoft.network/ipgroups": "ipgroup",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": "wafpolicy",
    "microsoft.network/connections": "gwconnection",
    "microsoft.network/localnetworkgateways": "lng",
    "microsoft.network/expressroutecircuits": "ercircuit",
    "microsoft.compute/virtualmachinescalesets": "vmss",
    "microsoft.network/virtualhubs": "vhub",
    # evaluated in v0.3.3
    "microsoft.app/managedenvironments": "aca-env",
    "microsoft.app/containerapps": "containerapp",
    "microsoft.logic/workflows": "logicapp",
    "microsoft.operationalinsights/workspaces": "loganalytics",
    "microsoft.insights/components": "appinsights",
    "microsoft.insights/datacollectionendpoints": "dce",
    "microsoft.automation/automationaccounts": "automation",
    "microsoft.purview/accounts": "purview",
}

INVENTORY = """
Resources
| project id, name, type, kind, location, resourceGroup, subscriptionId, tags, sku, identity, managedBy, properties
| order by id asc
"""

CONTAINERS = """
ResourceContainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, subscriptionId, location, tags, properties
| order by id asc
"""

ROLE_ASSIGNMENTS = """
AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| project id, properties
| order by id asc
"""

ROLE_DEFINITIONS_API = "2022-04-01"

# type -> [(key, path suffix, api-version, is_list)]
ENRICH: dict[str, list[tuple[str, str, str, bool]]] = {
    "microsoft.sql/servers": [
        ("server", "", "2021-11-01", False),
        ("firewall_rules", "/firewallRules", "2021-11-01", True),
        ("vnet_rules", "/virtualNetworkRules", "2021-11-01", True),
        ("entra_admins", "/administrators", "2021-11-01", True),
        ("entra_only", "/azureADOnlyAuthentications", "2021-11-01", True),
    ],
    "microsoft.dbforpostgresql/flexibleservers": [
        ("firewall_rules", "/firewallRules", "2022-12-01", True),
    ],
    "microsoft.dbformysql/flexibleservers": [
        ("firewall_rules", "/firewallRules", "2021-05-01", True),
    ],
    "microsoft.web/sites": [
        ("site_config", "/config/web", "2023-01-01", False),
        ("ftp_basic_auth", "/basicPublishingCredentialsPolicies/ftp", "2023-01-01", False),
        ("scm_basic_auth", "/basicPublishingCredentialsPolicies/scm", "2023-01-01", False),
    ],
    "microsoft.servicebus/namespaces": [
        ("network_rule_set", "/networkRuleSets/default", "2021-11-01", False),
    ],
    "microsoft.eventhub/namespaces": [
        ("network_rule_set", "/networkRuleSets/default", "2021-11-01", False),
    ],
    "microsoft.cache/redis": [
        ("firewall_rules", "/firewallRules", "2022-06-01", True),
    ],
    "microsoft.network/firewallpolicies": [
        ("rule_collection_groups", "/ruleCollectionGroups", "2023-09-01", True),
    ],
}
