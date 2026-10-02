"""v0.3 fixture: edge devices, routing and hybrid on top of the v0.2 estate.

  fw-hub      policy fwp-hub (parent fwp-parent), DNAT any->VM RDP, DNAT office(IP group)->unknown IP
  fw-legacy   classic rules, DNAT from one IP only
  lb-web-pub  public LB: rule 443->8443 to VM NIC, NAT v1 50001->22, NAT v2 range -> VMSS
  agw-pub     WAF_v2: listener WAF override (Prevention), gateway WAF (Detection), path override
  rt-spoke    0/0 -> fw-hub, 10.50/16 -> unowned NVA IP, blackhole route
  vgw-hub     VPN + P2S, S2S to lng-dc1; ergw-hub -> er-ams; spoke uses remote gateways
"""
from __future__ import annotations

import copy

from .fixture_v2 import fixture_v2
from .selftest import RG, SUB, row

N = "Microsoft.Network"
HUB = f"{RG}/{N}/virtualNetworks/hub-vnet"
NIC_IPCFG = f"{RG}/{N}/networkInterfaces/vm-web01-nic/ipConfigurations/ipconfig1"
VMSS_IPCFG = f"{RG}/Microsoft.Compute/virtualMachineScaleSets/vmss-api/virtualMachines/0/networkInterfaces/nic0/ipConfigurations/ip0"


def _find(raw, name):
    return next(r for r in raw["resources"] if r["name"] == name)


def _pip(name, ip, owner_cfg=None):
    return row(f"{N}/publicIPAddresses", name, {"ipAddress": ip, **({"ipConfiguration": {"id": owner_cfg}} if owner_cfg else {})},
               sku={"name": "Standard"})


def _ref(x):
    return {"id": x}


def fixture_v3() -> dict:
    raw = copy.deepcopy(fixture_v2())
    hub = _find(raw, "hub-vnet")["properties"]
    hub["subnets"] += [
        {"id": f"{HUB}/subnets/AppGwSubnet", "name": "AppGwSubnet", "properties": {"addressPrefix": "10.0.3.0/24"}},
        {"id": f"{HUB}/subnets/GatewaySubnet", "name": "GatewaySubnet", "properties": {"addressPrefix": "10.0.4.0/27"}}]
    _find(raw, "spoke-vnet")["properties"]["virtualNetworkPeerings"][0]["properties"]["useRemoteGateways"] = True
    fwp_hub, fwp_parent = f"{RG}/{N}/firewallPolicies/fwp-hub", f"{RG}/{N}/firewallPolicies/fwp-parent"
    _find(raw, "fw-hub")["properties"].update(firewallPolicy=_ref(fwp_hub), threatIntelMode="Alert")
    _find(raw, "rt-spoke")["properties"]["routes"] += [
        {"name": "to-nva", "properties": {"addressPrefix": "10.50.0.0/16", "nextHopType": "VirtualAppliance",
                                          "nextHopIpAddress": "10.9.9.9"}},
        {"name": "blackhole", "properties": {"addressPrefix": "10.66.0.0/16", "nextHopType": "None"}}]
    _find(raw, "web-app01")["properties"]["defaultHostName"] = "web-app01.azurewebsites.net"

    ipg = f"{RG}/{N}/ipGroups/ipg-office"
    lb = f"{RG}/{N}/loadBalancers/lb-web-pub"
    agw = f"{RG}/{N}/applicationGateways/agw-pub"
    waf_strict, waf_detect = (f"{RG}/{N}/ApplicationGatewayWebApplicationFirewallPolicies/{n}" for n in ("wafp-strict", "wafp-detect"))
    vgw, ergw = f"{RG}/{N}/virtualNetworkGateways/vgw-hub", f"{RG}/{N}/virtualNetworkGateways/ergw-hub"
    lng, er = f"{RG}/{N}/localNetworkGateways/lng-dc1", f"{RG}/{N}/expressRouteCircuits/er-ams"

    raw["resources"] += [
        row(f"{N}/ipGroups", "ipg-office", {"ipAddresses": ["203.0.113.0/24"]}),
        row(f"{N}/firewallPolicies", "fwp-parent", {"threatIntelMode": "Deny"}),
        row(f"{N}/firewallPolicies", "fwp-hub", {
            "basePolicy": _ref(fwp_parent), "threatIntelMode": "Deny", "sku": {"tier": "Premium"},
            "intrusionDetection": {"mode": "Alert"}, "dnsSettings": {"enableProxy": True}}),
        # classic firewall
        _pip("pip-legacy", "20.50.60.90", f"{RG}/{N}/azureFirewalls/fw-legacy/azureFirewallIpConfigurations/c"),
        row(f"{N}/azureFirewalls", "fw-legacy", {
            "sku": {"tier": "Standard"}, "threatIntelMode": "Alert",
            "ipConfigurations": [{"name": "c", "properties": {"privateIPAddress": "10.0.1.5",
                                                               "publicIPAddress": _ref(f"{RG}/{N}/publicIPAddresses/pip-legacy")}}],
            "natRuleCollections": [{"name": "nat-legacy", "properties": {"priority": 100, "action": {"type": "Dnat"}, "rules": [
                {"name": "web-8080", "sourceAddresses": ["198.51.100.7"], "destinationAddresses": ["20.50.60.90"],
                 "destinationPorts": ["8080"], "protocols": ["TCP"], "translatedAddress": "10.1.1.4", "translatedPort": "80"}]}}],
            "networkRuleCollections": [{"name": "net-legacy", "properties": {"priority": 200, "action": {"type": "Allow"}, "rules": [
                {"name": "dns-out", "sourceAddresses": ["10.1.0.0/16"], "destinationAddresses": ["*"],
                 "destinationPorts": ["53"], "protocols": ["UDP"]}]}}]}),
        # public load balancer + VMSS
        _pip("pip-lb", "20.50.60.100", f"{lb}/frontendIPConfigurations/fe-pub"),
        row(f"{N}/loadBalancers", "lb-web-pub", {
            "frontendIPConfigurations": [{"id": f"{lb}/frontendIPConfigurations/fe-pub", "name": "fe-pub",
                                          "properties": {"publicIPAddress": _ref(f"{RG}/{N}/publicIPAddresses/pip-lb")}}],
            "backendAddressPools": [
                {"id": f"{lb}/backendAddressPools/bp-web", "name": "bp-web",
                 "properties": {"backendIPConfigurations": [_ref(NIC_IPCFG)],
                                "loadBalancerBackendAddresses": [{"name": "dup", "properties": {
                                    "networkInterfaceIPConfiguration": _ref(NIC_IPCFG)}}]}},
                {"id": f"{lb}/backendAddressPools/bp-vmss", "name": "bp-vmss",
                 "properties": {"backendIPConfigurations": [_ref(VMSS_IPCFG)]}}],
            "probes": [{"id": f"{lb}/probes/hp", "name": "hp", "properties": {"protocol": "Https", "port": 8443, "requestPath": "/health"}}],
            "loadBalancingRules": [{"name": "https", "properties": {
                "frontendIPConfiguration": _ref(f"{lb}/frontendIPConfigurations/fe-pub"),
                "backendAddressPool": _ref(f"{lb}/backendAddressPools/bp-web"), "probe": _ref(f"{lb}/probes/hp"),
                "protocol": "Tcp", "frontendPort": 443, "backendPort": 8443, "disableOutboundSnat": True}}],
            "inboundNatRules": [
                {"name": "ssh-vm", "properties": {"frontendIPConfiguration": _ref(f"{lb}/frontendIPConfigurations/fe-pub"),
                                                  "protocol": "Tcp", "frontendPort": 50001, "backendPort": 22,
                                                  "backendIPConfiguration": _ref(NIC_IPCFG)}},
                {"name": "vmss-ssh", "properties": {"frontendIPConfiguration": _ref(f"{lb}/frontendIPConfigurations/fe-pub"),
                                                    "protocol": "Tcp", "frontendPortRangeStart": 50100, "frontendPortRangeEnd": 50199,
                                                    "backendPort": 22, "backendAddressPool": _ref(f"{lb}/backendAddressPools/bp-vmss")}}],
            "outboundRules": [{"name": "egress", "properties": {"protocol": "All", "allocatedOutboundPorts": 1024,
                                                                "frontendIPConfigurations": [_ref(f"{lb}/frontendIPConfigurations/fe-pub")],
                                                                "backendAddressPool": _ref(f"{lb}/backendAddressPools/bp-web")}}]},
            sku={"name": "Standard"}),
        row("Microsoft.Compute/virtualMachineScaleSets", "vmss-api", {"virtualMachineProfile": {"networkProfile": {
            "networkInterfaceConfigurations": [{"name": "nic", "properties": {
                "networkSecurityGroup": _ref(f"{RG}/{N}/networkSecurityGroups/nsg-vm-web01"),
                "ipConfigurations": [{"name": "ip0", "properties": {
                    "subnet": _ref(f"{RG}/{N}/virtualNetworks/spoke-vnet/subnets/web"),
                    "loadBalancerBackendAddressPools": [_ref(f"{lb}/backendAddressPools/bp-vmss")]}}]}}]}}},
            sku={"name": "Standard_D2s_v5", "capacity": 3}),
        # WAF policies + App Gateway
        row(f"{N}/ApplicationGatewayWebApplicationFirewallPolicies", "wafp-strict", {
            "policySettings": {"state": "Enabled", "mode": "Prevention", "requestBodyCheck": True},
            "managedRules": {"managedRuleSets": [{"ruleSetType": "Microsoft_DefaultRuleSet", "ruleSetVersion": "2.1"}]},
            "customRules": [{"name": "geo"}]}),
        row(f"{N}/ApplicationGatewayWebApplicationFirewallPolicies", "wafp-detect", {
            "policySettings": {"state": "Enabled", "mode": "Detection"},
            "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}]}}),
        _pip("pip-agw", "20.50.60.110", f"{agw}/frontendIPConfigurations/fe-pub"),
        row(f"{N}/applicationGateways", "agw-pub", {
            "sku": {"name": "WAF_v2", "tier": "WAF_v2"}, "firewallPolicy": _ref(waf_detect),
            "sslPolicy": {"policyType": "Predefined", "policyName": "AppGwSslPolicy20220101"},
            "gatewayIPConfigurations": [{"name": "g", "properties": {"subnet": _ref(f"{HUB}/subnets/AppGwSubnet")}}],
            "frontendIPConfigurations": [{"id": f"{agw}/frontendIPConfigurations/fe-pub", "name": "fe-pub",
                                          "properties": {"publicIPAddress": _ref(f"{RG}/{N}/publicIPAddresses/pip-agw")}}],
            "frontendPorts": [{"id": f"{agw}/frontendPorts/p443", "name": "p443", "properties": {"port": 443}},
                              {"id": f"{agw}/frontendPorts/p80", "name": "p80", "properties": {"port": 80}}],
            "httpListeners": [
                {"id": f"{agw}/httpListeners/l-https", "name": "l-https", "properties": {
                    "frontendIPConfiguration": _ref(f"{agw}/frontendIPConfigurations/fe-pub"),
                    "frontendPort": _ref(f"{agw}/frontendPorts/p443"), "protocol": "Https",
                    "hostNames": ["app.contoso.com"], "firewallPolicy": _ref(waf_strict)}},
                {"id": f"{agw}/httpListeners/l-http", "name": "l-http", "properties": {
                    "frontendIPConfiguration": _ref(f"{agw}/frontendIPConfigurations/fe-pub"),
                    "frontendPort": _ref(f"{agw}/frontendPorts/p80"), "protocol": "Http"}}],
            "backendAddressPools": [
                {"id": f"{agw}/backendAddressPools/bp-app", "name": "bp-app",
                 "properties": {"backendAddresses": [{"fqdn": "web-app01.azurewebsites.net"}]}},
                {"id": f"{agw}/backendAddressPools/bp-vm", "name": "bp-vm",
                 "properties": {"backendAddresses": [{"ipAddress": "10.1.1.4"}]}},
                {"id": f"{agw}/backendAddressPools/bp-ext", "name": "bp-ext",
                 "properties": {"backendAddresses": [{"ipAddress": "10.77.0.9"},
                                                     {"fqdn": "ca-open.happy-sky.westeurope.azurecontainerapps.io"}]}}],
            "backendHttpSettingsCollection": [
                {"id": f"{agw}/backendHttpSettingsCollection/s-https", "name": "s-https",
                 "properties": {"port": 443, "protocol": "Https", "pickHostNameFromBackendAddress": True}},
                {"id": f"{agw}/backendHttpSettingsCollection/s-http", "name": "s-http",
                 "properties": {"port": 80, "protocol": "Http"}}],
            "urlPathMaps": [{"id": f"{agw}/urlPathMaps/upm", "name": "upm", "properties": {
                "defaultBackendAddressPool": _ref(f"{agw}/backendAddressPools/bp-vm"),
                "defaultBackendHttpSettings": _ref(f"{agw}/backendHttpSettingsCollection/s-http"),
                "pathRules": [{"name": "api", "properties": {
                    "paths": ["/api/*"], "backendAddressPool": _ref(f"{agw}/backendAddressPools/bp-ext"),
                    "backendHttpSettings": _ref(f"{agw}/backendHttpSettingsCollection/s-http"),
                    "firewallPolicy": _ref(waf_strict)}}]}}],
            "requestRoutingRules": [
                {"name": "r1", "properties": {"ruleType": "Basic", "priority": 10,
                                              "httpListener": _ref(f"{agw}/httpListeners/l-https"),
                                              "backendAddressPool": _ref(f"{agw}/backendAddressPools/bp-app"),
                                              "backendHttpSettings": _ref(f"{agw}/backendHttpSettingsCollection/s-https")}},
                {"name": "r2", "properties": {"ruleType": "PathBasedRouting", "priority": 20,
                                              "httpListener": _ref(f"{agw}/httpListeners/l-http"),
                                              "urlPathMap": _ref(f"{agw}/urlPathMaps/upm")}}]}),
        # hybrid
        _pip("pip-vgw", "20.50.60.120", f"{vgw}/ipConfigurations/default"),
        row(f"{N}/virtualNetworkGateways", "vgw-hub", {
            "gatewayType": "Vpn", "vpnType": "RouteBased", "sku": {"name": "VpnGw2AZ"}, "activeActive": False,
            "enableBgp": True, "bgpSettings": {"asn": 65515, "bgpPeeringAddress": "10.0.4.4"},
            "vpnClientConfiguration": {"vpnClientAddressPool": {"addressPrefixes": ["172.16.200.0/24"]},
                                       "vpnAuthenticationTypes": ["AAD"], "vpnClientProtocols": ["OpenVPN"],
                                       "aadTenant": "https://login.microsoftonline.com/tenant-guid/"},
            "ipConfigurations": [{"name": "default", "properties": {
                "subnet": _ref(f"{HUB}/subnets/GatewaySubnet"), "publicIPAddress": _ref(f"{RG}/{N}/publicIPAddresses/pip-vgw")}}]}),
        row(f"{N}/virtualNetworkGateways", "ergw-hub", {
            "gatewayType": "ExpressRoute", "sku": {"name": "ErGw1AZ"},
            "ipConfigurations": [{"name": "default", "properties": {"subnet": _ref(f"{HUB}/subnets/GatewaySubnet")}}]}),
        row(f"{N}/localNetworkGateways", "lng-dc1", {
            "gatewayIpAddress": "198.51.100.1", "localNetworkAddressSpace": {"addressPrefixes": ["192.168.0.0/16"]}}),
        row(f"{N}/expressRouteCircuits", "er-ams", {
            "serviceProviderProperties": {"serviceProviderName": "Equinix", "peeringLocation": "Amsterdam", "bandwidthInMbps": 1000},
            "serviceProviderProvisioningState": "Provisioned", "circuitProvisioningState": "Enabled",
            "peerings": [{"name": "AzurePrivatePeering", "properties": {
                "peeringType": "AzurePrivatePeering", "state": "Enabled", "primaryPeerAddressPrefix": "169.254.0.0/30",
                "secondaryPeerAddressPrefix": "169.254.0.4/30", "vlanId": 100, "peerASN": 65001}}]}),
        row(f"{N}/connections", "cn-dc1", {"connectionType": "IPsec", "virtualNetworkGateway1": _ref(vgw),
                                           "localNetworkGateway2": _ref(lng), "enableBgp": False,
                                           "connectionStatus": "Connected", "connectionProtocol": "IKEv2"}),
        row(f"{N}/connections", "cn-er", {"connectionType": "ExpressRoute", "virtualNetworkGateway1": _ref(ergw),
                                          "peer": _ref(er), "routingWeight": 0}),
    ]

    # v0.3.3 evaluators
    env_ext, env_int = (f"{RG}/Microsoft.App/managedEnvironments/{n}" for n in ("cae-ext", "cae-int"))
    ing = lambda **k: {"configuration": {"ingress": {"targetPort": 8080, "transport": "auto", **k}}}
    req = {"definition": {"triggers": {"manual": {"type": "Request", "kind": "Http"}}}}
    raw["resources"] += [
        row("Microsoft.Compute/disks", "disk-sas", {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "AllowAll",
                                                    "diskState": "ActiveSAS", "dataAccessAuthMode": "None"}),
        row("Microsoft.Compute/disks", "disk-priv", {"publicNetworkAccess": "Enabled", "networkAccessPolicy": "AllowPrivate",
                                                     "diskAccessId": f"{RG}/Microsoft.Compute/diskAccesses/da1", "diskState": "Attached"}),
        row("Microsoft.Compute/disks", "disk-nopol", {"publicNetworkAccess": "Enabled", "diskState": "Unattached"}),
        row("Microsoft.Purview/accounts", "pv-open", {"publicNetworkAccess": "Enabled"}),
        row("Microsoft.Purview/accounts", "pv-ns", {"publicNetworkAccess": "NotSpecified"}),
        row("Microsoft.Automation/automationAccounts", "aa-open", {"publicNetworkAccess": True, "disableLocalAuth": False}),
        row("Microsoft.Automation/automationAccounts", "aa-closed", {"publicNetworkAccess": False}),
        row("Microsoft.App/managedEnvironments", "cae-ext", {"staticIp": "20.50.60.130"}),
        row("Microsoft.App/managedEnvironments", "cae-int", {"vnetConfiguration": {
            "internal": True, "infrastructureSubnetId": f"{RG}/{N}/virtualNetworks/spoke-vnet/subnets/data"}}),
        row("Microsoft.App/containerApps", "ca-open", {"managedEnvironmentId": env_ext,
                                                         **ing(external=True, fqdn="ca-open.happy-sky.westeurope.azurecontainerapps.io")}),
        row("Microsoft.App/containerApps", "ca-allow", {"managedEnvironmentId": env_ext, **ing(external=True, ipSecurityRestrictions=[
            {"name": "office", "action": "Allow", "ipAddressRange": "203.0.113.0/24"}])}),
        row("Microsoft.App/containerApps", "ca-on-internal", {"managedEnvironmentId": env_int, **ing(external=True)}),
        row("Microsoft.App/containerApps", "ca-noingress", {"managedEnvironmentId": env_ext, "configuration": {}}),
        row("Microsoft.App/containerApps", "ca-mixed", {"managedEnvironmentId": env_ext, **ing(external=True, ipSecurityRestrictions=[
            {"name": "a", "action": "Allow", "ipAddressRange": "1.2.3.4/32"}, {"name": "d", "action": "Deny", "ipAddressRange": "5.6.7.8/32"}])}),
        row("Microsoft.Logic/workflows", "la-http", {"state": "Enabled", **req}),
        row("Microsoft.Logic/workflows", "la-ip", {"state": "Enabled", **req, "accessControl": {"triggers": {
            "allowedCallerIpAddresses": [{"addressRange": "203.0.113.0/24"}]}}}),
        row("Microsoft.Logic/workflows", "la-onlyla", {"state": "Disabled", **req, "accessControl": {"triggers": {
            "allowedCallerIpAddresses": []}}}),
        row("Microsoft.Logic/workflows", "la-recur", {"definition": {"triggers": {"r": {"type": "Recurrence"}}}}),
        row("Microsoft.Logic/workflows", "la-webhook", {"definition": {"triggers": {
            "Microsoft_Sentinel_incident": {"type": "ApiConnectionWebhook"}}}}),
        row("Microsoft.Logic/workflows", "la-notrig", {"definition": {"triggers": {}}}),
        row("Microsoft.OperationalInsights/workspaces", "law-ing", {
            "publicNetworkAccessForIngestion": "Enabled", "publicNetworkAccessForQuery": "Disabled",
            "features": {"disableLocalAuth": True}}),
        row("Microsoft.OperationalInsights/workspaces", "law-closed", {
            "publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Disabled"}),
        row("Microsoft.Insights/components", "ai-query", {
            "publicNetworkAccessForIngestion": "Disabled", "publicNetworkAccessForQuery": "Enabled", "DisableLocalAuth": False}),
        row("Microsoft.Insights/dataCollectionEndpoints", "dce-open", {"networkAcls": {"publicNetworkAccess": "Enabled"}}),
        row("Microsoft.Insights/dataCollectionEndpoints", "dce-amp", {"networkAcls": {"publicNetworkAccess": "SecuredByPerimeter"}}),
        row("Microsoft.ContainerService/managedClusters", "aks-unset", {"agentPoolProfiles": []}),
        row("Microsoft.ContainerService/managedClusters", "aks-false", {"apiServerAccessProfile": {"enablePrivateCluster": False}}),
    ]

    mc = f"/subscriptions/{SUB}/resourceGroups/MC_rg-net_aks-stopped_westeurope/providers"
    klb = f"{mc}/{N}/loadBalancers/kubernetes"

    def mcrow(rtype, name, props, sku=None):
        return {"id": f"{mc}/{rtype}/{name}", "name": name, "type": rtype, "location": "westeurope",
                "resourceGroup": "MC_rg-net_aks-stopped_westeurope", "subscriptionId": SUB, "tags": {},
                "sku": sku, "properties": props}
    raw["resources"] += [
        row("Microsoft.ContainerService/managedClusters", "aks-stopped", {
            "powerState": {"code": "Stopped"}, "nodeResourceGroup": "MC_rg-net_aks-stopped_westeurope",
            "agentPoolProfiles": []}),
        mcrow(f"{N}/publicIPAddresses", "k8s-pip", {"ipAddress": "20.50.60.140",
                                                   "ipConfiguration": {"id": f"{klb}/frontendIPConfigurations/fe1"}}),
        mcrow(f"{N}/loadBalancers", "kubernetes", {
            "frontendIPConfigurations": [{"id": f"{klb}/frontendIPConfigurations/fe1", "name": "fe1", "properties": {
                "publicIPAddress": {"id": f"{mc}/{N}/publicIPAddresses/k8s-pip"}}}],
            "backendAddressPools": [{"id": f"{klb}/backendAddressPools/kubernetes", "name": "kubernetes",
                                     "properties": {"backendIPConfigurations": [], "loadBalancerBackendAddresses": []}}],
            "loadBalancingRules": [{"name": f"svc-TCP-{port}", "properties": {
                "frontendIPConfiguration": {"id": f"{klb}/frontendIPConfigurations/fe1"},
                "backendAddressPool": {"id": f"{klb}/backendAddressPools/kubernetes"},
                "protocol": "Tcp", "frontendPort": port, "backendPort": port}} for port in (80, 443)]},
            sku={"name": "Standard"}),
    ]
    # a RUNNING cluster whose load balancer has the same name ("kubernetes") as the stopped one
    mc2 = f"/subscriptions/{SUB}/resourceGroups/MC_rg-net_aks-run_westeurope/providers"
    klb2 = f"{mc2}/{N}/loadBalancers/kubernetes"
    raw["resources"] += [
        row("Microsoft.ContainerService/managedClusters", "aks-run", {
            "powerState": {"code": "Running"}, "nodeResourceGroup": "MC_rg-net_aks-run_westeurope", "agentPoolProfiles": []}),
        {"id": f"{mc2}/{N}/publicIPAddresses/k8s-run-pip", "name": "k8s-run-pip", "type": f"{N}/publicIPAddresses",
         "location": "westeurope", "resourceGroup": "MC_rg-net_aks-run_westeurope", "subscriptionId": SUB, "tags": {},
         "sku": None, "properties": {"ipAddress": "20.50.60.150",
                                     "ipConfiguration": {"id": f"{klb2}/frontendIPConfigurations/fe1"}}},
        {"id": klb2, "name": "kubernetes", "type": f"{N}/loadBalancers", "location": "westeurope",
         "resourceGroup": "MC_rg-net_aks-run_westeurope", "subscriptionId": SUB, "tags": {}, "sku": {"name": "Standard"},
         "properties": {
             "frontendIPConfigurations": [{"id": f"{klb2}/frontendIPConfigurations/fe1", "name": "fe1", "properties": {
                 "publicIPAddress": {"id": f"{mc2}/{N}/publicIPAddresses/k8s-run-pip"}}}],
             "backendAddressPools": [{"id": f"{klb2}/backendAddressPools/kubernetes", "name": "kubernetes",
                                      "properties": {"backendIPConfigurations": [{"id": VMSS_IPCFG}]}}],
             "loadBalancingRules": [{"name": "svc-TCP-80", "properties": {
                 "frontendIPConfiguration": {"id": f"{klb2}/frontendIPConfigurations/fe1"},
                 "backendAddressPool": {"id": f"{klb2}/backendAddressPools/kubernetes"},
                 "protocol": "Tcp", "frontendPort": 80, "backendPort": 80}}]}},
    ]
    # disabled resources whose rules must still be shown (not in effect), and a PE known only from its side
    web_closed = f"{RG}/Microsoft.Web/sites/web-closed"
    raw["resources"] += [
        row("Microsoft.Storage/storageAccounts", "st-closed", {
            "publicNetworkAccess": "Disabled",
            "networkAcls": {"defaultAction": "Deny", "ipRules": [{"value": "20.50.60.70"}], "virtualNetworkRules": []}}),
        row("Microsoft.Web/sites", "web-closed", {"publicNetworkAccess": "Disabled"}, ),
        row(f"{N}/privateEndpoints", "pe-web", {
            "subnet": {"id": f"{RG}/{N}/virtualNetworks/spoke-vnet/subnets/data"},
            "privateLinkServiceConnections": [{"name": "c", "properties": {
                "privateLinkServiceId": web_closed, "groupIds": ["sites"],
                "privateLinkServiceConnectionState": {"status": "Approved"}}}]}),
        row("Microsoft.CognitiveServices/accounts", "cog-noflag", {"networkAcls": {"defaultAction": "Allow"}}),
    ]
    raw["arm"][web_closed.lower()] = {
        "site_config": {"api": "2023-01-01", "data": {"properties": {"ipSecurityRestrictions": [
            {"name": "Allow all", "priority": 2147483647, "action": "Allow", "ipAddress": "Any"}]}}},
        "ftp_basic_auth": {"api": "2023-01-01", "data": {"properties": {"allow": False}}},
        "scm_basic_auth": {"api": "2023-01-01", "data": {"properties": {"allow": False}}}}
    raw["arm"][rid_open_sql := f"/subscriptions/{SUB}/resourcegroups/rg-data/providers/microsoft.sql/servers/sql-open"]["entra_only"] = \
        {"api": "2021-11-01", "data": []}

    def coll(name, prio, ctype, action, rules):
        return {"ruleCollectionType": ctype, "name": name, "priority": prio, "action": {"type": action}, "rules": rules}

    raw["arm"][fwp_parent.lower()] = {"rule_collection_groups": {"api": "2023-09-01", "data": [
        {"name": "Parent-Base", "properties": {"priority": 500, "ruleCollections": [
            coll("block-telnet", 100, "FirewallPolicyFilterRuleCollection", "Deny", [
                {"ruleType": "NetworkRule", "name": "no-telnet", "sourceAddresses": ["*"], "destinationAddresses": ["*"],
                 "destinationPorts": ["23"], "ipProtocols": ["TCP"]}])]}}]}}
    raw["arm"][fwp_hub.lower()] = {"rule_collection_groups": {"api": "2023-09-01", "data": [
        {"name": "Hub-Net", "properties": {"priority": 200, "ruleCollections": [
            coll("app-out", 400, "FirewallPolicyFilterRuleCollection", "Allow", [
                {"ruleType": "ApplicationRule", "name": "ms-updates", "sourceAddresses": ["10.1.0.0/16"],
                 "targetFqdns": ["*.microsoft.com"], "protocols": [{"protocolType": "Https", "port": 443}]}]),
            coll("net-out", 300, "FirewallPolicyFilterRuleCollection", "Allow", [
                {"ruleType": "NetworkRule", "name": "spoke-https", "sourceAddresses": ["10.1.0.0/16"],
                 "destinationAddresses": ["*"], "destinationPorts": ["443"], "ipProtocols": ["TCP"]}])]}},
        {"name": "Hub-DNAT", "properties": {"priority": 100, "ruleCollections": [
            coll("inbound", 100, "FirewallPolicyNatRuleCollection", "DNAT", [
                {"ruleType": "NatRule", "name": "rdp-to-vm", "sourceAddresses": ["*"], "destinationAddresses": ["20.50.60.80"],
                 "destinationPorts": ["3389"], "ipProtocols": ["TCP"], "translatedAddress": "10.1.1.4", "translatedPort": "3389"},
                {"ruleType": "NatRule", "name": "ssh-office", "sourceIpGroups": [ipg], "destinationAddresses": ["20.50.60.80"],
                 "destinationPorts": ["2222"], "ipProtocols": ["TCP"], "translatedAddress": "10.1.2.50", "translatedPort": "22"}])]}}]}}
    return raw
