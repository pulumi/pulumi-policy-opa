package azure

import future.keywords.if
import future.keywords.in

# Network Security Group Policy: No unrestricted SSH
deny[msg] {
    input.type == "azure-native:network:NetworkSecurityGroup"
    some rule in input.securityRules
    rule.access == "Allow"
    rule.direction == "Inbound"
    rule.destinationPortRange == "22"
    rule.sourceAddressPrefix == "*"
    msg := sprintf("NSG '%s' allows unrestricted SSH access (port 22) from Internet", [input.__name])
}

# Network Security Group Policy: No unrestricted RDP
deny[msg] {
    input.type == "azure-native:network:NetworkSecurityGroup"
    some rule in input.securityRules
    rule.access == "Allow"
    rule.direction == "Inbound"
    rule.destinationPortRange == "3389"
    rule.sourceAddressPrefix == "*"
    msg := sprintf("NSG '%s' allows unrestricted RDP access (port 3389) from Internet", [input.__name])
}

# Network Security Group Policy: Warn on overly permissive rules
warn[msg] {
    input.type == "azure-native:network:NetworkSecurityGroup"
    some rule in input.securityRules
    rule.access == "Allow"
    rule.direction == "Inbound"
    rule.destinationPortRange == "*"
    rule.sourceAddressPrefix == "*"
    msg := sprintf("NSG '%s' has overly permissive rule allowing all ports from all sources", [input.__name])
}

# Virtual Network Policy: Require DDoS protection for production
deny[msg] {
    input.type == "azure-native:network:VirtualNetwork"
    contains(lower(input.__name), "prod")
    not input.enableDdosProtection
    msg := sprintf("Production virtual network '%s' must have DDoS protection enabled", [input.__name])
}

# Application Gateway Policy: Require WAF
warn[msg] {
    input.type == "azure-native:network:ApplicationGateway"
    not input.webApplicationFirewallConfiguration
    msg := sprintf("Application Gateway '%s' should have Web Application Firewall enabled", [input.__name])
}

# Application Gateway Policy: WAF should be in prevention mode
warn[msg] {
    input.type == "azure-native:network:ApplicationGateway"
    input.webApplicationFirewallConfiguration
    input.webApplicationFirewallConfiguration.firewallMode == "Detection"
    msg := sprintf("Application Gateway '%s' WAF should be in Prevention mode, not Detection", [input.__name])
}
