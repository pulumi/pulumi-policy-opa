package azure

import future.keywords.if
import future.keywords.in

# Virtual Machine Policy: Require managed disks
deny[msg] {
    input.type == "azure-native:compute:VirtualMachine"
    not input.storageProfile.osDisk.managedDisk
    msg := sprintf("Virtual machine '%s' must use managed disks", [input.__name])
}

# Virtual Machine Policy: Require OS disk encryption
warn[msg] {
    input.type == "azure-native:compute:VirtualMachine"
    input.storageProfile.osDisk
    not input.storageProfile.osDisk.encryptionSettings
    msg := sprintf("Virtual machine '%s' should have OS disk encryption enabled", [input.__name])
}

# Virtual Machine Policy: No public IP for production
deny[msg] {
    input.type == "azure-native:compute:VirtualMachine"
    contains(lower(input.__name), "prod")
    input.networkProfile
    some nic in input.networkProfile.networkInterfaces
    nic.properties.ipConfigurations
    some ipConfig in nic.properties.ipConfigurations
    ipConfig.properties.publicIPAddress
    msg := sprintf("Production VM '%s' should not have a public IP address", [input.__name])
}

# Disk Policy: Require encryption
deny[msg] {
    input.type == "azure-native:compute:Disk"
    not input.encryption
    msg := sprintf("Disk '%s' must have encryption enabled", [input.__name])
}

deny[msg] {
    input.type == "azure-native:compute:Disk"
    input.encryption
    input.encryption.type == "EncryptionAtRestWithPlatformKey"
    contains(lower(input.__name), "prod")
    msg := sprintf("Production disk '%s' should use customer-managed keys for encryption", [input.__name])
}

# VM Scale Set Policy: Require automatic OS upgrades
warn[msg] {
    input.type == "azure-native:compute:VirtualMachineScaleSet"
    not input.upgradePolicy.automaticOSUpgradePolicy
    msg := sprintf("VM scale set '%s' should enable automatic OS upgrades", [input.__name])
}

# VM Scale Set Policy: Require health monitoring
warn[msg] {
    input.type == "azure-native:compute:VirtualMachineScaleSet"
    not input.healthProbeId
    msg := sprintf("VM scale set '%s' should have health monitoring enabled", [input.__name])
}
