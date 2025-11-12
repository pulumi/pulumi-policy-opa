package azure

import future.keywords.if
import future.keywords.in

# Storage Account Policy: Require HTTPS only
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    not input.enableHttpsTrafficOnly
    msg := sprintf("Storage account '%s' must enable HTTPS-only traffic", [input.__name])
}

deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.enableHttpsTrafficOnly == false
    msg := sprintf("Storage account '%s' must enable HTTPS-only traffic", [input.__name])
}

# Storage Account Policy: Require minimum TLS version
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    not input.minimumTlsVersion
    msg := sprintf("Storage account '%s' must specify minimum TLS version", [input.__name])
}

deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.minimumTlsVersion == "TLS1_0"
    msg := sprintf("Storage account '%s' must use TLS 1.2 or higher, not TLS 1.0", [input.__name])
}

deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.minimumTlsVersion == "TLS1_1"
    msg := sprintf("Storage account '%s' must use TLS 1.2 or higher, not TLS 1.1", [input.__name])
}

# Storage Account Policy: Disable public blob access
deny[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.allowBlobPublicAccess == true
    msg := sprintf("Storage account '%s' must not allow public blob access", [input.__name])
}

# Storage Account Policy: Require encryption
warn[msg] {
    input.type == "azure-native:storage:StorageAccount"
    not input.encryption
    msg := sprintf("Storage account '%s' should have encryption enabled", [input.__name])
}

# Storage Account Policy: Require infrastructure encryption
warn[msg] {
    input.type == "azure-native:storage:StorageAccount"
    input.encryption
    not input.encryption.requireInfrastructureEncryption
    msg := sprintf("Storage account '%s' should enable infrastructure encryption for additional security", [input.__name])
}

# Blob Container Policy: No public access
deny[msg] {
    input.type == "azure-native:storage:BlobContainer"
    input.publicAccess == "Blob"
    msg := sprintf("Blob container '%s' must not allow public blob access", [input.__name])
}

deny[msg] {
    input.type == "azure-native:storage:BlobContainer"
    input.publicAccess == "Container"
    msg := sprintf("Blob container '%s' must not allow public container access", [input.__name])
}
