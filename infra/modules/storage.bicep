// Private state storage: shared-key access and anonymous blob access are disabled.
// Access is Entra RBAC only (table + blob data roles, granted in rbac.bicep).
// publicNetworkAccess is parameterized: 'Enabled' is the default because no VNet or
// private endpoints are provisioned by this template. Set 'Disabled' only after
// private endpoints are added.

param location string
param tags object
param namePrefix string
param tableName string
param configContainerName string = 'sre-config'
param evidenceContainerName string = 'sre-evidence'

@allowed([ 'Enabled', 'Disabled' ])
param publicNetworkAccess string = 'Enabled'

@minValue(1)
@maxValue(365)
param blobDeleteRetentionDays int = 14

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('st${toLower(replace(namePrefix, '-', ''))}${uniqueString(resourceGroup().id)}', 24)
  location: location
  tags: tags
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    allowCrossTenantReplication: false
    defaultToOAuthAuthentication: true
    publicNetworkAccess: publicNetworkAccess
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: blobDeleteRetentionDays
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: blobDeleteRetentionDays
    }
  }
}

resource configContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: configContainerName
  properties: {
    publicAccess: 'None'
  }
}

// Private evidence container: worker writes incident evidence here via its managed identity.
resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: evidenceContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource stateTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: tableName
}

output storageAccountId string = storage.id
output storageAccountName string = storage.name
output tableEndpoint string = storage.properties.primaryEndpoints.table
output blobEndpoint string = storage.properties.primaryEndpoints.blob
output configContainerName string = configContainer.name
output evidenceContainerName string = evidenceContainer.name
output stateTableName string = stateTable.name
