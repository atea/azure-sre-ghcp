// Least-privilege RBAC. Each identity gets only the roles listed here.
//   receiver: AcrPull (ACR), Service Bus Data Sender (queue only),
//             Storage Blob Data Reader (sre-config container only, reviewed source registry).
//             No Key Vault role: the receiver holds no inference or publisher credentials.
//   worker:   AcrPull (ACR), Service Bus Data Receiver (queue only),
//             Storage Table Data Contributor (state table only),
//             Storage Blob Data Reader (sre-config container only),
//             Storage Blob Data Contributor (sre-evidence container only),
//             Key Vault Secrets User (vault; Key Vault RBAC cannot scope to one secret),
//             Reader on each explicitly named existing Container App (diagnostics, opt-in),
//             Log Analytics Reader on the diagnostics workspace (opt-in).
// Reader is NOT granted at subscription or resource-group scope.

param receiverPrincipalId string
param workerPrincipalId string
param acrName string
param serviceBusNamespaceName string
param queueName string
param storageAccountName string
param stateTableName string
param configContainerName string
param evidenceContainerName string
param keyVaultName string
param diagnosticsWorkspaceName string = ''

@description('Names of existing Container Apps in this resource group that the worker may read for diagnostics. Empty grants nothing.')
param diagnosticContainerAppNames array = []

var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var roleSbSender = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var roleSbReceiver = '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'
var roleTableContributor = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var roleBlobReader = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var roleBlobContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var roleKvSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'
var roleReader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
var roleLogAnalyticsReader = '73c42c96-874c-492b-b04d-ab87d138a893'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource sbNamespace 'Microsoft.ServiceBus/namespaces@2024-01-01' existing = {
  name: serviceBusNamespaceName
}

resource sbQueue 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' existing = {
  parent: sbNamespace
  name: queueName
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = {
  parent: storage
  name: 'default'
}

resource configContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = {
  parent: blobService
  name: configContainerName
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = {
  parent: blobService
  name: evidenceContainerName
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' existing = {
  parent: storage
  name: 'default'
}

resource stateTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' existing = {
  parent: tableService
  name: stateTableName
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource diagWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!empty(diagnosticsWorkspaceName)) {
  name: diagnosticsWorkspaceName
}

resource diagApps 'Microsoft.App/containerApps@2025-01-01' existing = [for appName in diagnosticContainerAppNames: {
  name: appName
}]

// ---- receiver ----

resource receiverAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, receiverPrincipalId, roleAcrPull)
  scope: acr
  properties: {
    principalId: receiverPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
  }
}

resource receiverSbSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbQueue.id, receiverPrincipalId, roleSbSender)
  scope: sbQueue
  properties: {
    principalId: receiverPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleSbSender)
  }
}

resource receiverConfigReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(configContainer.id, receiverPrincipalId, roleBlobReader)
  scope: configContainer
  properties: {
    principalId: receiverPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleBlobReader)
  }
}

// ---- worker ----

resource workerAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, workerPrincipalId, roleAcrPull)
  scope: acr
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
  }
}

resource workerSbReceiver 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbQueue.id, workerPrincipalId, roleSbReceiver)
  scope: sbQueue
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleSbReceiver)
  }
}

resource workerTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(stateTable.id, workerPrincipalId, roleTableContributor)
  scope: stateTable
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleTableContributor)
  }
}

resource workerConfigReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(configContainer.id, workerPrincipalId, roleBlobReader)
  scope: configContainer
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleBlobReader)
  }
}

resource workerEvidenceContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceContainer.id, workerPrincipalId, roleBlobContributor)
  scope: evidenceContainer
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleBlobContributor)
  }
}

resource workerKvSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, workerPrincipalId, roleKvSecretsUser)
  scope: keyVault
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKvSecretsUser)
  }
}

// Opt-in: one Reader assignment per explicitly named Container App. No broader scope.
resource workerAppReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (appName, i) in diagnosticContainerAppNames: {
  name: guid(diagApps[i].id, workerPrincipalId, roleReader)
  scope: diagApps[i]
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleReader)
  }
}]

// Opt-in: only assigned when a diagnostics workspace name is supplied.
resource workerDiagReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(diagnosticsWorkspaceName)) {
  name: guid(diagWorkspace.id, workerPrincipalId, roleLogAnalyticsReader)
  scope: diagWorkspace
  properties: {
    principalId: workerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleLogAnalyticsReader)
  }
}
