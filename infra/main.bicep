// Azure SRE Copilot: receiver + worker on Container Apps, one image, isolated identities.
// Deploy:  az deployment group create -g <rg> -f infra/main.bicep -p infra/environments/dev.bicepparam
// Offline validation: az bicep build --file infra/main.bicep
// Nothing here stores or references secret values. Key Vault secrets must already exist (supplied out of band)
// and are read at runtime by the worker through the Key Vault SDK, not injected as environment variables.

targetScope = 'resourceGroup'

@description('Short prefix for resource names (lowercase alphanumeric or hyphen, 3-8 chars).')
@minLength(3)
@maxLength(8)
param namePrefix string

param location string = resourceGroup().location
param tags object = {}

@description('Existing Azure Container Registry name (same resource group). Apps pull via managed identity (AcrPull).')
param acrName string

@description('Full image reference for the single shared image, e.g. myacr.azurecr.io/azure-sre-copilot:0.1.0. Prefer a digest pin for production.')
param image string

@description('Existing Key Vault name (same resource group). Only the worker is granted Secrets User on it.')
param keyVaultName string

@description('Exact Entra audience of the secure webhook API.')
@minLength(1)
param webhookAudience string

@description('Approved Monitor caller Entra application ID; validate in the live webhook gate.')
@minLength(36)
@maxLength(36)
param monitorCallerAppId string

@description('Required application-role value assigned to the Monitor caller.')
@minLength(1)
param webhookRole string

@description('Inference auth for Copilot model calls: pat (fine-grained user PAT, default) or app (GitHub App installation token).')
@allowed([ 'pat', 'app' ])
param inferenceAuthMode string = 'pat'
@description('pat mode: Key Vault secret name holding the fine-grained PAT (github_pat_). Must differ from the publisher secret.')
param inferencePatSecretName string = ''
@description('app mode only: dedicated inference GitHub App ID, distinct from publisher App.')
param inferenceAppId string = ''
@description('app mode only: inference GitHub App installation ID.')
param inferenceInstallationId string = ''
@description('app mode only: Key Vault secret name holding the inference App PEM.')
param inferenceKeySecretName string = ''
@minLength(1)
param publisherAppId string
@minLength(1)
param publisherBotLogin string
@description('Approved Copilot model name; verify organization availability in live gates.')
@minLength(1)
param copilotModel string

@description('Existing Log Analytics workspace (same resource group) that the worker may read for diagnostics. Empty grants nothing.')
param diagnosticsWorkspaceName string = ''

@description('Existing Container App names (same resource group) the worker may read for diagnostics (Reader, per app). Empty grants nothing.')
param diagnosticContainerAppNames array = []

@description('Name of the reviewed source-configuration blob in the sre-config container. Read by receiver and worker via managed identity.')
param sourceConfigBlobName string = 'sources.json'

@description('Storage table used for durable reconciler state.')
param stateTableName string = 'sreState'

@description('Service Bus queue that receiver enqueues to and worker consumes from.')
param queueName string = 'sre-incidents'

@description('Storage public network access. Set to Disabled only after private endpoints are added.')
@allowed([ 'Enabled', 'Disabled' ])
param storagePublicNetworkAccess string = 'Enabled'

@description('Receiver replica budget. Min 1 keeps the HTTPS endpoint warm.')
param receiverMinReplicas int = 1
param receiverMaxReplicas int = 2

@description('Worker replica budget. Min 1 keeps durable reconcilers running; raise maxReplicas to cap queue fan-out.')
param workerMinReplicas int = 1
param workerMaxReplicas int = 3

@description('Queue messages per worker replica before KEDA scales out.')
param workerQueueMessageCount int = 5

@description('Port the receiver listens on inside the container (SRE_PORT). Probes use /healthz and /readyz on this port.')
param receiverPort int = 8080

var uniqueSuffix = uniqueString(resourceGroup().id)

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

// Isolated per-role identities (no shared identity between receiver and worker).
resource receiverIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${namePrefix}-receiver-${uniqueSuffix}'
  location: location
  tags: tags
}

resource workerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${namePrefix}-worker-${uniqueSuffix}'
  location: location
  tags: tags
}

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    tags: tags
    namePrefix: namePrefix
  }
}

module messaging 'modules/messaging.bicep' = {
  name: 'messaging'
  params: {
    location: location
    tags: tags
    namePrefix: namePrefix
    queueName: queueName
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    tags: tags
    namePrefix: namePrefix
    tableName: stateTableName
    publicNetworkAccess: storagePublicNetworkAccess
  }
}

resource logWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: 'log-${namePrefix}'
  dependsOn: [
    monitoring
  ]
}

module rbac 'modules/rbac.bicep' = {
  name: 'rbac'
  params: {
    receiverPrincipalId: receiverIdentity.properties.principalId
    workerPrincipalId: workerIdentity.properties.principalId
    acrName: acr.name
    serviceBusNamespaceName: messaging.outputs.namespaceName
    queueName: messaging.outputs.queueName
    storageAccountName: storage.outputs.storageAccountName
    stateTableName: storage.outputs.stateTableName
    configContainerName: storage.outputs.configContainerName
    evidenceContainerName: storage.outputs.evidenceContainerName
    keyVaultName: keyVault.name
    diagnosticsWorkspaceName: diagnosticsWorkspaceName
    diagnosticContainerAppNames: diagnosticContainerAppNames
  }
}

var sourceConfigUrl = '${storage.outputs.blobEndpoint}${storage.outputs.configContainerName}/${sourceConfigBlobName}'

// Receiver env: enqueue only. No Key Vault, no state table, no evidence container.
var receiverEnv = [
  { name: 'SRE_WEBHOOK_AUDIENCE', value: webhookAudience }
  { name: 'SRE_MONITOR_APP_ID', value: monitorCallerAppId }
  { name: 'SRE_WEBHOOK_ROLE', value: webhookRole }
  { name: 'AZURE_SERVICEBUS_NAMESPACE', value: messaging.outputs.namespaceFqdn }
  { name: 'AZURE_SERVICEBUS_QUEUE_NAME', value: messaging.outputs.queueName }
  { name: 'SRE_SOURCE_CONFIG_URL', value: sourceConfigUrl }
  { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: monitoring.outputs.appInsightsConnectionString }
]

// Worker env: consume queue, durable state table, evidence container, Key Vault via SDK.
// Only the settings for the selected inference auth mode are emitted.
var inferenceEnv = inferenceAuthMode == 'pat'
  ? [
      { name: 'SRE_INFERENCE_PAT_SECRET', value: inferencePatSecretName }
    ]
  : [
      { name: 'SRE_INFERENCE_APP_ID', value: inferenceAppId }
      { name: 'SRE_INFERENCE_INSTALLATION_ID', value: inferenceInstallationId }
      { name: 'SRE_INFERENCE_KEY_SECRET', value: inferenceKeySecretName }
    ]

var workerEnv = concat(inferenceEnv, [
  { name: 'SRE_INFERENCE_AUTH_MODE', value: inferenceAuthMode }
  { name: 'SRE_INFERENCE_VAULT_URL', value: keyVault.properties.vaultUri }
  { name: 'SRE_PUBLISHER_APP_ID', value: publisherAppId }
  { name: 'SRE_PUBLISHER_BOT_LOGIN', value: publisherBotLogin }
  { name: 'SRE_MODEL', value: copilotModel }
  { name: 'AZURE_SERVICEBUS_NAMESPACE', value: messaging.outputs.namespaceFqdn }
  { name: 'AZURE_SERVICEBUS_QUEUE_NAME', value: messaging.outputs.queueName }
  { name: 'AZURE_STORAGE_TABLE_URL', value: storage.outputs.tableEndpoint }
  { name: 'SRE_STATE_TABLE_NAME', value: storage.outputs.stateTableName }
  { name: 'AZURE_STORAGE_BLOB_URL', value: storage.outputs.blobEndpoint }
  { name: 'SRE_EVIDENCE_CONTAINER_NAME', value: storage.outputs.evidenceContainerName }
  { name: 'SRE_SOURCE_CONFIG_URL', value: sourceConfigUrl }
  { name: 'AZURE_KEY_VAULT_URL', value: keyVault.properties.vaultUri }
  { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: monitoring.outputs.appInsightsConnectionString }
])

module containerApps 'modules/containerapps.bicep' = {
  name: 'containerapps'
  params: {
    location: location
    tags: tags
    namePrefix: namePrefix
    image: image
    acrLoginServer: acr.properties.loginServer
    logAnalyticsCustomerId: monitoring.outputs.workspaceCustomerId
    logAnalyticsSharedKey: logWorkspace.listKeys().primarySharedKey
    receiverIdentityId: receiverIdentity.id
    receiverClientId: receiverIdentity.properties.clientId
    workerIdentityId: workerIdentity.id
    workerClientId: workerIdentity.properties.clientId
    receiverEnv: receiverEnv
    workerEnv: workerEnv
    receiverPort: receiverPort
    receiverMinReplicas: receiverMinReplicas
    receiverMaxReplicas: receiverMaxReplicas
    workerMinReplicas: workerMinReplicas
    workerMaxReplicas: workerMaxReplicas
    workerQueueName: messaging.outputs.queueName
    workerServiceBusNamespaceName: messaging.outputs.namespaceName
    workerQueueMessageCount: workerQueueMessageCount
  }
  dependsOn: [
    rbac
  ]
}

output receiverFqdn string = containerApps.outputs.receiverFqdn
output receiverIdentityClientId string = receiverIdentity.properties.clientId
output workerIdentityClientId string = workerIdentity.properties.clientId
output serviceBusNamespace string = messaging.outputs.namespaceFqdn
output stateTableName string = storage.outputs.stateTableName
