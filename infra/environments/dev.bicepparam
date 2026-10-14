using '../main.bicep'

param namePrefix = 'sredev'
param location = 'swedencentral'
param tags = {
  workload: 'azure-sre-copilot'
  environment: 'dev'
}

// Existing resources supplied out of band (not created here).
param acrName = 'ghcpsreacr'
param keyVaultName = 'ghcpsrekv'
param image = 'ghcpsreacr.azurecr.io/azure-sre-copilot:<tag-or-digest>'
param webhookAudience = '789a0e7b-12ac-4de1-97bc-29c392ea8e53/ActionGroupsSecureWebhook'
param monitorCallerAppId = 'b57d1b8d-74bb-4a59-a763-712211091862'
param webhookRole = 'ActionGroupsSecureWebhook'
// Inference auth: 'pat' (default) uses a fine-grained user PAT stored in Key Vault.
// Switch to 'app' and fill the inferenceApp* params to use a GitHub App installation token.
param inferenceAuthMode = 'pat'
param inferencePatSecretName = 'githubcopilotpat'
param publisherAppId = '5308134'
param publisherBotLogin = 'GHCopilotSREAgent[bot]'
param copilotModel = 'gpt-6-luna'

// Leave empty unless the diagnostics workspace is explicitly approved for worker read access.
param diagnosticsWorkspaceName = ''

// Existing Container Apps (same resource group) the worker may read. Empty grants nothing.
param diagnosticContainerAppNames = ['ca-demoapp1-v2ho77']

param workerMinReplicas = 1
param workerMaxReplicas = 3
param receiverMinReplicas = 1
param receiverMaxReplicas = 2
