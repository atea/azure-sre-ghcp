using '../main.bicep'

param namePrefix = 'sredev'
param location = 'swedencentral'
param tags = {
  workload: 'azure-sre-copilot'
  environment: 'dev'
}

// Existing resources supplied out of band (not created here).
param acrName = '<existing-acr-name>'
param keyVaultName = '<existing-key-vault-name>'
param image = '<acr-login-server>/azure-sre-copilot:<tag-or-digest>'
param webhookAudience = '<approved-api-audience>'
param monitorCallerAppId = '00000000-0000-0000-0000-000000000000'
param webhookRole = '<assigned-application-role>'
param inferenceAppId = '<inference-github-app-id>'
param inferenceInstallationId = '<inference-installation-id>'
param inferenceKeySecretName = '<inference-pem-secret-name>'
param publisherAppId = '<separate-publisher-github-app-id>'
param publisherBotLogin = '<publisher-app-slug>[bot]'
param copilotModel = '<approved-copilot-model>'

// Leave empty unless the diagnostics workspace is explicitly approved for worker read access.
param diagnosticsWorkspaceName = ''

// Existing Container Apps (same resource group) the worker may read. Empty grants nothing.
param diagnosticContainerAppNames = []

param workerMinReplicas = 1
param workerMaxReplicas = 3
param receiverMinReplicas = 1
param receiverMaxReplicas = 2
