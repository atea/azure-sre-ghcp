// Container Apps environment plus the two apps built from the same image:
//   receiver: HTTPS external ingress on receiverPort, /healthz liveness and /readyz readiness.
//   worker:   no ingress, scaled by Service Bus queue depth (KEDA azure-servicebus).
// Each app runs under its own user-assigned managed identity and pulls the image from ACR
// through that identity. No Key Vault secret references are configured: the app loads
// secrets at runtime through the Key Vault SDK with its managed identity.

param location string
param tags object
param namePrefix string

param image string
param acrLoginServer string
param logAnalyticsCustomerId string
@secure()
param logAnalyticsSharedKey string

param receiverIdentityId string
param receiverClientId string
param workerIdentityId string
param workerClientId string

@description('Non-secret environment for the receiver role.')
param receiverEnv array

@description('Non-secret environment for the worker role.')
param workerEnv array

param receiverPort int = 8080
param receiverMinReplicas int = 1
param receiverMaxReplicas int = 2
param workerMinReplicas int = 1
param workerMaxReplicas int = 3
param workerQueueName string
@description('Service Bus namespace NAME (not the FQDN) as required by the KEDA azure-servicebus scaler.')
param workerServiceBusNamespaceName string
param workerQueueMessageCount int = 5

// Newest stable Microsoft.App API that declares scale-rule identity (no BCP037 suppression needed).
var containerAppsApiVersion = '2025-01-01'

resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: 'cae-${namePrefix}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsCustomerId
        sharedKey: logAnalyticsSharedKey
      }
    }
    zoneRedundant: false
  }
}

resource receiver 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'ca-${namePrefix}-recv'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${receiverIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: receiverPort
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          identity: receiverIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'receiver'
          image: image
          args: [ 'receiver' ]
          env: concat(receiverEnv, [
            { name: 'AZURE_CLIENT_ID', value: receiverClientId }
            { name: 'SRE_ROLE', value: 'receiver' }
            { name: 'SRE_PORT', value: string(receiverPort) }
          ])
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: receiverPort, scheme: 'HTTP' }
              initialDelaySeconds: 10
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: { path: '/readyz', port: receiverPort, scheme: 'HTTP' }
              initialDelaySeconds: 5
              periodSeconds: 10
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: receiverMinReplicas
        maxReplicas: receiverMaxReplicas
        rules: [
          {
            name: 'http-concurrency'
            http: {
              metadata: {
                concurrentRequests: '20'
              }
            }
          }
        ]
      }
    }
  }
}

resource worker 'Microsoft.App/containerApps@2025-01-01' = {
  name: 'ca-${namePrefix}-wrk'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${workerIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: null
      registries: [
        {
          server: acrLoginServer
          identity: workerIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'worker'
          image: image
          args: [ 'worker' ]
          env: concat(workerEnv, [
            { name: 'AZURE_CLIENT_ID', value: workerClientId }
            { name: 'SRE_ROLE', value: 'worker' }
          ])
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: workerMinReplicas
        maxReplicas: workerMaxReplicas
        rules: [
          {
            name: 'sb-queue-depth'
            custom: {
              type: 'azure-servicebus'
              metadata: {
                namespace: workerServiceBusNamespaceName
                queueName: workerQueueName
                messageCount: string(workerQueueMessageCount)
              }
              identity: workerIdentityId
            }
          }
        ]
      }
    }
  }
}

output environmentId string = environment.id
output containerAppsApiVersion string = containerAppsApiVersion
output receiverFqdn string = receiver.properties.configuration.ingress.fqdn
output workerName string = worker.name
