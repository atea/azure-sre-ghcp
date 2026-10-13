// Service Bus Standard namespace with the incident queue and its dead-letter path.
// Dead-lettered messages stay in the queue's $DeadLetterQueue sub-queue for inspection.
// Local (SAS) auth is disabled; access is Entra RBAC only.

param location string
param tags object
param namePrefix string
param queueName string

@description('Message time-to-live. Messages not processed within this window expire and are dead-lettered.')
param messageTimeToLive string = 'P14D'

@description('Deliveries before a message is dead-lettered.')
@minValue(1)
@maxValue(100)
param maxDeliveryCount int = 10

resource namespace 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
  name: 'sb-${namePrefix}'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
  }
}

resource queue 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = {
  parent: namespace
  name: queueName
  properties: {
    deadLetteringOnMessageExpiration: true
    maxDeliveryCount: maxDeliveryCount
    lockDuration: 'PT1M'
    defaultMessageTimeToLive: messageTimeToLive
    requiresDuplicateDetection: true
    duplicateDetectionHistoryTimeWindow: 'PT10M'
    enablePartitioning: false
  }
}

output namespaceId string = namespace.id
output namespaceName string = namespace.name
output namespaceFqdn string = '${namespace.name}.servicebus.windows.net'
output queueName string = queue.name
