package target

// IntegrationTarget names an in-process handler, not an app listener or a
// separate saved resource. changing this descriptor is explicit configuration.
type IntegrationTarget string

const (
	OAuthIntegration   IntegrationTarget = "integration:oauth"
	WebhookIntegration IntegrationTarget = "integration:webhooks"
)

func (target IntegrationTarget) Valid() bool {
	return target == OAuthIntegration || target == WebhookIntegration
}
