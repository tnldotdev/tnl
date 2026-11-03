package main

import (
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestWebhookSchemaUsesDeclaredProviders(t *testing.T) {
	provider, ok := webhookSchema().Properties.Get("provider")
	if !ok || provider.Type != "string" || len(provider.Enum) != 23 {
		t.Fatalf("provider schema = %+v", provider)
	}
	for _, value := range provider.Enum {
		name, ok := value.(string)
		if !ok || !controlv1.WebhookProvider(name).Valid() {
			t.Fatalf("provider %v is not in the control contract", value)
		}
	}
}
