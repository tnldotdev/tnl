package dns

import (
	"errors"
	"testing"
)

func TestManagedAddressCannotAdoptPublicURLOwnership(t *testing.T) {
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := route53TestPublicURL(client)
	record.Owner = ServiceOwner("svc_0123456789ABCDEFGHIJKL")
	for _, operation := range []func() error{
		func() error { _, err := provider.PublishAddress(t.Context(), record); return err },
		func() error { _, err := provider.RemoveAddress(t.Context(), record); return err },
	} {
		err := operation()
		var conflict *terminalError
		if !errors.As(err, &conflict) || len(client.changes) != 0 {
			t.Fatal("service adopted public URL DNS", err, client.changes)
		}
	}
	if record.Owner.marker() != `"tnl-service:svc_0123456789ABCDEFGHIJKL"` || PublicURLOwner("url").marker() != `"tnl-public-url:url"` {
		t.Fatal("DNS ownership identities were conflated")
	}
}
