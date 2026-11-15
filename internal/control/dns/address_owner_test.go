package dns

import (
	"errors"
	"testing"
)

func TestServiceAddressCannotAdoptAnotherServiceOwnership(t *testing.T) {
	client, provider := route53TestProvider(t, "tunnels.example.test")
	record := route53TestService(client)
	record.Owner = ServiceOwner("svc_0123456789ABCDEFGHIJKL")
	for _, operation := range []func() error{
		func() error { _, err := provider.PublishAddress(t.Context(), record); return err },
		func() error { _, err := provider.RemoveAddress(t.Context(), record); return err },
	} {
		err := operation()
		var conflict *terminalError
		if !errors.As(err, &conflict) || len(client.changes) != 0 {
			t.Fatal("service adopted another service's DNS", err, client.changes)
		}
	}
	if record.Owner.marker() != `"tnl-service:svc_0123456789ABCDEFGHIJKL"` || ServiceOwner("svc_1").marker() != `"tnl-service:svc_1"` {
		t.Fatal("service DNS ownership markers changed")
	}
}

func TestServiceAddressMarkerRejectsInvalidOwners(t *testing.T) {
	for _, owner := range []AddressOwner{
		ServiceOwner(""),
		ServiceOwner("svc_bad\nvalue"),
		ServiceOwner("svc_bad\"value"),
		ServiceOwner("svc_bad\\value"),
		ServiceOwner("svc_" + string(make([]byte, 129))),
		{kind: "public-url", id: "old"},
	} {
		if marker := owner.marker(); marker != "" {
			t.Fatalf("invalid owner produced marker %q", marker)
		}
	}
}
