package state

import (
	"errors"
	"testing"
	"time"
)

func TestPublisherPublicURLAllocationRequiresExplicitAccessMode(t *testing.T) {
	d := &Database{}
	p := PublisherIdentity{Scope: PublisherScope{Kind: "namespace"}}
	for _, mode := range []VisitorAccessMode{"", "unknown"} {
		if _, err := d.AllocatePublisherPublicURL(t.Context(), p, "invocation", "http://localhost:3000", nil, nil, time.Now(), PublisherPublicURLOptions{AccessMode: mode}); !errors.Is(err, ErrPublicURLInvalid) {
			t.Fatalf("access mode %q = %v; want invalid public URL without consulting storage", mode, err)
		}
	}
}
