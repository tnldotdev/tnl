package visitorlease

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPolicyDecodeRequiresServiceScopeAndExactPort(t *testing.T) {
	service := controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}
	for _, test := range []struct {
		name     string
		resource controlv1.VisitorResourceScope
		port     int
		valid    bool
	}{
		{"shared HTTPS", service, 443, true},
		{"dedicated HTTPS", service, 8443, true},
		{"non-HTTP", service, 5432, true},
		{"connector-only", service, 0, true},
		{"maximum port", service, 65535, true},
		{"negative port", service, -1, false},
		{"oversized port", service, 65536, false},
		{"retired scope", controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}, 443, false},
		{"retired kind", controlv1.VisitorResourceScope{Kind: "public_url", Id: service.Id}, 443, false},
		{"retired ID", controlv1.VisitorResourceScope{Kind: "service", Id: "url_" + strings.Repeat("A", 22)}, 443, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: test.resource, Port: test.port}}
			update, err := Decode(body)
			if !test.valid {
				if !errors.Is(err, ErrUpdate) {
					t.Fatal("invalid service policy did not fail closed", err)
				}
				return
			}
			if err != nil || update.View.Scope != (visitorscope.Scope{Kind: visitorscope.Service, ID: service.Id}) || int(update.View.Port) != test.port {
				t.Fatal("service policy changed its exact scope or endpoint port", err)
			}
		})
	}
}

func TestServicePolicyConnectionDeadlineFencesWithoutVisitorPermission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		until := now.Add(3 * time.Second)
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
		scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("a", 22)}
		body := controlv1.VisitorPolicyUpdate{SnapshotRequired: true, Policy: controlv1.VisitorPolicySnapshot{
			Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID},
			Issuer:   "https://control.example.test", Hostname: "demo.example.test", Port: 443,
			Enabled: true, VisitorPolicyRevision: 1, KeyRevision: 1, MetadataRevision: 1,
			ObservedAt: now, ValidUntil: until, ConnectionDeadline: &until,
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "first", PublicKey: key.Public().(ed25519.PublicKey)}},
		}}
		update, err := Decode(body)
		if err != nil || !update.BoundConnections {
			t.Fatal("service deadline could not reach its connection guard", err)
		}
		lease, err := New(scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.BindConnection(func() { stopped.Add(1) })
		if err != nil || guard == nil {
			t.Fatal("fixed policy did not bind the idle connection", err)
		}
		defer guard.Close()
		if _, err := lease.BindAnonymous(netip.MustParseAddr("192.0.2.1"), func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
			t.Fatal("a connection deadline granted visitor permission", err)
		}
		for _, invalid := range []time.Time{{}, until.Add(-time.Nanosecond)} {
			body.Policy.ConnectionDeadline = &invalid
			if _, err := Decode(body); !errors.Is(err, ErrUpdate) {
				t.Fatal("policy outlived its declared fixed deadline", err)
			}
		}
		body.Policy.ConnectionDeadline = nil
		ordinary, err := Decode(body)
		if err != nil || ordinary.BoundConnections {
			t.Fatal("ordinary policy acquired a connection deadline", err)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("idle service connection outlived its fixed policy")
		}
		if _, err := lease.BindConnection(func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
			t.Fatal("expired policy admitted another connection", err)
		}
	})
}
