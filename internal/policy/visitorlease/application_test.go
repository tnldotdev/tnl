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

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplicationPolicyKeepsExactGrantAcrossRevisionsAndStopsAtCurrentBoundary(t *testing.T) {
	for _, fault := range []string{"revoked", "rotated", "shortened", "outage"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, key := fixture(t)
				digest, _ := visitortoken.KeyDigest(key.Public().(ed25519.PublicKey))
				subject := visitortoken.Application{ClientID: opaqueid.PublisherIdentityPrefix + strings.Repeat("A", 22), GrantID: opaqueid.PublisherGrantPrefix + strings.Repeat("B", 22), KeyID: opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("C", 22), KeySHA256: digest}
				parent := visitortoken.ApplicationLease{Subject: subject, ExpiresAt: time.Now().Add(time.Minute)}
				update.View = update.View.WithApplicationLeases(map[string]visitortoken.ApplicationLease{subject.GrantID: parent})
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				view, _, _ := lease.Current()
				permission := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: subject, ExpiresAt: time.Now().Add(time.Minute)}
				token, err := visitortoken.Sign(view.Issuer, "first", key, permission, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				verified, err := visitortoken.VerifyBearer(token, view, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				var stopped atomic.Int64
				guard, err := lease.Bind(verified, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Close()
				if err := guard.AllowRenewal(); err != nil {
					t.Fatal(err)
				}
				for range 3 {
					time.Sleep(4 * time.Second)
					update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
					update.View.VisitorPolicyRevision++
					if err := lease.Apply(lease.Begin(), update); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				if stopped.Load() != 0 {
					t.Fatal("unrelated revisions revoked a current exact grant")
				}
				switch fault {
				case "revoked":
					update.View = update.View.WithApplicationLeases(nil)
				case "rotated":
					parent.Subject.KeyID = "pkey_" + strings.Repeat("D", 22)
					update.View = update.View.WithApplicationLeases(map[string]visitortoken.ApplicationLease{subject.GrantID: parent})
				case "shortened":
					parent.ExpiresAt = time.Now().Add(time.Second)
					update.View = update.View.WithApplicationLeases(map[string]visitortoken.ApplicationLease{subject.GrantID: parent})
				}
				if fault != "outage" {
					if err := lease.Apply(lease.Begin(), update); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "shortened" {
					time.Sleep(time.Second)
				} else if fault == "outage" {
					time.Sleep(visitortoken.PolicyLifetime)
				}
				synctest.Wait()
				if stopped.Load() != 1 {
					t.Fatal("current authority boundary did not stop traffic exactly once")
				}
			})
		})
	}
}

func TestDecodeApplicationLeasesRejectsAmbiguousOrIncompleteFacts(t *testing.T) {
	for _, fault := range []string{"valid", "duplicate", "client", "grant", "key", "digest", "expiry", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			now := time.Now()
			body := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}, Port: 443, ApplicationLeases: []controlv1.VisitorApplicationLease{{ClientId: "pub_" + strings.Repeat("A", 22), GrantId: opaqueid.PublisherGrantPrefix + strings.Repeat("B", 22), KeyId: "pkey_" + strings.Repeat("C", 22), KeySha256: strings.Repeat("A", 43), ExpiresAt: now.Add(time.Minute)}}}}
			parent := &body.Policy.ApplicationLeases[0]
			switch fault {
			case "duplicate":
				body.Policy.ApplicationLeases = append(body.Policy.ApplicationLeases, *parent)
			case "client":
				parent.ClientId = "invalid"
			case "grant":
				parent.GrantId = "invalid"
			case "key":
				parent.KeyId = "invalid"
			case "digest":
				parent.KeySha256 = "invalid"
			case "expiry":
				parent.ExpiresAt = time.Time{}
			case "overflow":
				body.Policy.ApplicationLeases = make([]controlv1.VisitorApplicationLease, 257)
			}
			update, err := Decode(body)
			if fault == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				parent.GrantId = "mutated"
				if !update.View.ValidApplicationLeases() {
					t.Fatal("wire mutation changed immutable application leases")
				}
			} else if !errors.Is(err, ErrUpdate) {
				t.Fatal("invalid application projection decoded", err)
			}
		})
	}
}
