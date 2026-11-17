package visitorlease

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// the explicit wire fixture is intentionally not the old signed-permission
// profile: identity attests the fixed certificate, not current visitor access.
func workloadIdentityEvidence(t *testing.T, update Update, key ed25519.PrivateKey, until time.Time, legacy bool) visitortoken.VerifiedPermission {
	t.Helper()
	view := update.View
	digest, err := visitortoken.KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	subject := visitortoken.Certificate{Serial: "1", KeySHA256: digest,
		Source: visitortoken.Workload{SessionID: "wls_" + strings.Repeat("W", 22), KeySHA256: digest}}
	var token visitortoken.Token
	if legacy {
		token, err = visitortoken.Sign(view.Issuer, "first", key, visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname,
			Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: subject, ExpiresAt: until}, time.Now())
	} else {
		var payload []byte
		payload, err = json.Marshal(map[string]any{"jti": base64.RawURLEncoding.EncodeToString(make([]byte, 16)), "version": 1,
			"iss": view.Issuer, "scope": view.Scope, "hostname": view.Hostname, "port": view.Port,
			"iat": time.Now().Unix(), "exp": until.Unix(),
			"visitor": map[string]any{"kind": "certificate", "value": subject}})
		if err == nil {
			var signer jose.Signer
			signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
				(&jose.SignerOptions{}).WithType("tnl-workload-identity+jwt").WithHeader("kid", "first"))
			if err == nil {
				var signed *jose.JSONWebSignature
				signed, err = signer.Sign(payload)
				if err == nil {
					var raw string
					raw, err = signed.CompactSerialize()
					token = visitortoken.Token(raw)
				}
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	uri, err := visitortoken.CertificateURI(token)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), PublicKey: key.Public(), NotBefore: time.Now().Add(-time.Second),
		NotAfter: until, URIs: []*url.URL{uri}}
	permission, err := visitortoken.VerifyCertificate(token, view, tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}, time.Now())
	if err != nil {
		t.Fatal("distinct workload identity did not obtain current short permission", err)
	}
	return permission
}

func workloadIdentityPolicy(update Update, key ed25519.PrivateKey, until time.Time) Update {
	digest, _ := visitortoken.KeyDigest(key.Public())
	update.View = update.View.WithWorkloadLeases(map[string]visitortoken.WorkloadLease{
		"wls_" + strings.Repeat("W", 22): {KeySHA256: digest, ExpiresAt: until},
	})
	return update
}

func TestWorkloadIdentityGuardRenewsCurrentPermissionNotFixedCredential(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		start := time.Now()
		certificateExpiry := start.Add(180 * time.Second)
		update.View.ValidUntil = start.Add(5 * time.Minute)
		update = workloadIdentityPolicy(update, key, start.Add(90*time.Second))
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		current, _, _ := lease.Current()
		update.View = current
		var identityStopped, legacyStopped atomic.Int32
		identity, err := lease.Bind(workloadIdentityEvidence(t, update, key, certificateExpiry, false),
			netip.MustParseAddr("192.0.2.1"), func() { identityStopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer identity.Close()
		legacy, err := lease.Bind(workloadIdentityEvidence(t, update, key, start.Add(90*time.Second), true),
			netip.MustParseAddr("192.0.2.1"), func() { legacyStopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer legacy.Close()
		for round := range 5 {
			time.Sleep(30 * time.Second)
			update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(5*time.Minute)
			if round >= 3 {
				update.View.VisitorPolicyRevision++
			}
			update = workloadIdentityPolicy(update, key, time.Now().Add(90*time.Second))
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			if identityStopped.Load() != 0 {
				t.Fatal("fresh exact-workload policy did not renew the original identity guard", round)
			}
			if round < 2 && legacyStopped.Load() != 0 || round >= 2 && legacyStopped.Load() != 1 {
				t.Fatal("fixed signed permission did not retain its original ninety-second fence", round)
			}
		}
		if legacyStopped.Load() != 1 {
			t.Fatal("old signed permission acquired renewable identity semantics")
		}
		time.Sleep(time.Until(certificateExpiry))
		synctest.Wait()
		if identityStopped.Load() != 1 {
			t.Fatal("workload renewal moved the original certificate expiry")
		}
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(5*time.Minute)
		update = workloadIdentityPolicy(update, key, time.Now().Add(90*time.Second))
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if identityStopped.Load() != 1 || identity.AllowRenewal() == nil || legacy.AllowRenewal() == nil {
			t.Fatal("fresh policy revived an expired guard")
		}
	})
}

func TestWorkloadIdentityGuardEarlierAuthorityWins(t *testing.T) {
	for _, fault := range []string{"permission outage", "provider proof", "policy expiry", "revocation", "selection removal", "wrong session", "wrong key", "wrong service", "wrong endpoint", "signing key revoked"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, key := fixture(t)
				start := time.Now()
				deadline := start.Add(90 * time.Second)
				update.View.ValidUntil = start.Add(5 * time.Minute)
				if fault == "provider proof" {
					deadline = start.Add(40 * time.Second)
				}
				if fault == "policy expiry" {
					update.View.ValidUntil = start.Add(20 * time.Second)
					deadline = update.View.ValidUntil
				}
				update = workloadIdentityPolicy(update, key, earlier(deadline, start.Add(90*time.Second)))
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				current, _, _ := lease.Current()
				update.View = current
				var stopped atomic.Int32
				guard, err := lease.Bind(workloadIdentityEvidence(t, update, key, start.Add(time.Hour), false),
					netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Close()
				time.Sleep(10 * time.Second)
				switch fault {
				case "revocation", "selection removal":
					update.View = update.View.WithWorkloadLeases(nil)
				case "wrong session":
					digest, _ := visitortoken.KeyDigest(key.Public())
					update.View = update.View.WithWorkloadLeases(map[string]visitortoken.WorkloadLease{
						"wls_" + strings.Repeat("X", 22): {KeySHA256: digest, ExpiresAt: deadline}})
				case "wrong key":
					other := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32)))
					update = workloadIdentityPolicy(update, other, deadline)
				case "wrong endpoint":
					update.View.Hostname = "other.example.test"
				case "signing key revoked":
					update.View = update.View.WithVerificationKeys(nil)
				case "wrong service":
					update.View.Scope.ID = "svc_" + strings.Repeat("B", 22)
				}
				switch fault {
				case "permission outage", "provider proof", "policy expiry":
					// failed/missing refresh installs no new evidence.
				default:
					update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(5*time.Minute)
					err := lease.Apply(lease.Begin(), update)
					if fault == "wrong service" {
						if err == nil || stopped.Load() != 0 {
							t.Fatal("another service's update changed the retained authority", err)
						}
					} else {
						if err != nil || stopped.Load() != 1 {
							t.Fatal("fresh refusal did not retire the exact original guard", err)
						}
						return
					}
				}
				time.Sleep(time.Until(deadline.Add(-time.Nanosecond)))
				if stopped.Load() != 0 {
					t.Fatal("guard ended before its actual earlier authority fence")
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if stopped.Load() != 1 {
					t.Fatal("long certificate or five-minute outage allowance extended short permission")
				}
			})
		})
	}
}

func TestWorkloadIdentityPolicyCannotReviveGuardBeforeExpiryTimerRuns(t *testing.T) {
	lease, update, key := fixture(t)
	now := time.Now().Truncate(time.Second)
	lease.now = func() time.Time { return now }
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(5*time.Minute)
	update = workloadIdentityPolicy(update, key, now.Add(90*time.Second))
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Int32
	guard, err := lease.Bind(workloadIdentityEvidence(t, update, key, now.Add(time.Hour), false),
		netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	now = now.Add(90 * time.Second)
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(5*time.Minute)
	update = workloadIdentityPolicy(update, key, now.Add(90*time.Second))
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if stopped.Load() != 1 || guard.AllowRenewal() == nil {
		t.Fatal("fresh control evidence revived a guard whose old permission had expired")
	}
}

func TestWorkloadIdentityFreshPolicyCannotRecoverSpentPermissionLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, key := fixture(t)
		first := lease.Begin()
		control := first.StartedAt.Add(time.Second)
		expires := control.Add(4 * time.Second)
		update.View.ObservedAt, update.View.ValidUntil = control, control.Add(5*time.Minute)
		update = workloadIdentityPolicy(update, key, expires)
		time.Sleep(2 * time.Second)
		if err := lease.Apply(first, update); err != nil {
			t.Fatal(err)
		}
		update.View, _, _ = lease.Current()
		var stopped atomic.Int32
		guard, err := lease.Bind(workloadIdentityEvidence(t, update, key, control.Add(180*time.Second), false),
			netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(time.Second)
		update.View.ObservedAt = first.StartedAt.Add(3500 * time.Millisecond)
		update.View.ValidUntil = update.View.ObservedAt.Add(5 * time.Minute)
		update = workloadIdentityPolicy(update, key, expires)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("faster policy response extended an unchanged absolute workload permission")
		}
		if guard.AllowRenewal() == nil {
			t.Fatal("fresh policy revived a guard after its accepted local deadline")
		}
	})
}
