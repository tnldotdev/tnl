package visitortoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativePeerSessionRequiresAttestationAndCurrentVisitorPermission(t *testing.T) {
	controlKey, permission, view, now := tokenFixture(t)
	visitor := ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", 32)))
	public := visitor.Public().(ed25519.PublicKey)
	digest, err := KeyDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	permission.Scope, permission.Port = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}, 5432
	view.Scope, view.Port, view.MetadataRevision = permission.Scope, permission.Port, 5
	initial := []byte("first client bytes")
	for name, subject := range map[string]Subject{
		"device":   Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22), DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: digest},
		"workload": Workload{SessionID: "wls_" + strings.Repeat("D", 22), KeySHA256: digest},
	} {
		t.Run(name, func(t *testing.T) {
			permission.Subject = subject
			current := view
			if workload, ok := subject.(Workload); ok {
				current = current.WithWorkloadLeases(map[string]WorkloadLease{workload.SessionID: {KeySHA256: digest, ExpiresAt: permission.ExpiresAt}})
			}
			peer, err := NativeSubject(subject)
			if err != nil {
				t.Fatal(err)
			}
			token := issueToken(t, controlKey, permission, current, now)
			entry := tunnelv1.NativePeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.NativePeerVisitorStream,
				PairID: "npp_" + strings.Repeat("P", 22), DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 3,
				ServiceID: permission.Scope.ID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 4,
				Subject: peer, SourceIP: "192.0.2.10", VisitorConnectionID: "vc_" + strings.Repeat("V", 22), MetadataRevision: 5,
				Permission: tunnelv1.NativeVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(public)}}
			sign := func(e *tunnelv1.NativePeerVisitorEntry, data []byte) {
				t.Helper()
				e.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				message, err := tunnelv1.NativePeerProofMessage(*e, data)
				if err != nil {
					t.Fatal(err)
				}
				e.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(visitor, message))
			}
			sign(&entry, initial)
			expected := entry.Session()
			expected.ExpiresAt = now.Add(time.Minute)
			if verified, err := VerifyNativePeerSession(entry, initial, expected, current, now); err != nil || !verified.Valid() || verified.Facts().Subject != subject {
				t.Fatal("current native peer proof was rejected", err)
			}
			// each signed field must fail, even when the caller's expected facts
			// change to match the altered entry (the signature is still over the old bytes).
			for field, change := range map[string]func(*tunnelv1.NativePeerVisitorEntry){
				"pair":       func(e *tunnelv1.NativePeerVisitorEntry) { e.PairID = "npp_" + strings.Repeat("Q", 22) },
				"delivery":   func(e *tunnelv1.NativePeerVisitorEntry) { e.DeliveryID = "AgICAgICAgICAgICAgICAg" },
				"generation": func(e *tunnelv1.NativePeerVisitorEntry) { e.DeliveryGeneration++ },
				"service":    func(e *tunnelv1.NativePeerVisitorEntry) { e.ServiceID = "svc_" + strings.Repeat("Z", 22) },
				"run":        func(e *tunnelv1.NativePeerVisitorEntry) { e.ServiceRunID = "srun_" + strings.Repeat("Z", 22) },
				"run number": func(e *tunnelv1.NativePeerVisitorEntry) { e.RunNumber++ },
				"subject": func(e *tunnelv1.NativePeerVisitorEntry) {
					if e.Subject.Kind == tunnelv1.VisitorHumanDevice {
						e.Subject.DeviceID = "vdev_" + strings.Repeat("Z", 22)
					} else {
						e.Subject.WorkloadSessionID = "wls_" + strings.Repeat("Z", 22)
					}
				},
				"visitor":  func(e *tunnelv1.NativePeerVisitorEntry) { e.VisitorConnectionID = "vc_" + strings.Repeat("Z", 22) },
				"metadata": func(e *tunnelv1.NativePeerVisitorEntry) { e.MetadataRevision++ },
				"token": func(e *tunnelv1.NativePeerVisitorEntry) {
					e.Permission.Token = issueToken(t, controlKey, permission, current, now).Reveal()
				},
				"source": func(e *tunnelv1.NativePeerVisitorEntry) { e.SourceIP = "192.0.2.11" },
			} {
				t.Run(field, func(t *testing.T) {
					changed := entry
					change(&changed)
					changedFacts := changed.Session()
					changedFacts.ExpiresAt = expected.ExpiresAt
					if _, err := VerifyNativePeerSession(changed, initial, changedFacts, current, now); err == nil {
						t.Fatal("modified signed field passed admission")
					}
				})
			}
			for field, changed := range map[string]tunnelv1.NativePeerSession{
				"expired pair":          func() tunnelv1.NativePeerSession { s := expected; s.ExpiresAt = now; return s }(),
				"missing pair deadline": func() tunnelv1.NativePeerSession { s := expected; s.ExpiresAt = time.Time{}; return s }(),
				"wrong source":          func() tunnelv1.NativePeerSession { s := expected; s.SourceIP = "192.0.2.11"; return s }(),
				"wrong subject": func() tunnelv1.NativePeerSession {
					s := expected
					s.Subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: "wls_" + strings.Repeat("Z", 22)}
					return s
				}(),
				"wrong run": func() tunnelv1.NativePeerSession { s := expected; s.RunNumber++; return s }(),
				"wrong pair": func() tunnelv1.NativePeerSession {
					s := expected
					s.PairID = "npp_" + strings.Repeat("Z", 22)
					return s
				}(),
			} {
				t.Run(field, func(t *testing.T) {
					if _, err := VerifyNativePeerSession(entry, initial, changed, current, now); !errors.Is(err, ErrBinding) {
						t.Fatal("opening field became attestation", err)
					}
				})
			}
			if _, err := VerifyNativePeerSession(entry, []byte("changed bytes"), expected, current, now); !errors.Is(err, ErrBinding) {
				t.Fatal("initial bytes not signed", err)
			}
			wrong := entry
			wrong.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(controlKey.Public().(ed25519.PublicKey))
			if _, err := VerifyNativePeerSession(wrong, initial, expected, current, now); !errors.Is(err, ErrBinding) {
				t.Fatal("wrong native key accepted", err)
			}
			for _, changed := range []View{
				func() View { v := current; v.VisitorPolicyRevision++; return v }(),
				func() View { v := current; v.ValidUntil = now; return v }(),
				func() View { v := current; v.MetadataRevision++; return v }(),
				func() View { v := current; v.Scope.ID = "svc_" + strings.Repeat("Z", 22); return v }(),
			} {
				if verified, err := VerifyNativePeerSession(entry, initial, expected, changed, now); err == nil || verified.Valid() {
					t.Fatal("stale or mismatched view admitted visitor", err)
				}
			}
			for _, guest := range []Subject{
				Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)},
				Share{ShareID: "shr_" + strings.Repeat("S", 22)},
			} {
				other := permission
				other.Subject = guest
				changed := entry
				changed.Permission.Token = issueToken(t, controlKey, other, current, now).Reveal()
				sign(&changed, initial)
				if verified, err := VerifyNativePeerSession(changed, initial, expected, current, now); !errors.Is(err, ErrBinding) || verified.Valid() {
					t.Fatal("guest or browser permission admitted native peer", err)
				}
			}
			// a correct carrier key and signed proof still need a signed control token.
			changed := entry
			changed.Permission.Token = "pair-key-only"
			sign(&changed, initial)
			if verified, err := VerifyNativePeerSession(changed, initial, expected, current, now.Add(time.Second)); err == nil || verified.Valid() {
				t.Fatal("pair key became visitor permission", err)
			}
		})
	}
}
