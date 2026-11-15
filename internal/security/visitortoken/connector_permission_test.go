package visitortoken

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestCheckConnectorPermissionReturnsOnlyCurrentSignedFacts(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	permission.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	view.Scope = permission.Scope
	digest, err := KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []Subject{
		Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22), DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: digest},
		Workload{SessionID: "wls_" + strings.Repeat("D", 22), KeySHA256: digest},
		RegisteredKey{GrantID: "pgrant_" + strings.Repeat("E", 22), KeyID: "pkey_" + strings.Repeat("F", 22), KeySHA256: digest},
	} {
		t.Run(subject.visitorSubject(), func(t *testing.T) {
			permission.Subject = subject
			current := view
			switch s := subject.(type) {
			case Workload:
				current = current.WithWorkloadLeases(map[string]WorkloadLease{s.SessionID: {KeySHA256: digest, ExpiresAt: now.Add(time.Minute)}})
			case RegisteredKey:
				current = current.WithRegisteredKeyLeases(map[string]RegisteredKeyLease{s.AuthorityID(): {KeySHA256: digest, ExpiresAt: now.Add(time.Minute)}})
			}
			token := issueToken(t, key, permission, current, now)
			facts, err := CheckConnectorPermission(token, current, now)
			if err != nil || facts.Subject != subject || facts.Scope != permission.Scope || facts.SigningKeyID != "key-one" {
				t.Fatal("current connector facts rejected", err)
			}
			if _, err := VerifyBearer(token, current, now); err == nil {
				t.Fatal("connector token became bearer evidence")
			}
			for name, change := range map[string]func(*View){
				"policy": func(v *View) { v.VisitorPolicyRevision++ },
				"key":    func(v *View) { *v = v.WithVerificationKeys(nil) },
				"signature": func(v *View) {
					*v = v.WithVerificationKeys(map[string]ed25519.PublicKey{"key-one": ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))).Public().(ed25519.PublicKey)})
				},
				"service": func(v *View) { v.Scope.ID = "svc_" + strings.Repeat("Z", 22) },
				"parents": func(v *View) { *v = v.WithWorkloadLeases(nil).WithRegisteredKeyLeases(nil) },
			} {
				if name == "parents" && subject.visitorSubject() == "device" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					changed := current
					change(&changed)
					if _, err := CheckConnectorPermission(token, changed, now); err == nil {
						t.Fatal("invalid connector facts accepted")
					}
				})
			}
			if _, err := CheckConnectorPermission(token, current, now.Add(PolicyLifetime)); err == nil {
				t.Fatal("expired policy accepted")
			}
			expired := permission
			expired.ExpiresAt = now.Add(time.Second)
			if _, err := CheckConnectorPermission(issueToken(t, key, expired, current, now), current, now.Add(time.Second)); err == nil {
				t.Fatal("expired permission accepted")
			}
		})
	}
	for _, subject := range []Subject{
		Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)},
		Share{ShareID: "shr_" + strings.Repeat("C", 22)},
		Grant{GrantID: "shg_" + strings.Repeat("D", 22), Kind: "token"},
		Certificate{Serial: "abc", KeySHA256: digest, Source: Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22), DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: digest}},
	} {
		t.Run("not-connector-"+subject.visitorSubject(), func(t *testing.T) {
			permission.Subject = subject
			if _, err := CheckConnectorPermission(issueToken(t, key, permission, view, now), view, now); err == nil {
				t.Fatal("non-connector subject accepted")
			}
		})
	}
}
