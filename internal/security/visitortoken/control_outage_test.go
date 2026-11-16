package visitortoken

import (
	"strings"
	"testing"
	"time"
)

func TestLongPolicyRetainsEarlierCredentialAndParentExpiry(t *testing.T) {
	for _, kind := range []string{"workload", "registered key"} {
		t.Run(kind, func(t *testing.T) {
			key, permission, view, now := tokenFixture(t)
			view.ValidUntil = now.Add(10 * time.Minute)
			digest, err := KeyDigest(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(3 * time.Second)
			switch kind {
			case "workload":
				subject := Workload{SessionID: "wls_" + strings.Repeat("D", 22), KeySHA256: digest}
				permission.Subject = subject
				view = view.WithWorkloadLeases(map[string]WorkloadLease{subject.SessionID: {KeySHA256: digest, ExpiresAt: until}})
			case "registered key":
				subject := RegisteredKey{GrantID: "pgrant_" + strings.Repeat("E", 22), KeyID: "pkey_" + strings.Repeat("F", 22), KeySHA256: digest}
				permission.Subject = subject
				view = view.WithRegisteredKeyLeases(map[string]RegisteredKeyLease{subject.AuthorityID(): {KeySHA256: digest, ExpiresAt: until}})
			}
			token := issueToken(t, key, permission, view, now)
			if _, err := CheckConnectorPermission(token, view, now); err != nil {
				t.Fatal("long operator-selected policy rejected current authority", err)
			}
			if _, err := CheckConnectorPermission(token, view, until); err == nil {
				t.Fatal("long policy extended an expired parent")
			}
			removed := view.WithWorkloadLeases(nil).WithRegisteredKeyLeases(nil)
			if _, err := CheckConnectorPermission(token, removed, now.Add(time.Second)); err == nil {
				t.Fatal("learned parent removal retained permission")
			}
			permission.ExpiresAt = now.Add(time.Second)
			short := issueToken(t, key, permission, view, now)
			if _, err := CheckConnectorPermission(short, view, permission.ExpiresAt); err == nil {
				t.Fatal("long policy extended an expired credential")
			}
		})
	}
}
