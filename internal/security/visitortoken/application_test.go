package visitortoken

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func applicationSubject(t *testing.T) Application {
	t.Helper()
	digest, err := KeyDigest(ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", 32))).Public())
	if err != nil {
		t.Fatal(err)
	}
	return Application{ClientID: opaqueid.PublisherIdentityPrefix + strings.Repeat("A", 22), GrantID: opaqueid.PublisherGrantPrefix + strings.Repeat("B", 22), KeyID: opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("C", 22), KeySHA256: digest}
}

func TestApplicationBearerRequiresExactCurrentGrantAndKey(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	subject := applicationSubject(t)
	permission.Subject = subject
	parent := ApplicationLease{Subject: subject, ExpiresAt: now.Add(time.Minute)}
	input := map[string]ApplicationLease{subject.GrantID: parent}
	view = view.WithApplicationLeases(input)
	delete(input, subject.GrantID)
	token := issueToken(t, key, permission, view, now)
	verified, err := VerifyBearer(token, view, now)
	if err != nil || verified.Facts().Subject != subject {
		t.Fatal("application bearer lost its exact subject", err)
	}
	if deadline := PermissionDeadline(verified, view); !deadline.Equal(parent.ExpiresAt) {
		t.Fatal("application permission ignored shorter parent expiry")
	}
	for _, fault := range []string{"missing", "client", "grant", "key", "digest", "expiry", "resource", "hostname", "port", "policy outage", "signing key"} {
		t.Run(fault, func(t *testing.T) {
			changed, lease := view, parent
			switch fault {
			case "missing":
				changed = changed.WithApplicationLeases(nil)
			case "client":
				lease.Subject.ClientID = "pub_" + strings.Repeat("D", 22)
			case "grant":
				lease.Subject.GrantID = opaqueid.PublisherGrantPrefix + strings.Repeat("D", 22)
			case "key":
				lease.Subject.KeyID = "pkey_" + strings.Repeat("D", 22)
			case "digest":
				lease.Subject.KeySHA256 = strings.Repeat("A", 43)
			case "expiry":
				lease.ExpiresAt = now
			case "resource":
				changed.Scope.ID = "url_" + strings.Repeat("D", 22)
			case "hostname":
				changed.Hostname = "other.example.test"
			case "port":
				changed.Port = 8443
			case "policy outage":
				changed.ValidUntil = now
			case "signing key":
				changed = changed.WithVerificationKeys(nil)
			}
			if fault != "missing" {
				changed = changed.WithApplicationLeases(map[string]ApplicationLease{subject.GrantID: lease})
			}
			if _, err := VerifyBearer(token, changed, now); err == nil {
				t.Fatal("application bearer crossed current authority boundary")
			}
			if err := CheckCurrent(verified, changed, now); err == nil {
				t.Fatal("admitted application escaped current authority")
			}
		})
	}
	view.VisitorPolicyRevision++
	if _, err := VerifyBearer(token, view, now); err != nil {
		t.Fatal("unrelated revision revoked an exact current application grant", err)
	}
	view.ObservedAt, view.ValidUntil = parent.ExpiresAt, parent.ExpiresAt.Add(PolicyLifetime)
	if _, err := VerifyBearer(token, view, parent.ExpiresAt); !errors.Is(err, ErrBinding) {
		t.Fatal("application outlived its current parent", err)
	}
}

func TestApplicationSubjectIsClosedAndBounded(t *testing.T) {
	subject := applicationSubject(t)
	encoded, err := encodeSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeSubject(encoded); err != nil || decoded != subject {
		t.Fatal("application subject did not round-trip", err)
	}
	for _, bad := range []Application{
		{}, {ClientID: subject.ClientID, GrantID: subject.GrantID, KeyID: subject.KeyID},
		{ClientID: subject.ClientID, GrantID: subject.GrantID, KeyID: "pgr_" + strings.Repeat("C", 22), KeySHA256: subject.KeySHA256},
	} {
		if _, err := encodeSubject(bad); !errors.Is(err, ErrToken) {
			t.Fatal("incomplete application subject serialized", err)
		}
	}
	if _, err := decodeSubject([]byte(`{"kind":"application","value":{"client_id":"` + subject.ClientID + `","grant_id":"` + subject.GrantID + `","key_id":"` + subject.KeyID + `","key_sha256":"` + subject.KeySHA256 + `","operation":"publish"}}`)); !errors.Is(err, ErrToken) {
		t.Fatal("unknown application facts were accepted", err)
	}
}
