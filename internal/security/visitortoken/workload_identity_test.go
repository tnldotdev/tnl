package visitortoken

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func identityFixture(t *testing.T) (ed25519.PrivateKey, WorkloadIdentity, Token, View, tls.ConnectionState, time.Time) {
	t.Helper()
	key, permission, view, now := tokenFixture(t)
	digest, err := KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{Issuer: view.Issuer, Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port,
		Certificate: Certificate{Serial: "1", KeySHA256: digest, Source: Workload{SessionID: "wls_" + strings.Repeat("W", 22), KeySHA256: digest}},
		ExpiresAt:   now.Add(time.Hour)}
	token, err := SignWorkloadIdentity(view.Issuer, "key-one", key, identity, now)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := CertificateURI(token)
	if err != nil {
		t.Fatal(err)
	}
	view.ValidUntil = now.Add(5 * time.Minute)
	view = view.WithWorkloadLeases(map[string]WorkloadLease{identity.Certificate.Source.(Workload).SessionID: {
		KeySHA256: digest, ExpiresAt: now.Add(90 * time.Second),
	}})
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{{
		PublicKey: key.Public(), SerialNumber: big.NewInt(1), URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Second), NotAfter: identity.ExpiresAt,
	}}}
	return key, identity, token, view, state, now
}

func TestWorkloadIdentitySeparatesFixedCredentialFromCurrentPermission(t *testing.T) {
	key, identity, token, view, state, now := identityFixture(t)
	permission, err := VerifyCertificate(token, view, state, now)
	if err != nil || !permission.Facts().ExpiresAt.Equal(now.Add(90*time.Second)) {
		t.Fatal("identity became its own long permission", err)
	}
	current, ok := permission.WorkloadPermission()
	if !ok || current.Identity() != (WorkloadIdentity{Issuer: view.Issuer, SigningKeyID: "key-one", Scope: identity.Scope,
		Hostname: identity.Hostname, Port: identity.Port, Certificate: identity.Certificate, ExpiresAt: identity.ExpiresAt}) {
		t.Fatal("verified identity lost its exact signed binding")
	}
	for _, verify := range []func(Token, View, time.Time) (VerifiedPermission, error){VerifyBearer, VerifyBearerRenewalProof} {
		if _, err := verify(token, view, now); err == nil {
			t.Fatal("identity became bearer permission")
		}
	}
	view.ObservedAt, view.ValidUntil = now.Add(30*time.Second), now.Add(5*time.Minute)
	view.VisitorPolicyRevision++
	workload := identity.Certificate.Source.(Workload)
	view = view.WithWorkloadLeases(map[string]WorkloadLease{workload.SessionID: {KeySHA256: workload.KeySHA256, ExpiresAt: now.Add(120 * time.Second)}})
	if CheckCurrent(permission, view, now.Add(30*time.Second)) == nil {
		t.Fatal("old short permission bypassed the current policy revision")
	}
	next, err := current.Renew(view, now.Add(30*time.Second))
	if err != nil || !next.SameIdentity(permission) || !next.Facts().ExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatal("fresh policy did not replace only the same identity's short permission", err)
	}
	fixed := Permission{Scope: identity.Scope, Hostname: identity.Hostname, Port: identity.Port, Subject: identity.Certificate,
		VisitorPolicyRevision: view.VisitorPolicyRevision, ExpiresAt: identity.ExpiresAt}
	legacy := issueToken(t, key, fixed, view, now)
	legacyState := state
	leaf := *state.PeerCertificates[0]
	uri, _ := CertificateURI(legacy)
	leaf.URIs = []*url.URL{uri}
	legacyState.PeerCertificates = []*x509.Certificate{&leaf}
	old, err := VerifyCertificate(legacy, view, legacyState, now.Add(30*time.Second))
	if err != nil || old.SameIdentity(next) {
		t.Fatal("old fixed permission was reclassified as renewable identity", err)
	}
	if _, ok := old.WorkloadPermission(); ok {
		t.Fatal("old fixed permission acquired a renewal source")
	}
	if _, err := current.Renew(view, now.Add(90*time.Second)); err == nil {
		t.Fatal("expired short permission revived under a newer workload lease")
	}
}

func TestWorkloadIdentityStrictWireAndCertificateBinding(t *testing.T) {
	key, _, token, view, state, now := identityFixture(t)
	parts := strings.Split(token.Reveal(), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"unknown type", "old permission type", "unknown field", "duplicate field", "trailing JSON", "policy revision", "issuer", "service", "hostname", "port", "future", "expired", "overlong lifetime", "nonce", "device", "source key", "signature"} {
		t.Run(fault, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatal(err)
			}
			profile := WorkloadIdentityType
			switch fault {
			case "unknown type":
				profile = "tnl-unknown+jwt"
			case "old permission type":
				profile = Type
			case "unknown field":
				body["authority"] = "extra"
			case "policy revision":
				body["visitor_policy_revision"] = 1
			case "issuer":
				body["iss"] = "https://other.example.test"
			case "service":
				body["scope"] = map[string]any{"kind": "service", "id": "svc_" + strings.Repeat("B", 22)}
			case "hostname":
				body["hostname"] = "other.example.test"
			case "port":
				body["port"] = 8443
			case "future":
				body["iat"] = now.Add(time.Second).Unix()
			case "expired":
				body["exp"] = now.Unix()
			case "overlong lifetime":
				body["exp"] = now.Add(7 * time.Hour).Unix()
			case "nonce":
				body["jti"] = "short"
			case "device":
				subject := body["visitor"].(map[string]any)["value"].(map[string]any)
				subject["source"] = map[string]any{"kind": "device", "value": Device{
					IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22),
					DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: subject["key_sha256"].(string)}}
			case "source key":
				subject := body["visitor"].(map[string]any)["value"].(map[string]any)
				subject["source"].(map[string]any)["value"].(map[string]any)["key_sha256"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			}
			changed, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "duplicate field" {
				changed = []byte(strings.Replace(string(changed), `"version":1`, `"version":1,"version":1`, 1))
			}
			if fault == "trailing JSON" {
				changed = append(changed, []byte(` {}`)...)
			}
			signing := key
			if fault == "signature" {
				signing = ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32)))
			}
			bad, err := signPayload(profile, "key-one", signing, changed)
			if err != nil {
				t.Fatal(err)
			}
			leaf := *state.PeerCertificates[0]
			uri, _ := CertificateURI(bad)
			leaf.URIs = []*url.URL{uri}
			changedState := state
			changedState.PeerCertificates = []*x509.Certificate{&leaf}
			if _, err := VerifyCertificate(bad, view, changedState, now); err == nil {
				t.Fatal("accepted malformed or wrong-bound identity")
			}
		})
	}
	for _, fault := range []string{"handshake", "serial", "key", "short certificate", "long certificate", "CA", "extra peer", "missing peer"} {
		t.Run(fault, func(t *testing.T) {
			leaf := *state.PeerCertificates[0]
			changed := state
			changed.PeerCertificates = []*x509.Certificate{&leaf}
			switch fault {
			case "handshake":
				changed.HandshakeComplete = false
			case "serial":
				leaf.SerialNumber = big.NewInt(2)
			case "key":
				leaf.PublicKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))).Public()
			case "short certificate":
				leaf.NotAfter = leaf.NotAfter.Add(-time.Second)
			case "long certificate":
				leaf.NotAfter = leaf.NotAfter.Add(time.Second)
			case "CA":
				leaf.IsCA = true
			case "extra peer":
				changed.PeerCertificates = append(changed.PeerCertificates, &leaf)
			case "missing peer":
				changed.PeerCertificates = nil
			}
			if _, err := VerifyCertificate(token, view, changed, now); err == nil {
				t.Fatal("accepted wrong certificate possession or expiry binding")
			}
		})
	}
}

func TestWorkloadIdentitySigningCannotBroadenDeviceOrBearerAuthority(t *testing.T) {
	key, identity, _, view, _, now := identityFixture(t)
	for _, subject := range []Subject{
		Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22),
			DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: identity.Certificate.KeySHA256},
		Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)},
	} {
		changed := identity
		changed.Certificate.Source = subject
		if _, err := SignWorkloadIdentity(view.Issuer, "key-one", key, changed, now); err == nil {
			t.Fatal("non-workload authority acquired the renewable identity profile")
		}
	}
}

func TestWorkloadIdentityCannotRenewAnotherScopeOrMissingAuthority(t *testing.T) {
	_, identity, token, view, state, now := identityFixture(t)
	permission, err := VerifyCertificate(token, view, state, now)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := permission.WorkloadPermission()
	for _, fault := range []string{"issuer", "service", "hostname", "port", "session", "key", "overlong lease", "revoked", "signer", "policy", "certificate"} {
		t.Run(fault, func(t *testing.T) {
			changed := view
			at := now
			switch fault {
			case "issuer":
				changed.Issuer = "https://other.example.test"
			case "service":
				changed.Scope.ID = "svc_" + strings.Repeat("B", 22)
			case "hostname":
				changed.Hostname = "other.example.test"
			case "port":
				changed.Port = 8443
			case "session":
				changed = changed.WithWorkloadLeases(map[string]WorkloadLease{"wls_" + strings.Repeat("X", 22): {KeySHA256: identity.Certificate.KeySHA256, ExpiresAt: now.Add(90 * time.Second)}})
			case "key":
				changed = changed.WithWorkloadLeases(map[string]WorkloadLease{identity.Certificate.Source.(Workload).SessionID: {
					KeySHA256: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: now.Add(90 * time.Second)}})
			case "overlong lease":
				changed = changed.WithWorkloadLeases(map[string]WorkloadLease{identity.Certificate.Source.(Workload).SessionID: {
					KeySHA256: identity.Certificate.KeySHA256, ExpiresAt: now.Add(WorkloadLeaseLifetime + time.Nanosecond)}})
			case "revoked":
				changed = changed.WithWorkloadLeases(nil)
			case "signer":
				changed = changed.WithVerificationKeys(nil)
			case "policy":
				at = changed.ValidUntil
			case "certificate":
				at = identity.ExpiresAt
				changed.ObservedAt, changed.ValidUntil = at, at.Add(5*time.Minute)
			}
			if _, err := current.Renew(changed, at); err == nil {
				t.Fatal("renewal substituted an authority or outlived its actual expiry")
			}
		})
	}
}
