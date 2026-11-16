package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func connectorRetirementFixture() ConnectorPeerPairRetireProof {
	return ConnectorPeerPairRetireProof{
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
		RunNumber: 2, PublisherIdentityID: "pub_1234567890123456789012",
		PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", IdempotencyKey: "pair-one",
		RequestedAt: time.Date(2026, 1, 2, 4, 4, 5, 123456999, time.FixedZone("other", 3600)),
	}
}

func TestConnectorPeerPairRetireProofGolden(t *testing.T) {
	p := connectorRetirementFixture()
	golden, err := os.ReadFile("testdata/connector-peer-retire-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := json.Compact(&body, golden); err != nil {
		t.Fatal(err)
	}
	sessionKey := bytes.Repeat([]byte{0x35}, sha256.Size)
	mac := hmac.New(sha256.New, sessionKey)
	_, _ = mac.Write([]byte("tnl connector peer pair retire mac v1\x00"))
	_, _ = mac.Write(body.Bytes())
	expectedMAC := mac.Sum(nil)
	gotMAC, err := p.SessionProof(sessionKey)
	if err != nil || !bytes.Equal(gotMAC, expectedMAC) {
		t.Fatal("retirement MAC changed", err)
	}
	expectedMessage := append([]byte("tnl connector peer pair retire v1\x00"), body.Bytes()...)
	expectedMessage = append(expectedMessage, expectedMAC...)
	message, err := p.Message(gotMAC)
	if err != nil || !bytes.Equal(message, expectedMessage) {
		t.Fatal("canonical retirement signing bytes changed", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signature := ed25519.Sign(key, expectedMessage)
	if err := p.VerifySignature(key.Public().(ed25519.PublicKey), gotMAC, signature); err != nil {
		t.Fatal("original snapshot signature rejected", err)
	}
	if err := p.VerifySessionProof(sessionKey, gotMAC); err != nil {
		t.Fatal("exact stable session proof rejected", err)
	}
	expectedDigest := sha256.Sum256(append(append(bytes.Clone(body.Bytes()), expectedMAC...), signature...))
	digest, err := p.RequestDigest(gotMAC, signature)
	if err != nil || digest != expectedDigest {
		t.Fatal("canonical retirement retry digest changed", err)
	}
	normalized := p
	normalized.RequestedAt = p.RequestedAt.UTC().Truncate(time.Microsecond)
	retryMAC, err := normalized.SessionProof(sessionKey)
	if err != nil || !bytes.Equal(retryMAC, gotMAC) {
		t.Fatal("timestamp normalization changed the retry MAC", err)
	}
	retryDigest, err := normalized.RequestDigest(gotMAC, signature)
	if err != nil || retryDigest != digest {
		t.Fatal("identical normalized proof changed the retry digest", err)
	}
}

func TestConnectorPeerPairRetireProofBindsEveryScopeField(t *testing.T) {
	p := connectorRetirementFixture()
	sessionKey := bytes.Repeat([]byte{0x35}, sha256.Size)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	mac, err := p.SessionProof(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := p.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, message)
	originalDigest, err := p.RequestDigest(mac, signature)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*ConnectorPeerPairRetireProof)
	}{
		{"service", func(p *ConnectorPeerPairRetireProof) { p.ServiceID = "svc_abcdefghijklmnopqrstuv" }},
		{"run", func(p *ConnectorPeerPairRetireProof) { p.ServiceRunID = "srun_abcdefghijklmnopqrstuv" }},
		{"run number", func(p *ConnectorPeerPairRetireProof) { p.RunNumber++ }},
		{"publisher", func(p *ConnectorPeerPairRetireProof) { p.PublisherIdentityID = "pub_abcdefghijklmnopqrstuv" }},
		{"sibling pair", func(p *ConnectorPeerPairRetireProof) { p.PairID = "cpp_abcdefghijklmnopqrstuv" }},
		{"replacement delivery", func(p *ConnectorPeerPairRetireProof) {
			p.DeliveryID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
		}},
		{"owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = "another-owner" }},
		{"timestamp", func(p *ConnectorPeerPairRetireProof) { p.RequestedAt = p.RequestedAt.Add(time.Microsecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := p
			test.edit(&next)
			if err := next.VerifySignature(key.Public().(ed25519.PublicKey), mac, signature); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
				t.Fatal("changed scope retained the original signature", err)
			}
			if err := next.VerifySessionProof(sessionKey, mac); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
				t.Fatal("changed scope retained the original MAC", err)
			}
			digest, err := next.RequestDigest(mac, signature)
			if err != nil || digest == originalDigest {
				t.Fatal("changed scope retained the original retry digest", err)
			}
		})
	}
}

func TestConnectorPeerPairRetireProofRequiresBothKeysAndDomains(t *testing.T) {
	p := connectorRetirementFixture()
	sessionKey := bytes.Repeat([]byte{0x35}, sha256.Size)
	otherSession := bytes.Repeat([]byte{0x36}, sha256.Size)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	mac, err := p.SessionProof(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := p.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, message)
	if err := p.VerifySignature(otherKey.Public().(ed25519.PublicKey), mac, signature); err == nil {
		t.Fatal("another enrolled key substituted for the original snapshot")
	}
	if err := p.VerifySessionProof(otherSession, mac); err == nil {
		t.Fatal("sibling or replacement session key substituted for the stable pair key")
	}
	changedMAC := bytes.Clone(mac)
	changedMAC[0] ^= 1
	if err := p.VerifySignature(key.Public().(ed25519.PublicKey), changedMAC, signature); err == nil {
		t.Fatal("signature did not bind the raw MAC")
	}
	// a holder of the enrolled key alone can sign an arbitrary MAC but cannot
	// satisfy the independent pair-key check; an endpoint alone lacks that signer.
	forged := ed25519.Sign(key, append(append([]byte("tnl connector peer pair retire v1\x00"), mustRetirementBody(t, p)...), changedMAC...))
	if err := p.VerifySignature(key.Public().(ed25519.PublicKey), changedMAC, forged); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifySessionProof(sessionKey, changedMAC); err == nil {
		t.Fatal("an enrolled signature alone authorized pair retirement")
	}
	for _, domain := range []string{
		"tnl connector peer pair v1\x00", "tnl connector peer rebind v1\x00",
		"tnl connector peer pair retire mac v1\x00", "tnl connector pair leg claim v1\x00",
		"tnl relay connector pair leg claim v1\x00",
	} {
		t.Run(domain, func(t *testing.T) {
			wrong := append([]byte(domain), mustRetirementBody(t, p)...)
			wrong = append(wrong, mac...)
			if err := p.VerifySignature(key.Public().(ed25519.PublicKey), mac, ed25519.Sign(key, wrong)); err == nil {
				t.Fatal("another proof domain authorized retirement")
			}
			wrongMAC := hmac.New(sha256.New, sessionKey)
			_, _ = wrongMAC.Write([]byte(domain))
			_, _ = wrongMAC.Write(mustRetirementBody(t, p))
			if domain != "tnl connector peer pair retire mac v1\x00" && p.VerifySessionProof(sessionKey, wrongMAC.Sum(nil)) == nil {
				t.Fatal("another MAC domain authorized retirement")
			}
		})
	}
}

func mustRetirementBody(t testing.TB, p ConnectorPeerPairRetireProof) []byte {
	t.Helper()
	body, err := p.body()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestConnectorPeerPairRetireProofRejectsInvalidScope(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*ConnectorPeerPairRetireProof)
	}{
		{"service", func(p *ConnectorPeerPairRetireProof) { p.ServiceID = "svc_bad" }},
		{"run", func(p *ConnectorPeerPairRetireProof) { p.ServiceRunID = "srun_bad" }},
		{"publisher", func(p *ConnectorPeerPairRetireProof) { p.PublisherIdentityID = "pub_bad" }},
		{"pair", func(p *ConnectorPeerPairRetireProof) { p.PairID = "cpp_bad" }},
		{"zero run", func(p *ConnectorPeerPairRetireProof) { p.RunNumber = 0 }},
		{"negative run", func(p *ConnectorPeerPairRetireProof) { p.RunNumber = -1 }},
		{"zero delivery", func(p *ConnectorPeerPairRetireProof) { p.DeliveryID = strings.Repeat("A", 22) }},
		{"padded delivery", func(p *ConnectorPeerPairRetireProof) { p.DeliveryID += "==" }},
		{"noncanonical delivery", func(p *ConnectorPeerPairRetireProof) { p.DeliveryID = strings.Repeat("A", 21) + "B" }},
		{"empty owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = "" }},
		{"long owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = strings.Repeat("x", 129) }},
		{"spaced owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = " owner" }},
		{"nul owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = "owner\x00key" }},
		{"control owner", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = "owner\nkey" }},
		{"invalid utf8", func(p *ConnectorPeerPairRetireProof) { p.IdempotencyKey = string([]byte{0xff}) }},
		{"zero time", func(p *ConnectorPeerPairRetireProof) { p.RequestedAt = time.Time{} }},
		{"normalized zero time", func(p *ConnectorPeerPairRetireProof) { p.RequestedAt = time.Time{}.Add(time.Nanosecond) }},
		{"unencodable time", func(p *ConnectorPeerPairRetireProof) { p.RequestedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := connectorRetirementFixture()
			test.edit(&p)
			if _, err := p.SessionProof(make([]byte, sha256.Size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
				t.Fatal("invalid retirement scope produced a MAC", err)
			}
			if _, err := p.Message(make([]byte, sha256.Size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
				t.Fatal("invalid retirement scope produced a message", err)
			}
		})
	}
	p := connectorRetirementFixture()
	p.RunNumber = math.MaxInt64
	p.IdempotencyKey = strings.Repeat("x", 128)
	if _, err := p.Message(make([]byte, sha256.Size)); err != nil {
		t.Fatal("valid maximum run number or owner length rejected", err)
	}
}

func TestConnectorPeerPairRetireProofRejectsInvalidProofBounds(t *testing.T) {
	p := connectorRetirementFixture()
	for _, size := range []int{0, 1, sha256.Size - 1, sha256.Size + 1} {
		if _, err := p.SessionProof(make([]byte, size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid session-key size accepted", size, err)
		}
		if _, err := p.Message(make([]byte, size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid MAC size accepted", size, err)
		}
		if err := p.VerifySessionProof(make([]byte, sha256.Size), make([]byte, size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid MAC size verified", size, err)
		}
	}
	for _, size := range []int{0, ed25519.SignatureSize - 1, ed25519.SignatureSize + 1} {
		if err := p.VerifySignature(make([]byte, ed25519.PublicKeySize), make([]byte, sha256.Size), make([]byte, size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid signature size accepted", size, err)
		}
		if _, err := p.RequestDigest(make([]byte, sha256.Size), make([]byte, size)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid signature size retained as a retry", size, err)
		}
	}
	for _, size := range []int{0, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		if err := p.VerifySignature(make([]byte, size), make([]byte, sha256.Size), make([]byte, ed25519.SignatureSize)); !errors.Is(err, ErrConnectorPeerPairRetireProof) {
			t.Fatal("invalid snapshot size accepted", size, err)
		}
	}
}

func FuzzConnectorPeerPairRetireProof(f *testing.F) {
	p := connectorRetirementFixture()
	f.Add(p.PairID, p.DeliveryID, p.IdempotencyKey, p.RunNumber, []byte("invalid MAC"), []byte("invalid signature"))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	mac, err := p.SessionProof(make([]byte, sha256.Size))
	if err != nil {
		f.Fatal(err)
	}
	message, err := p.Message(mac)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(p.PairID, p.DeliveryID, p.IdempotencyKey, p.RunNumber, mac, ed25519.Sign(key, message))
	f.Fuzz(func(t *testing.T, pair, delivery, owner string, number int64, mac, signature []byte) {
		p := connectorRetirementFixture()
		p.PairID, p.DeliveryID, p.IdempotencyKey, p.RunNumber = pair, delivery, owner, number
		_, _ = p.Message(mac)
		_, _ = p.SessionProof(make([]byte, sha256.Size))
		_, _ = p.RequestDigest(mac, signature)
		_ = p.VerifySignature(make([]byte, ed25519.PublicKeySize), mac, signature)
		_ = p.VerifySessionProof(make([]byte, sha256.Size), mac)
	})
}
