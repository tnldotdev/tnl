package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/0xcadams/tnl/internal/naming"
	"golang.org/x/crypto/acme"
)

var acmeIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// TLSALPNChallenge is the bounded challenge material delivered to an agent.
// The ACME key authorization and account key remain on the server.
type TLSALPNChallenge struct {
	ID        string
	Hostname  string
	Digest    [sha256.Size]byte
	ExpiresAt time.Time
}

type challengeCertificate struct {
	challenge   TLSALPNChallenge
	certificate tls.Certificate
}

// TLSALPNChallenges stores temporary agent-owned challenge certificates. Its
// zero value is ready for use.
type TLSALPNChallenges struct {
	mu         sync.RWMutex
	byHostname map[string]*challengeCertificate
	hostByID   map[string]string
}

// Install creates and atomically installs a temporary challenge certificate.
// Repeating an identical command is idempotent; a new ID replaces the current
// challenge for the hostname.
func (s *TLSALPNChallenges) Install(challenge TLSALPNChallenge) error {
	if challenge.ID == "" {
		return errors.New("agent: missing TLS-ALPN challenge ID")
	}
	hostname, err := naming.CanonicalizeHostname(challenge.Hostname)
	if err != nil || hostname != challenge.Hostname {
		return errors.New("agent: non-canonical TLS-ALPN hostname")
	}
	if !challenge.ExpiresAt.After(time.Now()) {
		return errors.New("agent: expired TLS-ALPN challenge")
	}

	s.mu.RLock()
	existing, seen := s.challengeByIDLocked(challenge.ID)
	s.mu.RUnlock()
	if seen {
		if existing != nil && sameChallenge(existing.challenge, challenge) {
			return nil
		}
		return errors.New("agent: conflicting TLS-ALPN challenge ID")
	}

	certificate, err := newChallengeCertificate(challenge)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !challenge.ExpiresAt.After(time.Now()) {
		return errors.New("agent: expired TLS-ALPN challenge")
	}
	if existing, seen := s.challengeByIDLocked(challenge.ID); seen {
		if existing != nil && sameChallenge(existing.challenge, challenge) {
			return nil
		}
		return errors.New("agent: conflicting TLS-ALPN challenge ID")
	}
	if s.byHostname == nil {
		s.byHostname = make(map[string]*challengeCertificate)
		s.hostByID = make(map[string]string)
	}
	// hostByID retains superseded IDs so delayed installs fail closed.
	s.byHostname[hostname] = certificate
	s.hostByID[challenge.ID] = hostname
	return nil
}

// Remove removes only the challenge with the matching ID. A stale removal
// cannot remove a replacement challenge for the same hostname.
func (s *TLSALPNChallenges) Remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	hostname, ok := s.hostByID[id]
	if !ok {
		return false
	}
	certificate := s.byHostname[hostname]
	if certificate == nil || certificate.challenge.ID != id {
		return false
	}
	delete(s.byHostname, hostname)
	return true
}

// GetCertificate selects a challenge certificate for crypto/tls. It accepts
// only canonical exact SNI and the sole ALPN protocol acme-tls/1. The serving
// TLS config must disable session tickets so every handshake is rechecked.
func (s *TLSALPNChallenges) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != acme.ALPNProto {
		return nil, errors.New("agent: not a TLS-ALPN challenge handshake")
	}

	s.mu.RLock()
	certificate := s.byHostname[hello.ServerName]
	if certificate == nil || !certificate.challenge.ExpiresAt.After(time.Now()) {
		s.mu.RUnlock()
		return nil, errors.New("agent: no active TLS-ALPN challenge")
	}
	selected := &certificate.certificate
	s.mu.RUnlock()
	return selected, nil
}

func (s *TLSALPNChallenges) challengeByIDLocked(id string) (*challengeCertificate, bool) {
	hostname, ok := s.hostByID[id]
	if !ok {
		return nil, false
	}
	certificate := s.byHostname[hostname]
	if certificate == nil || certificate.challenge.ID != id {
		return nil, true
	}
	return certificate, true
}

func sameChallenge(left, right TLSALPNChallenge) bool {
	return left.ID == right.ID &&
		left.Hostname == right.Hostname &&
		left.Digest == right.Digest &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func newChallengeCertificate(challenge TLSALPNChallenge) (*challengeCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	extensionValue, err := asn1.Marshal(challenge.Digest[:])
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              challenge.ExpiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{challenge.Hostname},
		ExtraExtensions: []pkix.Extension{{
			Id:       acmeIdentifierOID,
			Critical: true,
			Value:    extensionValue,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &challengeCertificate{
		challenge: challenge,
		certificate: tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        leaf,
		},
	}, nil
}
