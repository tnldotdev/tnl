package stream

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

type visitorTLSBrokenIO struct{ err error }

func (f visitorTLSBrokenIO) Read([]byte) (int, error)  { return 0, f.err }
func (f visitorTLSBrokenIO) Write([]byte) (int, error) { return 0, f.err }

func TestVisitorTLSRetainsEveryFallibleServerCallback(t *testing.T) {
	independent := errors.New("local TLS dependency failed independently")
	failure := errors.Join(context.Canceled, independent)
	for _, test := range []struct {
		name string
		call func(*visitorTLSFailures) error
	}{
		{"certificate", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, failure }})
			_, err := config.GetCertificate(nil)
			return err
		}},
		{"peer-verification", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return failure }})
			return config.VerifyPeerCertificate(nil, nil)
		}},
		{"connection-verification", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{VerifyConnection: func(tls.ConnectionState) error { return failure }})
			return config.VerifyConnection(tls.ConnectionState{})
		}},
		{"session-unwrap", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, failure }})
			_, err := config.UnwrapSession(nil, tls.ConnectionState{})
			return err
		}},
		{"session-wrap", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, failure }})
			_, err := config.WrapSession(tls.ConnectionState{}, nil)
			return err
		}},
		{"encrypted-client-hello-keys", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return nil, failure }})
			_, err := config.GetEncryptedClientHelloKeys(nil)
			return err
		}},
		{"entropy", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{Rand: visitorTLSBrokenIO{err: failure}})
			_, err := config.Rand.Read(make([]byte, 32))
			return err
		}},
		{"key-log", func(f *visitorTLSFailures) error {
			config := f.config(&tls.Config{KeyLogWriter: visitorTLSBrokenIO{err: failure}})
			_, err := config.KeyLogWriter.Write([]byte("bounded fixture"))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &visitorTLSFailures{}
			f.active.Store(true)
			if err := test.call(f); err != failure {
				t.Fatal("TLS dependency wrapper changed the exact callback result", err)
			}
			var required *VisitorTLSCallbackFailure
			if !errors.As(f.err, &required) || !errors.Is(f.err, independent) || !errors.Is(f.err, context.Canceled) {
				t.Fatal("visitor negotiation lost a fallible local dependency's provenance", f.err)
			}
		})
	}
}

type visitorTLSBrokenSigner struct {
	crypto.Signer
	err error
}

func (k visitorTLSBrokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, k.err
}

func TestVisitorTLSRetainsCertificateSigningFailureWithoutMutatingCertificate(t *testing.T) {
	certificate := visitorfixture.Certificate(t, "service.example.test")
	failure := errors.Join(context.Canceled, errors.New("certificate signer failed independently"))
	original := visitorTLSBrokenSigner{Signer: certificate.PrivateKey.(crypto.Signer), err: failure}
	certificate.PrivateKey = original
	f := &visitorTLSFailures{}
	f.active.Store(true)
	wrapped := f.certificate(&certificate)
	if _, err := crypto.SignMessage(wrapped.PrivateKey.(crypto.Signer), nil, []byte("visitor handshake"), crypto.SHA256); err != failure {
		t.Fatal("TLS signing wrapper changed the original failure", err)
	}
	var required *VisitorTLSCallbackFailure
	if !errors.As(f.err, &required) || !errors.Is(f.err, failure) {
		t.Fatal("TLS signing failure lost local-dependency provenance", f.err)
	}
	if certificate.PrivateKey != original {
		t.Fatal("visitor negotiation mutated the shared service certificate")
	}
}
