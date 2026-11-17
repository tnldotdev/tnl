package stream

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// VisitorProtocolRefusal is issued only by visitor TLS negotiation. the TLS
// library owns parsing and protocol errors; its fallible local dependencies are
// captured separately before it can wrap or discard their failures.
type VisitorProtocolRefusal struct{ err error }

func (e *VisitorProtocolRefusal) Error() string { return e.err.Error() }
func (e *VisitorProtocolRefusal) Unwrap() error { return e.err }

// VisitorTLSCallbackFailure cannot borrow the protocol refusal's provenance,
// even if a callback returns a TLS error, EOF, or a joined cancellation.
type VisitorTLSCallbackFailure struct{ err error }

func (e *VisitorTLSCallbackFailure) Error() string { return e.err.Error() }
func (e *VisitorTLSCallbackFailure) Unwrap() error { return e.err }

// VisitorTLSIOFailure retains the actual socket operation result, including an
// alert write that the TLS library can discard while returning a protocol error.
type VisitorTLSIOFailure struct{ err error }

func (e *VisitorTLSIOFailure) Error() string { return e.err.Error() }
func (e *VisitorTLSIOFailure) Unwrap() error { return e.err }

func negotiateVisitorTLS(ctx context.Context, conn net.Conn, config *tls.Config) (*tls.Conn, error) {
	failures := &visitorTLSFailures{}
	failures.active.Store(true)
	config = failures.config(config)
	secured := tls.Server(&visitorTLSConn{Conn: conn, failures: failures}, config)
	err := secured.HandshakeContext(ctx)
	failures.active.Store(false)
	failures.mu.Lock()
	required := failures.err
	failures.mu.Unlock()
	if err != nil {
		err = &VisitorProtocolRefusal{err: err}
	}
	return secured, errors.Join(err, required)
}

type visitorTLSFailures struct {
	active atomic.Bool
	mu     sync.Mutex
	err    error
}

func (f *visitorTLSFailures) record(err error) {
	if err == nil || !f.active.Load() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active.Load() {
		f.err = errors.Join(f.err, err)
	}
}

func (f *visitorTLSFailures) callback(err error) error {
	if err != nil {
		f.record(&VisitorTLSCallbackFailure{err: err})
	}
	return err
}

func (f *visitorTLSFailures) config(original *tls.Config) *tls.Config {
	config := original.Clone()
	config.Certificates = make([]tls.Certificate, len(original.Certificates))
	for i := range original.Certificates {
		config.Certificates[i] = *f.certificate(&original.Certificates[i])
	}
	//lint:ignore SA1019 preserve caller-supplied certificate selection while observing its signer failures.
	namedCertificates := original.NameToCertificate
	if namedCertificates != nil {
		wrapped := make(map[string]*tls.Certificate, len(namedCertificates))
		for name, certificate := range namedCertificates {
			wrapped[name] = f.certificate(certificate)
		}
		//lint:ignore SA1019 retain the supplied compatibility map without mutating the caller's certificates.
		config.NameToCertificate = wrapped
	}
	if original.GetCertificate != nil {
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, err := original.GetCertificate(hello)
			return f.certificate(certificate), f.callback(err)
		}
	}
	if original.VerifyPeerCertificate != nil {
		config.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			return f.callback(original.VerifyPeerCertificate(raw, chains))
		}
	}
	if original.VerifyConnection != nil {
		config.VerifyConnection = func(state tls.ConnectionState) error {
			return f.callback(original.VerifyConnection(state))
		}
	}
	if original.UnwrapSession != nil {
		config.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
			session, err := original.UnwrapSession(identity, state)
			return session, f.callback(err)
		}
	}
	if original.WrapSession != nil {
		config.WrapSession = func(state tls.ConnectionState, session *tls.SessionState) ([]byte, error) {
			ticket, err := original.WrapSession(state, session)
			return ticket, f.callback(err)
		}
	}
	if original.GetEncryptedClientHelloKeys != nil {
		config.GetEncryptedClientHelloKeys = func(hello *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			keys, err := original.GetEncryptedClientHelloKeys(hello)
			return keys, f.callback(err)
		}
	}
	//lint:ignore SA1019 preserve a caller-supplied compatibility entropy reader rather than silently replacing it.
	random := original.Rand
	if random != nil {
		//lint:ignore SA1019 observe the supplied reader so its failures retain local provenance.
		config.Rand = visitorTLSReader{Reader: random, failures: f}
	}
	if original.KeyLogWriter != nil {
		config.KeyLogWriter = visitorTLSWriter{Writer: original.KeyLogWriter, failures: f}
	}
	// Stream installs its own hostname gate and forbids caller-supplied
	// GetConfigForClient. client-only callbacks cannot run on this TLS server.
	return config
}

func (f *visitorTLSFailures) certificate(original *tls.Certificate) *tls.Certificate {
	if original == nil {
		return nil
	}
	certificate := *original
	signer, signs := original.PrivateKey.(crypto.Signer)
	decrypter, decrypts := original.PrivateKey.(crypto.Decrypter)
	switch {
	case signs && decrypts:
		certificate.PrivateKey = visitorTLSPrivateKey{
			visitorTLSSigner:    visitorTLSSigner{Signer: signer, failures: f},
			visitorTLSDecrypter: visitorTLSDecrypter{Decrypter: decrypter, failures: f},
		}
	case signs:
		certificate.PrivateKey = visitorTLSSigner{Signer: signer, failures: f}
	case decrypts:
		certificate.PrivateKey = visitorTLSDecrypter{Decrypter: decrypter, failures: f}
	}
	return &certificate
}

type visitorTLSConn struct {
	net.Conn
	failures *visitorTLSFailures
}

func (c *visitorTLSConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil {
		c.failures.record(&VisitorTLSIOFailure{err: err})
	}
	return n, err
}

func (c *visitorTLSConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if err != nil {
		c.failures.record(&VisitorTLSIOFailure{err: err})
	}
	return n, err
}

type visitorTLSReader struct {
	io.Reader
	failures *visitorTLSFailures
}

func (r visitorTLSReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	return n, r.failures.callback(err)
}

type visitorTLSWriter struct {
	io.Writer
	failures *visitorTLSFailures
}

func (w visitorTLSWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	return n, w.failures.callback(err)
}

type visitorTLSSigner struct {
	crypto.Signer
	failures *visitorTLSFailures
}

func (k visitorTLSSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	signature, err := k.Signer.Sign(random, digest, options)
	return signature, k.failures.callback(err)
}

func (k visitorTLSSigner) SignMessage(random io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	signature, err := crypto.SignMessage(k.Signer, random, message, options)
	return signature, k.failures.callback(err)
}

type visitorTLSDecrypter struct {
	crypto.Decrypter
	failures *visitorTLSFailures
}

func (k visitorTLSDecrypter) Decrypt(random io.Reader, ciphertext []byte, options crypto.DecrypterOpts) ([]byte, error) {
	plaintext, err := k.Decrypter.Decrypt(random, ciphertext, options)
	return plaintext, k.failures.callback(err)
}

type visitorTLSPrivateKey struct {
	visitorTLSSigner
	visitorTLSDecrypter
}

func (k visitorTLSPrivateKey) Public() crypto.PublicKey { return k.visitorTLSSigner.Public() }
