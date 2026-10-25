package state

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitorcert"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceClientMaterial struct {
	Certificate     tls.Certificate `json:"-"`
	CertificateFile string          `json:"certificate_file"`
	KeyFile         string          `json:"key_file"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

func (ServiceClientMaterial) String() string   { return "service client credentials" }
func (ServiceClientMaterial) GoString() string { return "service client credentials" }

// one client key remains stable across certificate renewal, so a GUI never
// observes mismatched key/certificate files during an atomic certificate update.
// a pending CSR is saved before the request and reused after an uncertain reply.
// every call rechecks access and binds the credential to the current control
// session. replaying a CSR keeps the same certificate within one session; a
// newly authenticated parent can replace the certificate with the same key.
func (s *Store) EnsureServiceClientCertificate(ctx context.Context, identity, service, device string, issue func(context.Context, []byte) (controlv1.ServiceClientCertificate, error)) (result ServiceClientMaterial, retErr error) {
	if s == nil || issue == nil || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) || !opaqueid.Valid(service, opaqueid.ServicePrefix) || !opaqueid.Valid(device, opaqueid.VisitorDevicePrefix) {
		return result, ErrPublisherStateConflict
	}
	encoded, _ := json.Marshal([]string{s.controlEndpoint, identity, service, device})
	digest := sha256.Sum256(encoded)
	label := hex.EncodeToString(digest[:])
	lock, err := openLockContext(ctx, filepath.Join(s.locksDir, "service-client-"+label+".lock"), "service client certificate")
	if err != nil {
		return result, err
	}
	defer lock.Close()
	var encrypted, csr, issuedCSR, certificate, issuerPEM []byte
	var csrCreated int64
	err = s.database.db.QueryRowContext(ctx, `SELECT private_key_ciphertext,csr_der,issued_csr_der,certificate_pem,issuer_pem,csr_created_at FROM service_client_certificates WHERE server_origin=? AND identity_id=? AND service_id=? AND device_id=?`, s.controlEndpoint, identity, service, device).Scan(&encrypted, &csr, &issuedCSR, &certificate, &issuerPEM, &csrCreated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	secretContext := "service-client-key:" + string(encoded)
	var der []byte
	if len(encrypted) != 0 {
		der, err = s.secrets.Open(ctx, secretContext, encrypted)
		if err != nil {
			return result, err
		}
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return result, err
		}
		der, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return result, err
		}
		encrypted, err = s.secrets.Seal(ctx, secretContext, der)
		if err != nil {
			clear(der)
			return result, err
		}
	}
	defer clear(der)
	key, err := parseKey(der)
	if err != nil {
		return result, err
	}
	var material tls.Certificate
	var priorSession string
	refresh := true
	if len(certificate) != 0 {
		material, priorSession, err = validateServiceClientMaterial(der, certificate, issuerPEM, service, identity, device)
		if err != nil {
			return result, err
		}
		renewBefore := min(24*time.Hour, material.Leaf.NotAfter.Sub(material.Leaf.NotBefore)/4)
		refresh = len(issuedCSR) == 0 || len(csr) != 0 || !material.Leaf.NotAfter.After(time.Now().Add(renewBefore))
	}
	if refresh {
		if len(csr) != 0 && !time.Unix(0, csrCreated).Add(visitorcert.MaxLifetime).After(time.Now()) {
			csr = nil
		}
		if len(csr) == 0 {
			csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				return result, err
			}
			if _, err = s.database.db.ExecContext(ctx, `INSERT INTO service_client_certificates(server_origin,identity_id,service_id,device_id,private_key_ciphertext,csr_der,certificate_pem,issuer_pem,csr_created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(server_origin,identity_id,service_id,device_id) DO UPDATE SET csr_der=excluded.csr_der,csr_created_at=excluded.csr_created_at`, s.controlEndpoint, identity, service, device, encrypted, csr, certificate, issuerPEM, time.Now().UnixNano()); err != nil {
				return result, err
			}
		}
	} else {
		csr = issuedCSR
	}
	issued, err := issue(ctx, csr)
	if err != nil {
		return result, err
	}
	if issued.ServiceId != service {
		return result, ErrPublisherStateConflict
	}
	changed := issued.CertificatePem != string(certificate) || issued.IssuerPem != string(issuerPEM)
	certificate, issuerPEM = []byte(issued.CertificatePem), []byte(issued.IssuerPem)
	var issuedSession string
	material, issuedSession, err = validateServiceClientMaterial(der, certificate, issuerPEM, service, identity, device)
	if err != nil || !material.Leaf.NotAfter.Equal(issued.ExpiresAt) || !issued.ExpiresAt.After(time.Now()) {
		return result, errors.Join(visitorcert.ErrInvalidCertificate, err)
	}
	if !refresh && changed && priorSession == issuedSession {
		return result, ErrPublisherStateConflict
	}
	if refresh || changed {
		if _, err = s.database.db.ExecContext(ctx, `UPDATE service_client_certificates SET csr_der=NULL,issued_csr_der=?,certificate_pem=?,issuer_pem=? WHERE server_origin=? AND identity_id=? AND service_id=? AND device_id=?`, csr, certificate, issuerPEM, s.controlEndpoint, identity, service, device); err != nil {
			return result, err
		}
	}
	parent, err := privateSubdir(s.database.root, "service-clients")
	if err != nil {
		return result, err
	}
	directory, err := privateSubdir(parent, label)
	if err != nil {
		return result, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(privatePEM)
	if err = writeServiceCredential(directory, "client-key.pem", privatePEM, true); err != nil {
		return result, err
	}
	if err = writeServiceCredential(directory, "client-cert.pem", certificate, false); err != nil {
		return result, err
	}
	result = ServiceClientMaterial{Certificate: material, CertificateFile: filepath.Join(directory, "client-cert.pem"), KeyFile: filepath.Join(directory, "client-key.pem"), ExpiresAt: material.Leaf.NotAfter}
	return result, nil
}

func validateServiceClientMaterial(key, certificate, issuer []byte, service, identity, device string) (tls.Certificate, string, error) {
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(private)
	material, err := tls.X509KeyPair(certificate, private)
	if err != nil || len(material.Certificate) == 0 {
		return material, "", visitorcert.ErrInvalidCertificate
	}
	leaf, err := x509.ParseCertificate(material.Certificate[0])
	if err != nil {
		return material, "", err
	}
	block, rest := pem.Decode(issuer)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return material, "", visitorcert.ErrInvalidCertificate
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return material, "", err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	// expired material may be renewed with its existing protected key; every
	// new returned certificate is separately checked against the actual clock.
	now := time.Now()
	if now.After(leaf.NotAfter) {
		now = leaf.NotAfter.Add(-time.Second)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || leaf.IsCA || leaf.NotAfter.Sub(leaf.NotBefore) > visitorcert.MaxLifetime+time.Minute {
		return material, "", visitorcert.ErrInvalidCertificate
	}
	scope, source, err := visitortoken.CertificateIssuanceBinding(chains)
	human, ok := source.(visitortoken.Device)
	if err != nil || scope.Kind != visitorscope.Service || scope.ID != service || !ok || human.IdentityID != identity || human.DeviceID != device {
		return material, "", visitorcert.ErrInvalidCertificate
	}
	material.Leaf = leaf
	return material, human.SessionID, nil
}

func writeServiceCredential(directory, name string, data []byte, immutable bool) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil {
		if err = validatePrivateFile(info, false); err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrPublisherStateConflict
		}
		if immutable {
			file, err := root.Open(name)
			if err != nil {
				return err
			}
			old, readErr := io.ReadAll(io.LimitReader(file, 16<<10))
			closeErr := file.Close()
			equal := bytes.Equal(old, data)
			clear(old)
			if readErr != nil || closeErr != nil {
				return errors.Join(readErr, closeErr)
			}
			if !equal {
				return ErrPublisherStateConflict
			}
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	id, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	temporary := "." + name + "." + id
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	_, writeErr := io.Copy(file, bytes.NewReader(data))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err = root.Rename(temporary, name); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
