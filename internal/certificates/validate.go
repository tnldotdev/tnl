package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	maxCSRBytes         = 12 << 10
	maxCertificateBytes = 48 << 10
	maxChainLength      = 8
	certificateSkew     = 5 * time.Minute
)

var subjectAltNameOID = []int{2, 5, 29, 17}

func validateCSR(csrDER []byte, hostname string) (*x509.CertificateRequest, [32]byte, [32]byte, error) {
	if len(csrDER) == 0 || len(csrDER) > maxCSRBytes {
		return nil, [32]byte{}, [32]byte{}, ErrInvalidArgument
	}
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		return nil, [32]byte{}, [32]byte{}, ErrInvalidArgument
	}
	if len(request.DNSNames) != 1 || request.DNSNames[0] != hostname ||
		len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 || len(request.URIs) != 0 ||
		!emptyName(request.Subject) || len(request.Extensions) != 1 || !request.Extensions[0].Id.Equal(subjectAltNameOID) {
		return nil, [32]byte{}, [32]byte{}, ErrInvalidArgument
	}
	publicKey, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, [32]byte{}, [32]byte{}, ErrInvalidArgument
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, ErrInvalidArgument
	}
	return request, sha256.Sum256(csrDER), sha256.Sum256(spki), nil
}

func validateCertificateChain(
	certificatePEM []byte,
	hostname string,
	spkiHash [32]byte,
	now time.Time,
	roots *x509.CertPool,
) ([]byte, *x509.Certificate, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > maxCertificateBytes {
		return nil, nil, errors.New("certificates: certificate chain exceeds limit")
	}
	remaining := certificatePEM
	certificates := make([]*x509.Certificate, 0, 3)
	var canonical bytes.Buffer
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("certificates: certificate response is not a strict PEM chain")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("certificates: parse certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		if len(certificates) > maxChainLength {
			return nil, nil, errors.New("certificates: certificate chain exceeds length limit")
		}
		if err := pem.Encode(&canonical, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return nil, nil, err
		}
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("certificates: certificate response is empty")
	}
	leaf := certificates[0]
	if sha256.Sum256(leaf.RawSubjectPublicKeyInfo) != spkiHash ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA {
		return nil, nil, errors.New("certificates: issued leaf does not match the request")
	}
	if leaf.NotBefore.After(now.Add(certificateSkew)) || !leaf.NotAfter.After(now.Add(certificateSkew)) {
		return nil, nil, errors.New("certificates: issued leaf is not currently valid")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: hostname, Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now,
	}); err != nil {
		return nil, nil, fmt.Errorf("certificates: verify issued chain: %w", err)
	}
	return canonical.Bytes(), leaf, nil
}

func renewalTime(issuanceID string, notBefore, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(notBefore)
	base := notBefore.Add(lifetime * 2 / 3)
	// Stable +/-5% jitter spreads renewals without moving them across restarts.
	digest := sha256.Sum256([]byte(issuanceID))
	fraction := int64(binary.BigEndian.Uint16(digest[:2])) - 32768
	jitter := time.Duration(fraction) * (lifetime / 20) / 32768
	return base.Add(jitter).UTC()
}

func emptyName(name pkix.Name) bool {
	return name.CommonName == "" && name.SerialNumber == "" &&
		len(name.Country) == 0 && len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 && len(name.Locality) == 0 &&
		len(name.Province) == 0 && len(name.StreetAddress) == 0 && len(name.PostalCode) == 0 &&
		len(name.Names) == 0 && len(name.ExtraNames) == 0
}
