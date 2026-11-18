package certificateidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"time"
)

// Supplied identifies validated visitor material, not permission to serve any
// additional name on the certificate. callers still enforce exact run authority.
type Supplied struct {
	Leaf        *x509.Certificate
	Fingerprint string
	ExpiresAt   time.Time
}

// ValidateSuppliedChain requires a trusted server chain covering every requested
// hostname. roots=nil uses system trust (the portable binary embeds WebPKI roots).
// broader SANs and wildcards are allowed; they never broaden the run's names.
func ValidateSuppliedChain(chain []byte, hostnames []string, now time.Time, roots *x509.CertPool) (Supplied, error) {
	certificates, err := parseSuppliedChain(chain, hostnames, now)
	if err != nil {
		return Supplied{}, err
	}
	invalid := errors.New("certificateidentity: supplied certificate chain, trust, names, or validity is invalid")
	leaf := certificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	expires := leaf.NotAfter
	for _, hostname := range hostnames {
		chains, err := leaf.Verify(x509.VerifyOptions{
			DNSName: hostname, Roots: roots, Intermediates: intermediates,
			CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return Supplied{}, invalid
		}
		// choose the longest-lived verified path, never a deadline beyond one
		// of its certificates. another hostname can only narrow that deadline.
		var best time.Time
		for _, path := range chains {
			until := leaf.NotAfter
			for _, certificate := range path {
				if certificate.NotAfter.Before(until) {
					until = certificate.NotAfter
				}
			}
			if until.After(best) {
				best = until
			}
		}
		if best.Before(expires) {
			expires = best
		}
	}
	digest := sha256.Sum256(leaf.Raw)
	return Supplied{Leaf: leaf, Fingerprint: hex.EncodeToString(digest[:]), ExpiresAt: expires}, nil
}

func parseSuppliedChain(chain []byte, hostnames []string, now time.Time) ([]*x509.Certificate, error) {
	invalid := errors.New("certificateidentity: supplied certificate chain, names, or validity is invalid")
	if len(chain) == 0 || len(chain) > 128<<10 || len(hostnames) == 0 || len(hostnames) > 2 || now.IsZero() {
		return nil, invalid
	}
	var certificates []*x509.Certificate
	for remaining := bytes.TrimSpace(chain); len(remaining) != 0; {
		if len(certificates) >= 16 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			bytes.Count(remaining[:len(remaining)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, invalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, invalid
	}
	leaf := certificates[0]
	if leaf.IsCA || !DNSNamesOnly(leaf.Extensions, leaf.DNSNames) ||
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, invalid
	}
	if leaf.NotBefore.After(now) || !leaf.NotAfter.After(now) {
		return nil, invalid
	}
	for index, certificate := range certificates[1:] {
		if certificates[index].CheckSignatureFrom(certificate) != nil {
			return nil, invalid
		}
	}
	for _, hostname := range hostnames {
		if !Covers(leaf.DNSNames, hostname) {
			return nil, invalid
		}
	}
	return certificates, nil
}

// LoadSupplied validates local chain structure, names, validity and key matching.
// it does not establish issuer trust: control must acknowledge the chain before
// callers install it for visitors. this also validates durable recovery records.
func LoadSupplied(chain, privateKey []byte, hostnames []string, now time.Time) (tls.Certificate, error) {
	certificates, err := parseSuppliedChain(chain, hostnames, now)
	if err != nil || len(privateKey) == 0 || len(privateKey) > 16<<10 {
		return tls.Certificate{}, errors.New("certificateidentity: supplied certificate material is invalid")
	}
	certificate, err := tls.X509KeyPair(chain, privateKey)
	if err != nil {
		return tls.Certificate{}, errors.New("certificateidentity: supplied certificate key does not match")
	}
	certificate.Leaf = certificates[0]
	return certificate, nil
}
