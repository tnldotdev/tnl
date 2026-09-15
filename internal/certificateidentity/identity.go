package certificateidentity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

// CanonicalPlan validates an authoritative plan and returns an owned, sorted identifier set.
// Scope and cache key are opaque authorization bindings, not locally derived DNS policy.
func CanonicalPlan(plan controlv1.CertificatePlan) (controlv1.CertificatePlan, error) {
	if plan.CacheKey == "" || len(plan.CacheKey) > 256 || plan.Scope == "" || len(plan.Scope) > 256 || strings.TrimSpace(plan.CacheKey) != plan.CacheKey ||
		strings.TrimSpace(plan.Scope) != plan.Scope || !plan.ChallengeMethod.Valid() ||
		len(plan.Identifiers) == 0 || len(plan.Identifiers) > 2 {
		return controlv1.CertificatePlan{}, errors.New("certificateidentity: invalid certificate plan")
	}
	plan.Identifiers = slices.Clone(plan.Identifiers)
	slices.Sort(plan.Identifiers)
	for index, identifier := range plan.Identifiers {
		base := strings.TrimPrefix(identifier, "*.")
		canonical, err := naming.CanonicalizeHostname(base)
		if err != nil || canonical != base || len(identifier) > 253 || index > 0 && identifier == plan.Identifiers[index-1] ||
			base != identifier && plan.ChallengeMethod != controlv1.Dns01 {
			return controlv1.CertificatePlan{}, errors.New("certificateidentity: invalid certificate identifiers")
		}
	}
	return plan, nil
}

func SamePlan(left, right controlv1.CertificatePlan) bool {
	left, err := CanonicalPlan(left)
	if err != nil {
		return false
	}
	right, err = CanonicalPlan(right)
	return err == nil && left.CacheKey == right.CacheKey && left.Scope == right.Scope &&
		left.ChallengeMethod == right.ChallengeMethod && slices.Equal(left.Identifiers, right.Identifiers)
}

// Covers applies x509's exact-name and one-label wildcard rules to a canonical route hostname.
func Covers(identifiers []string, hostname string) bool {
	canonical, err := naming.CanonicalizeHostname(hostname)
	return err == nil && canonical == hostname && (&x509.Certificate{DNSNames: identifiers}).VerifyHostname(hostname) == nil
}

// Matches requires the complete authorized DNS SAN set, including no hidden GeneralNames.
func Matches(extensions []pkix.Extension, names, identifiers []string) bool {
	actual, expected := slices.Clone(names), slices.Clone(identifiers)
	slices.Sort(actual)
	slices.Sort(expected)
	return slices.Equal(actual, expected) && DNSNamesOnly(extensions, names)
}

// ValidateCertificate checks automatic application material without trusting a caller-supplied Leaf.
func ValidateCertificate(certificate tls.Certificate, hostname string, identifiers []string) (*x509.Certificate, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("certificateidentity: certificate and private key are required")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !Matches(leaf.Extensions, leaf.DNSNames, identifiers) || !Covers(leaf.DNSNames, hostname) || leaf.IsCA ||
		leaf.NotBefore.After(time.Now().Add(5*time.Minute)) || !leaf.NotAfter.After(time.Now()) {
		return nil, errors.New("certificateidentity: certificate identity or validity is invalid")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("certificateidentity: certificate is not valid for TLS servers")
	}
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("certificateidentity: certificate requires an ECDSA P-256 key")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, errors.New("certificateidentity: certificate key does not match leaf")
	}
	return leaf, nil
}

// ValidateIssuedCertificate checks a chain against the authorized CSR without a
// private key or clock-skew allowance. Trust in the issuer comes from ACME.
func ValidateIssuedCertificate(certificatePEM, csrDER []byte, identifiers []string, now time.Time) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || len(identifiers) == 0 || !Matches(csr.Extensions, csr.DNSNames, identifiers) {
		return nil, errors.New("CSR is invalid")
	}
	var certificates []*x509.Certificate
	for remaining := bytes.TrimSpace(certificatePEM); len(remaining) != 0; {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("certificate chain is not canonical PEM")
		}
		block, rest := pem.Decode(remaining)
		// pem.Decode can skip malformed blocks; require it to consume the first one.
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			bytes.Count(remaining[:len(remaining)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("certificate chain is not canonical PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	leaf := certificates[0]
	leafPublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode certificate public key: %w", err)
	}
	csrPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(leafPublicKey, csrPublicKey) {
		return nil, errors.New("certificate public key does not match the CSR")
	}
	actualIdentifiers, expectedIdentifiers := slices.Clone(leaf.DNSNames), slices.Clone(identifiers)
	slices.Sort(actualIdentifiers)
	slices.Sort(expectedIdentifiers)
	if !slices.Equal(actualIdentifiers, expectedIdentifiers) {
		return nil, errors.New("certificate identifiers do not match the certificate plan")
	}
	if leaf.IsCA || !DNSNamesOnly(leaf.Extensions, leaf.DNSNames) {
		return nil, errors.New("certificate contains an unsupported identity or constraint")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("certificate is not valid for TLS servers")
	}
	if !leaf.NotAfter.After(leaf.NotBefore) || leaf.NotBefore.After(now) || !leaf.NotAfter.After(now) {
		return nil, errors.New("certificate validity period is invalid")
	}
	for index := 0; index+1 < len(certificates); index++ {
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return nil, fmt.Errorf("verify certificate chain: %w", err)
		}
	}
	return leaf, nil
}

// DNSNamesOnly reports whether the certificate or CSR has exactly one SAN
// extension and every GeneralName in it is a dNSName parsed by x509.
func DNSNamesOnly(extensions []pkix.Extension, dnsNames []string) bool {
	var encoded []byte
	for _, extension := range extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		if encoded != nil {
			return false
		}
		encoded = extension.Value
	}
	if encoded == nil {
		return false
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
		sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false
	}
	parsed := make([]string, 0, len(dnsNames))
	for rest = sequence.Bytes; len(rest) != 0; {
		var name asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &name)
		if err != nil || name.Class != asn1.ClassContextSpecific || name.Tag != 2 || name.IsCompound || !ascii(name.Bytes) {
			return false
		}
		parsed = append(parsed, string(name.Bytes))
	}
	return slices.Equal(parsed, dnsNames)
}

func ascii(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}
