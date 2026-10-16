package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type visitorCertificateCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" name:"url" required:"" help:"PostgreSQL, MySQL or Redis public URL ID or hostname from tnl url available."`
	Directory   string           `name:"directory" required:"" help:"Private local directory for client-key.pem, client-cert.pem and issuer.pem."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func resolveVisitorPublicURL(ctx context.Context, s *teamSession, selector string) (controlv1.AvailablePublicURL, error) {
	cursor := ""
	for {
		page, err := s.authenticated.Control.ListAvailablePublicURLs(ctx, "", cursor)
		if err != nil {
			return controlv1.AvailablePublicURL{}, err
		}
		for _, item := range page.PublicUrls {
			if item.Id == selector || item.CanonicalHostname == strings.TrimSuffix(strings.TrimPrefix(selector, "https://"), "/") {
				return item, nil
			}
		}
		if page.NextCursor == nil {
			return controlv1.AvailablePublicURL{}, failure.Wrap("select visitor public URL", failure.ServerResourceNotFound, controlclient.ErrNotFound)
		}
		if *page.NextCursor == cursor {
			return controlv1.AvailablePublicURL{}, failure.Wrap("read visitor inventory", failure.ServerResponseInvalid, errors.New("invalid visitor inventory cursor"))
		}
		cursor = *page.NextCursor
	}
}

func runVisitorCertificate(ctx context.Context, flags visitorCertificateCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.remoteFlags, "tnl url certificate", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	if item.ServiceProtocol != "postgres" && item.ServiceProtocol != "mysql" && item.ServiceProtocol != "redis" {
		return failure.Wrap("select a database public URL", failure.InvalidCommand, errors.New("visitor certificates require a PostgreSQL, MySQL or Redis public URL"))
	}
	certificate, issued, err := createVisitorCertificate(ctx, session.authenticated.Control, item.Id)
	if err != nil {
		return err
	}
	key := certificate.PrivateKey.(*ecdsa.PrivateKey)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err = exportVisitorCertificate(flags.Directory, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), issued, key, time.Now()); err != nil {
		reason := failure.ClientStateUnavailable
		if errors.Is(err, visitorcert.ErrInvalidCertificate) {
			reason = failure.ServerResponseInvalid
		}
		return failure.Wrap("export visitor certificate", reason, err)
	}
	metadata := struct {
		PublicURLID string    `json:"public_url_id"`
		Directory   string    `json:"directory"`
		ExpiresAt   time.Time `json:"expires_at"`
	}{item.Id, flags.Directory, issued.ExpiresAt}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(metadata)
	}
	return writeHumanFrame(output, "tnl url certificate", "saved", "", clioutput.Fields(clioutput.Field{Label: "public URL ID", Value: item.Id}, clioutput.Field{Label: "directory", Value: flags.Directory}, clioutput.Field{Label: "expires", Value: issued.ExpiresAt.UTC().Format(time.RFC3339)}))
}

type visitorCertificateIssuer interface {
	IssueVisitorCertificate(context.Context, string, []byte) (controlv1.VisitorCertificate, error)
}

// createVisitorCertificate keeps its fresh private key in memory. control sees
// only the CSR, and the returned certificate must bind that key to this URL.
func createVisitorCertificate(ctx context.Context, issuer visitorCertificateIssuer, urlID string) (tls.Certificate, controlv1.VisitorCertificate, error) {
	if !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) {
		return tls.Certificate{}, controlv1.VisitorCertificate{}, failure.Wrap("select visitor public URL", failure.ServerResponseInvalid, visitorcert.ErrInvalidCertificate)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, controlv1.VisitorCertificate{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return tls.Certificate{}, controlv1.VisitorCertificate{}, err
	}
	issued, err := issuer.IssueVisitorCertificate(ctx, urlID, csr)
	if err != nil {
		return tls.Certificate{}, controlv1.VisitorCertificate{}, err
	}
	certificate, err := validateVisitorCertificate(issued, key, urlID, time.Now())
	if err != nil {
		return tls.Certificate{}, controlv1.VisitorCertificate{}, failure.Wrap("validate visitor certificate", failure.ServerResponseInvalid, err)
	}
	return certificate, issued, nil
}

// validation mirrors the export boundary without writing a private key to disk.
// the issuer is trusted only for client credentials, never for visitor TLS.
func validateVisitorCertificate(issued controlv1.VisitorCertificate, key *ecdsa.PrivateKey, urlID string, now time.Time) (tls.Certificate, error) {
	invalid := visitorcert.ErrInvalidCertificate
	if key == nil || issued.PublicUrlId != urlID || !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) {
		return tls.Certificate{}, invalid
	}
	block, rest := pem.Decode([]byte(issued.CertificatePem))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, invalid
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, invalid
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) || leaf.IsCA || !leaf.NotAfter.Equal(issued.ExpiresAt) || leaf.NotAfter.Sub(leaf.NotBefore) > visitorcert.MaxLifetime || len(leaf.URIs) != 1 {
		return tls.Certificate{}, invalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(issued.IssuerPem)) {
		return tls.Certificate{}, invalid
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, invalid
	}
	scope := leaf.URIs[0]
	identity, found := strings.CutPrefix(scope.Path, "/"+urlID+"/")
	if !found || !opaqueid.Valid(identity, opaqueid.IdentityPrefix) || scope.Scheme != "tnl" || scope.Host != "visitor" || scope.User != nil || scope.RawPath != "" || scope.RawQuery != "" || scope.Fragment != "" || scope.Opaque != "" {
		return tls.Certificate{}, invalid
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// exportVisitorCertificate validates the certificate and proven local key before
// touching disk. files are exclusive creates in an owner-only directory.
func exportVisitorCertificate(directory string, privatePEM []byte, issued controlv1.VisitorCertificate, key *ecdsa.PrivateKey, now time.Time) (retErr error) {
	return visitorcert.Export(directory, privatePEM, []byte(issued.CertificatePem), []byte(issued.IssuerPem), key, issued.PublicUrlId, issued.ExpiresAt, now)
}
