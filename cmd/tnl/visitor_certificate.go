package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	issued, err := session.authenticated.Control.IssueVisitorCertificate(ctx, item.Id, csr)
	if err != nil {
		return err
	}
	if issued.PublicUrlId != item.Id {
		return failure.Wrap("validate visitor certificate", failure.ServerResponseInvalid, errors.New("certificate response has a different public URL"))
	}
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

// exportVisitorCertificate validates the certificate and proven local key before
// touching disk. files are exclusive creates in an owner-only directory.
func exportVisitorCertificate(directory string, privatePEM []byte, issued controlv1.VisitorCertificate, key *ecdsa.PrivateKey, now time.Time) (retErr error) {
	return visitorcert.Export(directory, privatePEM, []byte(issued.CertificatePem), []byte(issued.IssuerPem), key, issued.PublicUrlId, issued.ExpiresAt, now)
}
