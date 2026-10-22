package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) GetVisitorIngressTransportTrust(ctx context.Context, sessionID string) (controlv1.IngressTransportTrust, error) {
	return requestWithAccess[controlv1.IngressTransportTrust](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetVisitorIngressTransportTrust(ctx, sessionID, editors...)
	})
}

// the control HTTPS response authenticates this private transport trust anchor.
// normal chain/hostname verification stays enabled; the extra pin binds the
// peer key and URI to one ingress process lease, for either QUIC or TLS/TCP.
func IngressTransportTLSConfig(trust controlv1.IngressTransportTrust) (*tls.Config, error) {
	invalid := errors.New("controlclient: invalid ingress transport trust")
	if trust.IngressId == "" || trust.IngressRunId == "" || trust.IngressLeaseRevision < 1 || trust.TlsServerName == "" || len(trust.IssuerPem) > 131072 || len(trust.CertificatePem) > 65536 || !trust.ValidUntil.After(time.Now()) {
		return nil, invalid
	}
	identityURI := url.URL{Scheme: "tnl", Host: "ingress", Path: "/" + trust.IngressId + "/" + trust.IngressRunId + "/" + strconv.FormatInt(trust.IngressLeaseRevision, 10)}
	identityURI.RawPath = "/" + url.PathEscape(trust.IngressId) + "/" + url.PathEscape(trust.IngressRunId) + "/" + strconv.FormatInt(trust.IngressLeaseRevision, 10)
	if identityURI.String() != trust.LeaseUri || trust.ValidUntil.After(trust.NotAfter) {
		return nil, invalid
	}
	pin, err := hex.DecodeString(trust.PublicKeySha256)
	if err != nil || len(pin) != sha256.Size || hex.EncodeToString(pin) != trust.PublicKeySha256 {
		return nil, invalid
	}
	roots := x509.NewCertPool()
	remaining := []byte(trust.IssuerPem)
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(remaining), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, invalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, invalid
		}
		roots.AddCert(certificate)
		remaining = rest
		count++
		if count > 2 {
			return nil, invalid
		}
	}
	if count == 0 {
		return nil, invalid
	}
	block, rest := pem.Decode([]byte(trust.CertificatePem))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, invalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, invalid
	}
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: trust.TlsServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, invalid
	}
	verify := func(peer *x509.Certificate) error {
		digest := sha256.Sum256(peer.RawSubjectPublicKeyInfo)
		if peer.VerifyHostname(trust.TlsServerName) != nil || !bytes.Equal(digest[:], pin) || len(peer.URIs) != 1 || peer.URIs[0].String() != trust.LeaseUri || !time.Now().Before(trust.ValidUntil) {
			return invalid
		}
		return nil
	}
	if err = verify(certificate); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: trust.TlsServerName, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
			return invalid
		}
		return verify(state.PeerCertificates[0])
	}}, nil
}
