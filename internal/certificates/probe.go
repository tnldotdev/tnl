package certificates

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/sourceauth"
	"github.com/tnldotdev/tnl/internal/worker"
	"golang.org/x/crypto/acme"
)

var acmeIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ProbeTLSALPN verifies challenge material through the assigned route backend.
func ProbeTLSALPN(ctx context.Context, backend worker.RouteBackend, sourceKey [32]byte, issuance Issuance) error {
	if backend == nil || issuance.Challenge() == nil {
		return errors.New("certificates: route challenge is unavailable")
	}
	stream, err := backend.Open(ctx)
	if err != nil {
		return fmt.Errorf("certificates: open route challenge: %w", err)
	}
	defer stream.Close()
	deadline := time.Now().Add(10 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return fmt.Errorf("certificates: set challenge probe deadline: %w", err)
	}
	if err := sourceauth.Client(stream, sourceKey, sourceauth.PurposeACME, proxyproto.Header{
		Source:      netip.MustParseAddrPort("127.0.0.1:1"),
		Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	}); err != nil {
		return fmt.Errorf("certificates: authenticate challenge source: %w", err)
	}
	connection := tls.Client(stream, &tls.Config{
		ServerName: issuance.Hostname, NextProtos: []string{acme.ALPNProto}, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, // The self-signed challenge is verified below by its ACME digest.
		VerifyConnection: func(status tls.ConnectionState) error {
			return verifyChallengeConnection(status, issuance)
		},
	})
	if err := connection.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("certificates: challenge TLS handshake: %w", err)
	}
	return nil
}

func verifyChallengeConnection(status tls.ConnectionState, issuance Issuance) error {
	if status.NegotiatedProtocol != acme.ALPNProto || len(status.PeerCertificates) != 1 {
		return errors.New("certificates: challenge negotiated unexpected TLS status")
	}
	certificate := status.PeerCertificates[0]
	if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != issuance.Hostname ||
		len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.URIs) != 0 ||
		certificate.IsCA || certificate.NotBefore.After(time.Now().Add(certificateSkew)) || !certificate.NotAfter.After(time.Now()) {
		return errors.New("certificates: challenge certificate identity is invalid")
	}
	if err := certificate.CheckSignature(
		certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature,
	); err != nil || !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
		return errors.New("certificates: challenge certificate is not self-signed")
	}
	found := false
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(acmeIdentifierOID) {
			continue
		}
		if found || !extension.Critical {
			return errors.New("certificates: challenge extension is invalid")
		}
		found = true
		var digest []byte
		rest, err := asn1.Unmarshal(extension.Value, &digest)
		if err != nil || len(rest) != 0 || subtle.ConstantTimeCompare(digest, issuance.ChallengeDigest[:]) != 1 {
			return errors.New("certificates: challenge digest does not match")
		}
	}
	if !found {
		return errors.New("certificates: challenge extension is missing")
	}
	return nil
}
