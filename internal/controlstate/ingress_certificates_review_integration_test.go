package controlstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func ingressTrustReviewDTO(t IngressTransportTrust) controlv1.IngressTransportTrust {
	return controlv1.IngressTransportTrust{IngressId: t.IngressID, IngressRunId: t.IngressRunID, IngressLeaseRevision: int64(t.IngressLeaseRevision), TlsServerName: t.TLSServerName,
		CertificatePem: t.CertificatePEM, IssuerPem: t.IssuerPEM, IssuerRevision: t.IssuerRevision, PublicKeySha256: t.PublicKeySHA256, LeaseUri: t.LeaseURI,
		NotBefore: t.NotBefore, NotAfter: t.NotAfter, ValidUntil: t.ValidUntil}
}

func TestIntegrationIngressTransportCertificateTopologyReview(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "ingress_transport_review")
	owner := oidcRouteRequest(t, d, now)
	service, err := d.CreatePrivateService(t.Context(), owner.TeamID, owner.ActingIdentityID, "database", "create", now)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(t.Context(), owner.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	var leases []IngressLease
	var registrations []IngressRegistration
	var materials []IngressTransportCertificate
	var listeners []net.Listener
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	})
	for index := range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		runID, err := opaqueid.New(opaqueid.IngressRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		registration := IngressRegistration{IngressID: fmt.Sprintf("ingress-%d", index), IngressRunID: runID, ProtocolVersion: 1, ConnectionCapacity: 8,
			PrivateConnectorAddress: listener.Addr().String(), PrivateConnectorTLSServerName: "private-ingress.example.test"}
		lease, err := d.RegisterIngress(t.Context(), registration, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		material, err := d.GetIngressTransportCertificate(t.Context(), lease.IngressLeaseIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		if material.TLSServerName != registration.PrivateConnectorTLSServerName || material.NotAfter.After(lease.LeaseExpiresAt) || !material.NotAfter.After(now) {
			t.Fatal("certificate escaped its registered hostname/lease deadline")
		}
		if strings.Contains(fmt.Sprint(material), "PRIVATE KEY") {
			t.Fatal("certificate material leaks its key through logging")
		}
		keyPair, err := tls.X509KeyPair([]byte(material.CertificatePEM), []byte(material.PrivateKeyPEM))
		if err != nil {
			t.Fatal(err)
		}
		serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{keyPair}}
		workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer connection.Close()
					_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
					secured := tls.Server(connection, serverTLS)
					var request [4]byte
					if _, err := io.ReadFull(secured, request[:]); err == nil {
						_, _ = secured.Write(request[:])
					}
				})
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		})
		leases = append(leases, lease)
		registrations = append(registrations, registration)
		materials = append(materials, material)
	}
	if materials[0].PublicKeySHA256 == materials[1].PublicKeySHA256 || materials[0].IssuerPEM != materials[1].IssuerPEM {
		t.Fatal("node keys are not independent under the shared persistent issuer")
	}
	assignments, err := d.CreateVisitorIngressAssignments(t.Context(), owner.ActingIdentityID, device.ID, service.ID, "startup", now)
	if err != nil || len(assignments) != 2 {
		t.Fatalf("distinct local endpoint assignments: %+v %v", assignments, err)
	}
	if assignments[0].IngressAddress == assignments[1].IngressAddress || assignments[0].IngressID == assignments[1].IngressID {
		t.Fatal("local topology collapsed two ingress endpoint leases")
	}
	for _, assignment := range assignments {
		trust, err := d.GetVisitorIngressTransportTrust(t.Context(), owner.ActingIdentityID, assignment.ID, now)
		if err != nil {
			t.Fatal(err)
		}
		if trust.IngressID != assignment.IngressID || trust.TLSServerName != assignment.TLSServerName {
			t.Fatal("assignment trust changed peer identity")
		}
		config, err := controlclient.IngressTransportTLSConfig(ingressTrustReviewDTO(trust))
		if err != nil {
			t.Fatal(err)
		}
		if config.InsecureSkipVerify || config.RootCAs == nil {
			t.Fatal("infrastructure TLS bypassed normal verification")
		}
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", assignment.IngressAddress, config)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, err = connection.Write([]byte("ping"))
		if err != nil {
			t.Fatal(err)
		}
		var response [4]byte
		if _, err = io.ReadFull(connection, response[:]); err != nil || string(response[:]) != "ping" {
			t.Fatalf("verified local ingress transport: %q %v", response, err)
		}
		_ = connection.Close()
		otherAddress := registrations[0].PrivateConnectorAddress
		if otherAddress == assignment.IngressAddress {
			otherAddress = registrations[1].PrivateConnectorAddress
		}
		// both nodes use the same DNS identity and issuer: only the exact
		// process-key/URI pin distinguishes the wrong live ingress.
		if wrong, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", otherAddress, config); err == nil {
			_ = wrong.Close()
			t.Fatal("another live ingress passed this assignment's pin")
		}
		bad := ingressTrustReviewDTO(trust)
		bad.TlsServerName = "other.example.test"
		if _, err = controlclient.IngressTransportTLSConfig(bad); err == nil {
			t.Fatal("wrong transport hostname was accepted")
		}
		if _, err = d.GetVisitorIngressTransportTrust(t.Context(), "another-identity", assignment.ID, now); !errors.Is(err, ErrPrivateServiceAccess) {
			t.Fatalf("another identity read device assignment trust: %v", err)
		}
	}
	block, _ := pem.Decode([]byte(materials[0].CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0].String() != materials[0].LeaseURI {
		t.Fatal("transport leaf lacks its exact process lease binding", err)
	}
	var issuances, issuers int
	if err = d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.acme_orders),(SELECT count(*) FROM control.ingress_transport_issuers)`).Scan(&issuances, &issuers); err != nil || issuances != 0 || issuers != 1 {
		t.Fatalf("infrastructure transport used public URL issuance: %d/%d %v", issuances, issuers, err)
	}
	var ciphertext []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT private_key_ciphertext FROM control.ingress_transport_certificates WHERE ingress_id=$1`, leases[0].IngressID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("PRIVATE KEY")) {
		t.Fatal("node key was not encrypted at rest", err)
	}
	conflict := registrations[0]
	conflict.PrivateConnectorAddress = "127.0.0.1:1"
	if _, err = d.RegisterIngress(t.Context(), conflict, now.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatalf("live process changed its advertised certificate endpoint: %v", err)
	}
	renewed, err := d.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: leases[0].IngressLeaseIdentity}, now.Add(time.Second), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := d.GetIngressTransportCertificate(t.Context(), renewed.IngressLeaseIdentity, now.Add(time.Second))
	if err != nil || refreshed.PublicKeySHA256 != materials[0].PublicKeySHA256 || !refreshed.NotAfter.After(materials[0].NotAfter) {
		t.Fatalf("lease renewal rotated the process pin or failed to renew: %+v %v", refreshed.IngressTransportTrust, err)
	}
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	rotated, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotated.Close)
	if err = rotated.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := rotated.GetIngressTransportCertificate(t.Context(), renewed.IngressLeaseIdentity, now.Add(time.Second))
	if err != nil || after.PublicKeySHA256 != refreshed.PublicKeySHA256 {
		t.Fatal("storage rotation lost the infrastructure signing keys", err)
	}
	replaceAt := renewed.LeaseExpiresAt
	replacement := registrations[0]
	replacement.IngressRunID, _ = opaqueid.New(opaqueid.IngressRunPrefix)
	current, err := rotated.RegisterIngress(t.Context(), replacement, replaceAt, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rotated.GetIngressTransportCertificate(t.Context(), renewed.IngressLeaseIdentity, replaceAt); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("stale process fetched a transport private key: %v", err)
	}
	newMaterial, err := rotated.GetIngressTransportCertificate(t.Context(), current.IngressLeaseIdentity, replaceAt)
	if err != nil || newMaterial.PublicKeySHA256 == after.PublicKeySHA256 {
		t.Fatal("restarted ingress reused a previous process key", err)
	}
	if _, err = rotated.GetVisitorIngressTransportTrust(t.Context(), owner.ActingIdentityID, assignments[0].ID, replaceAt); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("old assignment trusted a replacement process: %v", err)
	}
	if err = rotated.RevokeVisitorDevice(t.Context(), owner.ActingIdentityID, device.ID, replaceAt); err != nil {
		t.Fatal(err)
	}
	if _, err = rotated.GetVisitorIngressTransportTrust(t.Context(), owner.ActingIdentityID, assignments[1].ID, replaceAt); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatalf("revoked device read transport trust: %v", err)
	}
}
