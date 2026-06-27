// Package serviceenrollment obtains and validates process-local service identities.
package serviceenrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const renewalInterval = 30 * time.Minute

// Client is the public control API operation needed for service enrollment.
type Client interface {
	EnrollServiceWithResponse(
		context.Context,
		controlv1.EnrollServiceJSONRequestBody,
		...controlv1.RequestEditorFn,
	) (*controlv1.EnrollServiceResponse, error)
}

// Config identifies one process and its enrollment credential.
type Config struct {
	Client                 Client
	ControlHostname        string
	ServiceEnrollmentToken credentials.ServiceEnrollmentToken
	Role                   servicepki.Role
	ProcessID              string
	Now                    func() time.Time
}

// Enrollment is validated service identity and trust material.
type Enrollment struct {
	Role                      servicepki.Role
	ProcessID                 string
	RelayServiceID            string
	RelayAddress              string
	TLSServerName             string
	InternalControlEndpoint   string
	ServiceCertificate        tls.Certificate
	TrustBundle               *x509.CertPool
	TrustBundlePEM            string
	CertificateExpiresAt      time.Time
	RenewAt                   time.Time
	RelayTransportCertificate *tls.Certificate
}

// InternalControlTLSConfig returns scoped mTLS for the enrolled role's private control API.
func (e Enrollment) InternalControlTLSConfig() (*tls.Config, error) {
	endpoint, err := url.Parse(e.InternalControlEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return nil, errors.New("serviceenrollment: internal control endpoint is invalid")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   endpoint.Hostname(),
		RootCAs:      e.TrustBundle,
		Certificates: []tls.Certificate{e.ServiceCertificate},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("serviceenrollment: internal control server certificate is missing")
			}
			role, err := servicepki.InternalControlCertificateRole(state.PeerCertificates[0])
			if err != nil || role != e.Role {
				return errors.New("serviceenrollment: internal control server certificate has the wrong role")
			}
			return nil
		},
	}, nil
}

// Enroller retains one process-local key across initial enrollment and renewal.
type Enroller struct {
	client          Client
	controlHostname string
	token           credentials.ServiceEnrollmentToken
	role            servicepki.Role
	processID       string
	privateKeyPEM   []byte
	csrPEM          string
	now             func() time.Time
}

// New generates the process-local key and CSR. The private key is never sent to control.
func New(config Config) (*Enroller, error) {
	return newEnroller(config, true)
}

// NewLocal creates an enroller for an in-process role whose client is
// authorized by control without a service enrollment token.
func NewLocal(config Config) (*Enroller, error) {
	return newEnroller(config, false)
}

func newEnroller(config Config, requireToken bool) (*Enroller, error) {
	if config.Client == nil {
		return nil, errors.New("serviceenrollment: control client is required")
	}
	canonicalHostname, err := naming.CanonicalizeHostname(config.ControlHostname)
	if err != nil || canonicalHostname != config.ControlHostname {
		return nil, errors.New("serviceenrollment: control hostname must be canonical")
	}
	if requireToken {
		if _, _, err := credentials.ParseServiceEnrollmentToken(config.ServiceEnrollmentToken); err != nil {
			return nil, err
		}
	} else if config.ServiceEnrollmentToken != "" {
		return nil, errors.New("serviceenrollment: local enrollment cannot use a token")
	}
	if config.Role != servicepki.RoleIngress && config.Role != servicepki.RoleRelay {
		return nil, errors.New("serviceenrollment: role must be ingress or relay")
	}
	if !validProcessID(config.ProcessID) {
		return nil, errors.New("serviceenrollment: process identity is invalid")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("serviceenrollment: generate process key: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("serviceenrollment: encode process key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("serviceenrollment: create CSR: %w", err)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Enroller{
		client: config.Client, controlHostname: config.ControlHostname, token: config.ServiceEnrollmentToken,
		role: config.Role, processID: config.ProcessID,
		privateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
		csrPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		now:           config.Now,
	}, nil
}

// Enroll obtains or renews the certificate for the enroller's process-local key.
func (e *Enroller) Enroll(ctx context.Context) (Enrollment, error) {
	request := controlv1.ServiceEnrollmentRequest{
		ServiceEnrollmentToken: e.token.String(), Role: controlv1.ServiceEnrollmentRole(e.role),
		CertificateSigningRequest: e.csrPEM,
	}
	if e.role == servicepki.RoleIngress {
		request.IngressId = &e.processID
	} else {
		request.RelayId = &e.processID
	}
	response, err := e.client.EnrollServiceWithResponse(ctx, request)
	if err != nil {
		return Enrollment{}, fmt.Errorf("serviceenrollment: enroll with control: %w", err)
	}
	if response == nil {
		return Enrollment{}, errors.New("serviceenrollment: control returned no enrollment response")
	}
	if response.JSON200 == nil {
		if response.ApplicationproblemJSONDefault != nil {
			return Enrollment{}, fmt.Errorf(
				"serviceenrollment: control returned %d (%s): %s",
				response.StatusCode(), response.ApplicationproblemJSONDefault.Code, problemDetail(response.ApplicationproblemJSONDefault),
			)
		}
		return Enrollment{}, fmt.Errorf("serviceenrollment: control returned HTTP %d", response.StatusCode())
	}
	return e.validate(*response.JSON200)
}

func (e *Enroller) validate(response controlv1.ServiceEnrollmentResponse) (Enrollment, error) {
	now := e.now().UTC()
	if servicepki.Role(response.Role) != e.role || response.CertificateExpiresAt.IsZero() {
		return Enrollment{}, errors.New("serviceenrollment: control returned the wrong service identity")
	}
	expectedEndpoint := "https://" + net.JoinHostPort(e.controlHostname, rolePort(e.role))
	if response.InternalControlEndpoint != expectedEndpoint {
		return Enrollment{}, errors.New("serviceenrollment: control returned an unexpected internal endpoint")
	}
	trustBundle, authorities, err := parseTrustBundle(response.TrustBundle)
	if err != nil {
		return Enrollment{}, err
	}
	serviceCertificate, err := tls.X509KeyPair([]byte(response.ServiceCertificate), e.privateKeyPEM)
	if err != nil {
		return Enrollment{}, fmt.Errorf("serviceenrollment: parse service certificate: %w", err)
	}
	serviceLeaf, err := certificateLeaf(&serviceCertificate)
	if err != nil {
		return Enrollment{}, err
	}
	identity, err := servicepki.CertificateIdentity(serviceLeaf)
	if err != nil || identity.Role != e.role || identity.ProcessID != e.processID {
		return Enrollment{}, errors.New("serviceenrollment: service certificate identity does not match this process")
	}
	if !serviceLeaf.NotAfter.Equal(response.CertificateExpiresAt) {
		return Enrollment{}, errors.New("serviceenrollment: service certificate expiration does not match the response")
	}
	if _, err := serviceLeaf.Verify(x509.VerifyOptions{
		Roots: trustBundle, Intermediates: certificateIntermediates(serviceCertificate.Certificate),
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Enrollment{}, fmt.Errorf("serviceenrollment: verify service certificate: %w", err)
	}
	result := Enrollment{
		Role: e.role, ProcessID: e.processID, InternalControlEndpoint: response.InternalControlEndpoint,
		ServiceCertificate: serviceCertificate, TrustBundle: trustBundle, TrustBundlePEM: response.TrustBundle,
		CertificateExpiresAt: response.CertificateExpiresAt, RenewAt: now.Add(renewalInterval),
	}
	if !result.RenewAt.Before(result.CertificateExpiresAt) {
		return Enrollment{}, errors.New("serviceenrollment: service certificate expires before renewal")
	}
	if e.role == servicepki.RoleIngress {
		if response.RelayServiceId != nil || response.RelayAddress != nil || response.TlsServerName != nil ||
			response.RelayTransportCertificate != nil || response.RelayTransportPrivateKey != nil {
			return Enrollment{}, errors.New("serviceenrollment: ingress response contains relay material")
		}
		return result, nil
	}
	if response.RelayServiceId == nil || response.RelayAddress == nil || response.TlsServerName == nil ||
		response.RelayTransportCertificate == nil || response.RelayTransportPrivateKey == nil {
		return Enrollment{}, errors.New("serviceenrollment: relay response is missing relay service material")
	}
	if !validProcessID(*response.RelayServiceId) || !validRelayAddress(*response.RelayAddress, *response.TlsServerName) {
		return Enrollment{}, errors.New("serviceenrollment: relay response contains invalid stable facts")
	}
	if identity.RelayServiceID != *response.RelayServiceId {
		return Enrollment{}, errors.New("serviceenrollment: relay certificate has the wrong relay service identity")
	}
	transportCertificate, err := tls.X509KeyPair(
		[]byte(*response.RelayTransportCertificate), []byte(*response.RelayTransportPrivateKey),
	)
	if err != nil {
		return Enrollment{}, fmt.Errorf("serviceenrollment: parse relay transport certificate: %w", err)
	}
	transportLeaf, err := certificateLeaf(&transportCertificate)
	if err != nil {
		return Enrollment{}, err
	}
	if _, err := transportLeaf.Verify(x509.VerifyOptions{
		DNSName: *response.TlsServerName, Roots: trustBundle,
		Intermediates: certificateIntermediates(transportCertificate.Certificate),
		CurrentTime:   now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return Enrollment{}, fmt.Errorf("serviceenrollment: verify relay transport certificate: %w", err)
	}
	if !signedByTrustBundle(transportLeaf, authorities) {
		return Enrollment{}, errors.New("serviceenrollment: relay transport certificate was not issued by the enrollment trust bundle")
	}
	result.RelayServiceID = *response.RelayServiceId
	result.RelayAddress = *response.RelayAddress
	result.TLSServerName = *response.TlsServerName
	result.RelayTransportCertificate = &transportCertificate
	return result, nil
}

func parseTrustBundle(value string) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	authorities := make([]*x509.Certificate, 0, 1)
	remainder := []byte(value)
	for len(bytes.TrimSpace(remainder)) != 0 {
		block, rest := pem.Decode(remainder)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("serviceenrollment: trust bundle is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil {
			return nil, nil, errors.New("serviceenrollment: trust bundle contains an invalid authority")
		}
		pool.AddCert(certificate)
		authorities = append(authorities, certificate)
		remainder = rest
	}
	if len(authorities) == 0 {
		return nil, nil, errors.New("serviceenrollment: trust bundle is empty")
	}
	return pool, authorities, nil
}

func certificateLeaf(certificate *tls.Certificate) (*x509.Certificate, error) {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("serviceenrollment: certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("serviceenrollment: parse certificate leaf: %w", err)
	}
	certificate.Leaf = leaf
	return leaf, nil
}

func certificateIntermediates(chain [][]byte) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, encoded := range chain[1:] {
		if certificate, err := x509.ParseCertificate(encoded); err == nil {
			pool.AddCert(certificate)
		}
	}
	return pool
}

func signedByTrustBundle(certificate *x509.Certificate, authorities []*x509.Certificate) bool {
	for _, authority := range authorities {
		if certificate.CheckSignatureFrom(authority) == nil {
			return true
		}
	}
	return false
}

func validRelayAddress(address, serverName string) bool {
	host, port, err := net.SplitHostPort(address)
	canonical, canonicalErr := naming.CanonicalizeHostname(serverName)
	return err == nil && port == "443" && host == serverName && canonicalErr == nil && canonical == serverName
}

func validProcessID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}

func rolePort(role servicepki.Role) string {
	if role == servicepki.RoleIngress {
		return "9443"
	}
	return "9444"
}

func problemDetail(problem *controlv1.Problem) string {
	if problem.Detail != nil {
		return *problem.Detail
	}
	return problem.Title
}
