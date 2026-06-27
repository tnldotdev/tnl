package serviceenrollment

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestEnrollerValidatesIngressAndRelayMaterial(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 123456789, time.UTC)
	authority, err := servicepki.GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name           string
		role           servicepki.Role
		processID      string
		relayServiceID string
	}{
		{name: "ingress", role: servicepki.RoleIngress, processID: "ingress-a"},
		{name: "relay", role: servicepki.RoleRelay, processID: "relay-a-1", relayServiceID: "relay-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			token, _, _, err := credentials.NewServiceEnrollmentToken()
			if err != nil {
				t.Fatal(err)
			}
			client := &fakeEnrollmentClient{
				authority: authority, now: now, role: test.role,
				processID: test.processID, relayServiceID: test.relayServiceID,
			}
			enroller, err := New(Config{
				Client: client, ControlHostname: "control.example.test", ServiceEnrollmentToken: token,
				Role: test.role, ProcessID: test.processID, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := enroller.Enroll(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if enrollment.Role != test.role || enrollment.ProcessID != test.processID ||
				enrollment.RelayServiceID != test.relayServiceID || enrollment.ServiceCertificate.Leaf == nil ||
				!enrollment.RenewAt.Equal(now.Add(renewalInterval)) {
				t.Fatalf("enrollment = %#v", enrollment)
			}
			if test.role == servicepki.RoleRelay && enrollment.RelayTransportCertificate == nil {
				t.Fatal("relay transport certificate is missing")
			}
			if client.request.CertificateSigningRequest == "" || client.request.ServiceEnrollmentToken != token.String() {
				t.Fatalf("request = %#v", client.request)
			}
			tlsConfig, err := enrollment.InternalControlTLSConfig()
			if err != nil || tlsConfig.ServerName != "control.example.test" || len(tlsConfig.Certificates) != 1 {
				t.Fatalf("internal control TLS = %#v, %v", tlsConfig, err)
			}
		})
	}
}

func TestEnrollerRejectsWrongCertificateIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := servicepki.GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewServiceEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeEnrollmentClient{
		authority: authority, now: now, role: servicepki.RoleIngress, processID: "other-ingress",
	}
	enroller, err := New(Config{
		Client: client, ControlHostname: "control.example.test", ServiceEnrollmentToken: token,
		Role: servicepki.RoleIngress, ProcessID: "ingress-a", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enroller.Enroll(t.Context()); err == nil {
		t.Fatal("wrong certificate identity accepted")
	}
}

func TestNewLocalRejectsEnrollmentToken(t *testing.T) {
	token, _, _, err := credentials.NewServiceEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewLocal(Config{
		Client: new(fakeEnrollmentClient), ControlHostname: "control.example.test",
		ServiceEnrollmentToken: token, Role: servicepki.RoleIngress, ProcessID: "ingress-a",
	})
	if err == nil {
		t.Fatal("local enrollment accepted a service enrollment token")
	}
}

func TestStateRotatesRelayCertificatesWithoutChangingStableFacts(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	authority, err := servicepki.GenerateAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewServiceEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeEnrollmentClient{
		authority: authority, now: now, role: servicepki.RoleRelay,
		processID: "relay-a-1", relayServiceID: "relay-a",
	}
	enroller, err := New(Config{
		Client: client, ControlHostname: "control.example.test", ServiceEnrollmentToken: token,
		Role: servicepki.RoleRelay, ProcessID: "relay-a-1", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewState(t.Context(), enroller)
	if err != nil {
		t.Fatal(err)
	}
	state.now = func() time.Time { return now }
	initial := state.Enrollment()

	now = now.Add(31 * time.Minute)
	client.now = now
	renewed, err := enroller.Enroll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.replace(renewed); err != nil {
		t.Fatal(err)
	}
	current := state.Enrollment()
	if current.ServiceCertificate.Leaf.SerialNumber.Cmp(initial.ServiceCertificate.Leaf.SerialNumber) == 0 ||
		current.RelayTransportCertificate.Leaf.SerialNumber.Cmp(initial.RelayTransportCertificate.Leaf.SerialNumber) == 0 {
		t.Fatal("renewal did not rotate both relay certificates")
	}
	controlTLS, err := state.InternalControlTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	serviceCertificate, err := controlTLS.GetClientCertificate(nil)
	if err != nil || serviceCertificate.Leaf.SerialNumber.Cmp(current.ServiceCertificate.Leaf.SerialNumber) != 0 {
		t.Fatalf("current service certificate = %#v, %v", serviceCertificate, err)
	}
	transportTLS, err := state.RelayTransportTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	transportCertificate, err := transportTLS.GetCertificate(nil)
	if err != nil || transportCertificate.Leaf.SerialNumber.Cmp(current.RelayTransportCertificate.Leaf.SerialNumber) != 0 {
		t.Fatalf("current relay transport certificate = %#v, %v", transportCertificate, err)
	}

	changed := renewed
	changed.RelayAddress = "other.example.test:443"
	if err := state.replace(changed); err == nil {
		t.Fatal("renewal changed stable relay address")
	}
	if state.Enrollment().RelayAddress != current.RelayAddress {
		t.Fatal("rejected renewal replaced current enrollment")
	}

	now = now.Add(2 * time.Hour)
	if state.Ready(now) {
		t.Fatal("expired enrollment remained ready")
	}
	if _, err := controlTLS.GetClientCertificate(nil); err == nil {
		t.Fatal("expired service certificate remained available")
	}
	if _, err := transportTLS.GetCertificate(nil); err == nil {
		t.Fatal("expired relay transport certificate remained available")
	}
}

func TestStateRunSchedulesRenewalWithItsClock(t *testing.T) {
	base := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	renewed := make(chan struct{})
	calls := 0
	source := enrollmentSourceFunc(func(context.Context) (Enrollment, error) {
		calls++
		renewAt := base.Add(time.Minute)
		if calls > 1 {
			renewAt = base.Add(time.Hour)
			close(renewed)
		}
		return Enrollment{
			Role: servicepki.RoleIngress, ProcessID: "ingress-a",
			InternalControlEndpoint: "https://control.example.test:9443",
			CertificateExpiresAt:    base.Add(2 * time.Hour), RenewAt: renewAt,
		}, nil
	})
	state, err := NewState(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	state.now = func() time.Time { return base.Add(2 * time.Minute) }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- state.Run(ctx, time.Second, nil) }()
	select {
	case <-renewed:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("renewal did not use the state clock")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type enrollmentSourceFunc func(context.Context) (Enrollment, error)

func (f enrollmentSourceFunc) Enroll(ctx context.Context) (Enrollment, error) { return f(ctx) }

type fakeEnrollmentClient struct {
	authority      servicepki.Authority
	now            time.Time
	role           servicepki.Role
	processID      string
	relayServiceID string
	request        controlv1.ServiceEnrollmentRequest
}

func (c *fakeEnrollmentClient) EnrollServiceWithResponse(
	_ context.Context,
	request controlv1.EnrollServiceJSONRequestBody,
	_ ...controlv1.RequestEditorFn,
) (*controlv1.EnrollServiceResponse, error) {
	c.request = request
	issued, err := servicepki.SignServiceCSR(c.authority, servicepki.Identity{
		Role: c.role, ProcessID: c.processID, RelayServiceID: c.relayServiceID,
	}, request.CertificateSigningRequest, c.now, time.Hour)
	if err != nil {
		return nil, err
	}
	response := controlv1.ServiceEnrollmentResponse{
		Role: controlv1.ServiceEnrollmentRole(c.role), ServiceCertificate: issued.CertificatePEM,
		TrustBundle: c.authority.CertificatePEM, CertificateExpiresAt: issued.ExpiresAt,
		InternalControlEndpoint: "https://control.example.test:" + rolePort(c.role),
	}
	if c.role == servicepki.RoleRelay {
		address, serverName, relayServiceID := "relay-a.example.test:443", "relay-a.example.test", c.relayServiceID
		transport, err := servicepki.IssueRelayTransportCertificate(c.authority, serverName, c.now, time.Hour)
		if err != nil {
			return nil, err
		}
		response.RelayServiceId = &relayServiceID
		response.RelayAddress = &address
		response.TlsServerName = &serverName
		response.RelayTransportCertificate = &transport.CertificatePEM
		response.RelayTransportPrivateKey = &transport.PrivateKeyPEM
	}
	return &controlv1.EnrollServiceResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK}, JSON200: &response,
	}, nil
}
