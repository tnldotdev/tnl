package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publishingCertificateRequest(t *testing.T, f *PublishingFixture, method, path, token, key string, body any, status int) []byte {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, f.URL+path, bytes.NewReader(payload))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response := httptest.NewRecorder()
	f.serve(response, request)
	if response.Code != status {
		t.Fatalf("%s %s: got HTTP %d, want %d", method, path, response.Code, status)
	}
	return response.Body.Bytes()
}

func publishingCertificateService(t *testing.T, f *PublishingFixture, name string) controlv1.Service {
	t.Helper()
	configuration := controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocolHTTP),
		DomainId: new("dom_0000000000000000000001"), Hostname: new("cache." + f.Namespace), Target: "app", Public: new(true)}
	payload := publishingCertificateRequest(t, f, http.MethodPost, "/v1/services", f.AccessToken, publishingID(t, opaqueid.IdempotencyPrefix),
		controlv1.CreateServiceRequest{TeamId: "tm_0000000000000000000001", Name: name, Configuration: &configuration}, http.StatusCreated)
	var service controlv1.Service
	if err := json.Unmarshal(payload, &service); err != nil {
		t.Fatal(err)
	}
	return service
}

func publishingCertificateRun(t *testing.T, f *PublishingFixture, service controlv1.Service, publisher string) *publishingRunState {
	t.Helper()
	key := publishingID(t, opaqueid.IdempotencyPrefix)
	// the backend consumes identity facts verified by its caller. this owner
	// test supplies only that input, not a grant or a replacement setup.
	// the installed composition exercises the actual signed enrollment.
	f.BindPublisher(key, authorityv1.PublisherEnrollmentResult{ClientId: publisher, TeamId: service.TeamId})
	payload := publishingCertificateRequest(t, f, http.MethodPost, "/v1/services/"+service.Id+"/runs", "", key,
		controlv1.ServiceRunDeclaration{Protocol: service.Protocol, TrustRevision: service.TrustRevision}, http.StatusOK)
	var preparation controlv1.ServiceRunPreparation
	if err := json.Unmarshal(payload, &preparation); err != nil {
		t.Fatal(err)
	}
	payload = publishingCertificateRequest(t, f, http.MethodPost, "/v1/services/"+service.Id+"/runs/"+preparation.ServiceRunId+"/start", "", "",
		controlv1.StartServiceRunJSONRequestBody{RunNumber: preparation.RunNumber}, http.StatusOK)
	var setup controlv1.ServiceRunSetup
	if err := json.Unmarshal(payload, &setup); err != nil || setup.ServiceRunId != preparation.ServiceRunId || setup.RunNumber != preparation.RunNumber || setup.RunToken == "" {
		t.Fatal("actual fixture preparation/start lost its run binding", err)
	}
	f.mu.Lock()
	run := f.runs[setup.ServiceRunId]
	f.mu.Unlock()
	if run == nil {
		t.Fatal("actual fixture start has no retained run")
	}
	return run
}

func publishingCertificateIssue(t *testing.T, f *PublishingFixture, run *publishingRunState) controlv1.ServiceCertificateIssuance {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: run.Preparation.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	payload := publishingCertificateRequest(t, f, http.MethodPost, "/v1/services/"+run.Service.Id+"/runs/"+run.Setup.ServiceRunId+"/certificate-issuances",
		run.Setup.RunToken, publishingID(t, opaqueid.IdempotencyPrefix), controlv1.CreateServiceCertificateIssuanceRequest{RunNumber: run.Setup.RunNumber, Csr: csr}, http.StatusOK)
	var issuance controlv1.ServiceCertificateIssuance
	if err := json.Unmarshal(payload, &issuance); err != nil || issuance.Id == "" || issuance.CertificatePem == nil || issuance.NotAfter == nil {
		t.Fatal("fixture did not retain actual issued material", err)
	}
	return issuance
}

func TestPublishingFixtureRetainedCertificateInstallation(t *testing.T) {
	if !IsolatedPublishingTest(t) {
		return
	}
	f := NewPublishingFixture(t, PublishingHooks{})
	service := publishingCertificateService(t, f, "cache")
	publisher := publishingID(t, opaqueid.PublisherIdentityPrefix)
	origin := publishingCertificateRun(t, f, service, publisher)
	issued := publishingCertificateIssue(t, f, origin)
	publishingCertificateRequest(t, f, http.MethodDelete, "/v1/services/"+service.Id+"/runs/"+origin.Setup.ServiceRunId, origin.Setup.RunToken, "", nil, http.StatusNoContent)
	current := publishingCertificateRun(t, f, service, publisher)
	if !origin.closed || current.Setup.RunNumber != origin.Setup.RunNumber+1 || current.Setup.ServiceRunId == origin.Setup.ServiceRunId || current.issuance != nil {
		t.Fatal("replacement did not retain the closed issuer and its distinct current run")
	}
	foreignService := publishingCertificateService(t, f, "foreign")
	foreign := publishingCertificateRun(t, f, foreignService, publishingID(t, opaqueid.PublisherIdentityPrefix))
	foreignIssued := publishingCertificateIssue(t, f, foreign)
	path := "/v1/services/" + service.Id + "/runs/" + current.Setup.ServiceRunId + "/certificate-installed"
	body := controlv1.ServiceCertificateInstalledRequest{RunNumber: current.Setup.RunNumber, IssuanceId: issued.Id, NotAfter: *issued.NotAfter}
	originalRun := publishingClone(origin.PublishingRun)
	currentRun := publishingClone(current.PublishingRun)
	originalIssuance := publishingClone(*origin.issuance)
	originalCSR := append([]byte(nil), origin.csr...)
	unknownIssuance := publishingID(t, opaqueid.IssuancePrefix)
	restore := func() {
		origin.PublishingRun = publishingClone(originalRun)
		current.PublishingRun = publishingClone(currentRun)
		issuance := publishingClone(originalIssuance)
		origin.issuance = &issuance
		origin.csr = append([]byte(nil), originalCSR...)
		current.installed = false
	}
	for _, test := range []struct {
		name   string
		change func(*controlv1.ServiceCertificateInstalledRequest)
	}{
		{"unknown_issuance", func(b *controlv1.ServiceCertificateInstalledRequest) {
			b.IssuanceId = unknownIssuance
		}},
		{"foreign_retained_issuance", func(b *controlv1.ServiceCertificateInstalledRequest) {
			b.IssuanceId, b.NotAfter = foreignIssued.Id, *foreignIssued.NotAfter
		}},
		{"publisher", func(*controlv1.ServiceCertificateInstalledRequest) {
			current.Preparation.PublisherIdentityId = foreign.Preparation.PublisherIdentityId
		}},
		{"team_owner", func(*controlv1.ServiceCertificateInstalledRequest) { current.Preparation.TeamId = "tm_other" }},
		{"guest_owner", func(*controlv1.ServiceCertificateInstalledRequest) { current.Preparation.GuestId = "guest_other" }},
		{"domain", func(*controlv1.ServiceCertificateInstalledRequest) { current.Preparation.DomainId = "dom_other" }},
		{"plan_cache_key", func(*controlv1.ServiceCertificateInstalledRequest) {
			current.Preparation.CertificatePlan.CacheKey += "-other"
		}},
		{"plan_scope", func(*controlv1.ServiceCertificateInstalledRequest) {
			current.Preparation.CertificatePlan.Scope += "-other"
		}},
		{"plan_identifiers", func(*controlv1.ServiceCertificateInstalledRequest) {
			current.Preparation.CertificatePlan.Identifiers[0] = "other." + f.Namespace
		}},
		{"plan_challenge", func(*controlv1.ServiceCertificateInstalledRequest) {
			current.Preparation.CertificatePlan.ChallengeMethod = "http-01"
		}},
		{"expiry", func(b *controlv1.ServiceCertificateInstalledRequest) { b.NotAfter = b.NotAfter.Add(time.Second) }},
		{"run_number", func(b *controlv1.ServiceCertificateInstalledRequest) { b.RunNumber-- }},
		{"issuance_publisher", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.PublisherIdentityId = foreign.Preparation.PublisherIdentityId
		}},
		{"issuance_service", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.ServiceId = foreign.Service.Id }},
		{"issuance_run", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.ServiceRunId = current.Setup.ServiceRunId
		}},
		{"issuance_run_number", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.RunNumber++ }},
		{"issuance_plan", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.CertificatePlan.Scope += "-other" }},
		{"origin_plan", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.Preparation.CertificatePlan.CacheKey += "-other"
		}},
		{"noninstallable_state", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.State = controlv1.CertificateIssuanceStateFailed
		}},
		{"missing_material", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.CertificatePem = nil }},
		{"invalid_material", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.CertificatePem = new("not a certificate")
		}},
		{"foreign_material", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.CertificatePem = foreignIssued.CertificatePem
		}},
		{"missing_csr", func(*controlv1.ServiceCertificateInstalledRequest) { origin.csr = nil }},
		{"missing_not_before", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.NotBefore = nil }},
		{"missing_not_after", func(*controlv1.ServiceCertificateInstalledRequest) { origin.issuance.NotAfter = nil }},
		{"material_expiry", func(*controlv1.ServiceCertificateInstalledRequest) {
			origin.issuance.NotAfter = new(origin.issuance.NotAfter.Add(time.Second))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f.mu.Lock()
			restore()
			changed := body
			test.change(&changed)
			f.mu.Unlock()
			publishingCertificateRequest(t, f, http.MethodPost, path, current.Setup.RunToken, "", changed, http.StatusBadRequest)
			f.mu.Lock()
			defer f.mu.Unlock()
			if current.installed || origin.installed || foreign.installed || current.issuance != nil {
				t.Fatal("rejected acknowledgment changed a run's installation or manufactured an issuance")
			}
		})
	}
	f.mu.Lock()
	restore()
	f.mu.Unlock()
	t.Run("wrong_token", func(t *testing.T) {
		publishingCertificateRequest(t, f, http.MethodPost, path, origin.Setup.RunToken, "", body, http.StatusUnauthorized)
	})
	t.Run("wrong_service", func(t *testing.T) {
		publishingCertificateRequest(t, f, http.MethodPost, "/v1/services/"+foreign.Service.Id+"/runs/"+current.Setup.ServiceRunId+"/certificate-installed",
			current.Setup.RunToken, "", body, http.StatusNotFound)
	})
	t.Run("closed_origin_is_not_current_authority", func(t *testing.T) {
		changed := body
		changed.RunNumber = origin.Setup.RunNumber
		publishingCertificateRequest(t, f, http.MethodPost, "/v1/services/"+service.Id+"/runs/"+origin.Setup.ServiceRunId+"/certificate-installed",
			origin.Setup.RunToken, "", changed, http.StatusNotFound)
	})
	t.Run("compatible_closed_origin", func(t *testing.T) {
		for range 2 {
			publishingCertificateRequest(t, f, http.MethodPost, path, current.Setup.RunToken, "", body, http.StatusNoContent)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !current.installed || origin.installed || foreign.installed || !origin.closed || current.issuance != nil || origin.issuance.Id != issued.Id {
			t.Fatal("compatible retained material did not install only on the current run")
		}
	})
}
