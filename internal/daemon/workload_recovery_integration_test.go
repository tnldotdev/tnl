package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// a retry retains the original nonce and key. another valid ephemeral client
// may use the same provider proof, but cannot take over that exact request.
func TestIntegrationWorkloadVisitorPrepareRecoveryAndScope(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t, nil)
	address := "127.0.0.1:8080"
	environment := createServiceRuntimeEnvironment(t, f, "workload", controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: controlv1.ServiceProtocolHTTP}}}, controlv1.CreateEnvironmentRequest{Name: "recovery", Public: new(true), Targets: controlv1.EnvironmentTargets{"api": {Address: &address}}})
	machine := registerRuntimeWorkload(t, f, "recovery", "")
	permission := runtimeWorkloadPermission(t, f, machine, environment, 120)
	assertion := issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now()))
	ref, protocols := runtimeEnvironmentReference(f, environment), runtimeEnvironmentProtocols(environment)
	lostReply := errors.New("fixture lost the committed preparation reply")
	var captured authorityv1.EnvironmentVisitorPrepareRequest
	client := *f.publicHTTP
	lost := false
	client.Transport = splitACMERoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/visitors/prepare") && !lost {
			body, err := r.GetBody()
			if err != nil {
				return nil, err
			}
			defer body.Close()
			if err := json.NewDecoder(body).Decode(&captured); err != nil {
				return nil, err
			}
			response, err := f.publicHTTP.Transport.RoundTrip(r)
			if err == nil && response.StatusCode == http.StatusOK {
				lost = true
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				return nil, lostReply
			}
			return response, err
		}
		return f.publicHTTP.Transport.RoundTrip(r)
	})
	job, err := workload.New(f.controlConfig.ControlOrigin(), &client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.Prepare(t.Context(), ref, permission, assertion, protocols); !errors.Is(err, lostReply) {
		t.Fatal("fixture did not lose the successful admission reply", err)
	}
	if _, err := job.Session(); !errors.Is(err, workload.ErrNoSession) {
		t.Fatal("lost reply installed unconfirmed visitor authority", err)
	}
	var id string
	var lease, expiry time.Time
	var provider, run, attempt, jobID, event string
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT id,lease_expires_at,expires_at,claims->>'provider',
		claims->'github'->>'run_id',claims->'github'->>'run_attempt',claims->'github'->>'check_run_id',claims->'github'->>'event_name'
		FROM control.workload_sessions WHERE session_nonce=$1`, captured.Nonce).Scan(&id, &lease, &expiry, &provider, &run, &attempt, &jobID, &event); err != nil {
		t.Fatal(err)
	}
	if provider != "github" || run != "111" || attempt != "1" || jobID != "222" || event != "push" {
		t.Fatal("serving authority did not retain the signed GitHub job execution")
	}
	_, takeover, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := captured
	forged.PublicKey = base64.RawURLEncoding.EncodeToString(takeover.Public().(ed25519.PublicKey))
	digest := sha256.Sum256([]byte(assertion))
	forged.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(takeover, machineproof.EnvironmentVisitorPossession(environment.ProjectKey, permission, environment.Id, "prepare", forged.PublicKey, forged.Nonce, protocols, digest)))
	if _, err := f.identity.authority.PrepareEnvironmentVisitor(t.Context(), environment.ProjectKey, environment.Id, forged); err == nil {
		t.Fatal("another ephemeral key took over the original nonce")
	} else if problem := new(clientauthority.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusConflict {
		t.Fatal("same-nonce takeover did not reach an authority conflict", err)
	}
	recovered, err := job.Prepare(t.Context(), ref, permission, assertion, protocols)
	if err != nil || recovered.Session.Id != id || recovered.Session.ExpiresAt == nil || !recovered.Session.ExpiresAt.Equal(expiry) || !recovered.Session.LeaseExpiresAt.Equal(lease) {
		t.Fatal("original-key retry replaced or extended committed authority", err)
	}
	independent, prepared := prepareRuntimeWorkload(t, f, environment, permission, assertion)
	if prepared.Session.Id == id || independent.PublicKey().Equal(job.PublicKey()) {
		t.Fatal("independent admission reused the original nonce/key scope")
	}
	for _, replacement := range []struct{ claim, value string }{
		{"run_id", "112"}, {"run_attempt", "2"}, {"check_run_id", "223"},
	} {
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
		claims[replacement.claim] = replacement.value
		if _, err := job.Attach(t.Context(), issuer.Sign(t, claims)); err == nil {
			t.Fatal("another GitHub execution attached to the original visitor", replacement.claim)
		} else if problem := new(clientauthority.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
			t.Fatal("replacement execution did not reach an authority denial", replacement.claim, err)
		}
	}
	claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
	claims["jti"], claims["exp"] = "rotated-source-proof", time.Now().Add(6*time.Minute).Unix()
	attached, err := job.Attach(t.Context(), issuer.Sign(t, claims))
	if err != nil || attached.Id != id || attached.Credential != recovered.Session.Credential || attached.ExpiresAt == nil || !attached.ExpiresAt.Equal(expiry) || !attached.IdentityExpiresAt.After(recovered.Session.IdentityExpiresAt) {
		t.Fatal("timestamp/JTI rotation changed the original execution or fixed deadline", err)
	}
	// the original credential cannot issue a certificate for a replacement key.
	certificate, err := job.ClientTLSCertificate(t.Context(), recovered.Services["api"].ServiceId)
	if err != nil || certificate.Leaf == nil || !certificate.Leaf.PublicKey.(ed25519.PublicKey).Equal(job.PublicKey()) {
		t.Fatal("original visitor could not obtain its key-bound certificate", err)
	}
	control, err := clientcontrol.New(f.controlConfig.ControlOrigin(), f.publicHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, takeover)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.IssueWorkloadServiceClientCertificate(t.Context(), recovered.Session.Credential, recovered.Services["api"].ServiceId, csr); err == nil {
		t.Fatal("original visitor credential issued a certificate for another ephemeral key")
	} else if problem := new(clientcontrol.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("replacement-key CSR did not reach an authorization denial", err)
	}
	if err := job.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := independent.Renew(t.Context()); err != nil {
		t.Fatal("original visitor revocation revoked its independently scoped sibling", err)
	}
	if _, err := job.Prepare(t.Context(), ref, permission, assertion, protocols); err == nil {
		t.Fatal("exact preparation replay restored revoked authority")
	}
}
