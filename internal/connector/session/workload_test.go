package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type workloadTransport func(*http.Request) (*http.Response, error)

func (f workloadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorkloadDeploymentRefreshesProofThenRenewsWithinHardDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		id := "wls_" + strings.Repeat("s", 22)
		team := "tm_" + strings.Repeat("t", 22)
		hard := now.Add(40 * time.Second)
		initialProof := now.Add(12 * time.Second)
		session := authorityv1.WorkloadSession{
			Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team,
			ProjectKey: "shop", Workload: "reader", Provider: controlv1.WorkloadOIDC,
			Subject:    controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id},
			ServiceIds: []string{"svc_" + strings.Repeat("p", 22)}, Binding: strings.Repeat("a", 64),
			IdentityExpiresAt: initialProof, LeaseExpiresAt: initialProof, ExpiresAt: &hard,
			RenewAfter: now.Add(30 * time.Second),
		}
		var exchanged, attached, renewed, revoked int
		client := &http.Client{Transport: workloadTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "control.tnl.dev" {
				t.Fatalf("workload request used unexpected host %q", r.URL.Host)
			}
			status := 200
			switch r.URL.Path {
			case "/v1/workload-sessions/exchange":
				exchanged++
				var body authorityv1.WorkloadExchange
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Assertion != "initial-proof" ||
					body.Services == nil || len(*body.Services) != 1 || (*body.Services)[0] != "http" {
					t.Fatal("exchange lost its exact request scope")
				}
			case "/v1/workload-sessions/" + id + "/assertions":
				attached++
				var body authorityv1.WorkloadAssertion
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Assertion != "fresh-proof" ||
					exchanged != 1 || renewed != 0 || time.Now().Before(now.Add(2*time.Second)) {
					t.Fatal("proof was not refreshed before renewal")
				}
				session.IdentityExpiresAt, session.LeaseExpiresAt = now.Add(time.Minute), hard
			case "/v1/workload-sessions/" + id + "/renew":
				renewed++
				if attached != 1 || !time.Now().Equal(now.Add(30*time.Second)) {
					t.Fatal("lease refreshed at the wrong boundary")
				}
				session.RenewalSequence = 1
				session.RenewAfter = hard
			case "/v1/workload-sessions/" + id:
				revoked++
				status = 204
			default:
				t.Fatalf("unexpected workload request: %q", r.URL.Path)
			}
			var body []byte
			if status == 200 {
				body, _ = json.Marshal(session)
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
		})}
		proofs := 0
		acquire := func(ctx context.Context) (string, error) {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			proofs++
			if proofs == 1 {
				return "initial-proof", nil
			}
			return "fresh-proof", nil
		}
		d, err := NewWorkloadDeployment(t.Context(), DeploymentOptions{Project: team + "/shop", Name: "production", Services: []string{"http"}},
			WorkloadOptions{Name: "reader", SourceFingerprint: strings.Repeat("b", 64)}, acquire, client)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.MaintainWorkload(t.Context(), acquire); !errors.Is(err, workload.ErrSessionExpired) || !time.Now().Equal(hard) {
			t.Fatalf("workload outlived or missed the hard deadline: %v", err)
		}
		if err := d.CloseWorkload(t.Context()); err != nil {
			t.Fatal(err)
		}
		if proofs != 2 || exchanged != 1 || attached != 1 || renewed != 1 || revoked != 1 {
			t.Fatalf("wrong workload lifetime: proofs=%d exchange=%d attach=%d renew=%d revoke=%d", proofs, exchanged, attached, renewed, revoked)
		}
	})
}
