package publisher

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	policyfixture "github.com/tnldotdev/tnl/internal/testutil/visitorpolicy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherVisitorPolicyHTTPMaximumAndBounds(t *testing.T) {
	for _, fault := range []string{"maximum", "keys", "workloads", "prefixes", "events", "nil key", "short key", "overlong key", "bytes"} {
		t.Run(fault, func(t *testing.T) {
			body, private := policyfixture.Maximum(t, time.Now().UTC())
			body.Policy.VisitorPolicyRevision = math.MaxInt64 - 256
			if _, err := visitorlease.Decode(body); err != nil {
				t.Fatal("maximum base is invalid before applying the boundary fault", err)
			}
			switch fault {
			case "keys":
				body.Policy.VerificationKeys = append(body.Policy.VerificationKeys, body.Policy.VerificationKeys[0])
			case "workloads":
				body.Policy.WorkloadLeases = append(body.Policy.WorkloadLeases, body.Policy.WorkloadLeases[0])
			case "prefixes":
				body.Policy.Ip.Prefixes = append(body.Policy.Ip.Prefixes, body.Policy.Ip.Prefixes[0])
			case "events":
				body.Revisions = make([]int64, 257)
			case "nil key":
				body.Policy.VerificationKeys[0].PublicKey = nil
			case "short key":
				body.Policy.VerificationKeys[0].PublicKey = make([]byte, 31)
			case "overlong key":
				body.Policy.VerificationKeys[0].PublicKey = make([]byte, 33)
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "bytes" {
				raw = append(raw, []byte(strings.Repeat(" ", 8<<20))...)
			}
			delta := body
			delta.SnapshotRequired = false
			delta.AfterRevision = body.Policy.VisitorPolicyRevision
			delta.Policy.VisitorPolicyRevision = math.MaxInt64
			delta.Revisions = make([]int64, 256)
			for i := range delta.Revisions {
				delta.Revisions[i] = delta.AfterRevision + int64(i) + 1
			}
			deltaRaw, err := json.Marshal(delta)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request controlv1.PublisherVisitorPolicyRequest
				if json.NewDecoder(r.Body).Decode(&request) != nil {
					t.Error("publisher sent malformed policy request")
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if fault == "maximum" && request.AfterRevision == delta.AfterRevision {
					_, _ = w.Write(deltaRaw)
				} else {
					_, _ = w.Write(raw)
				}
			}))
			defer server.Close()
			client, err := clientcontrol.New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.Service, ID: body.Policy.Resource.Id}, "srun_"+strings.Repeat("R", 22), 1, "fixture-run-secret", nil)
			if fault != "maximum" {
				if policy != nil {
					policy.Close()
					t.Fatal("invalid policy became prepared")
				}
				if fault == "bytes" {
					if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
						t.Fatal("oversized HTTP policy lost its byte-boundary failure")
					}
				} else if !errors.Is(err, visitorlease.ErrUpdate) {
					t.Fatal("oversized policy items did not fail before installation", err)
				}
				return
			}
			if err != nil {
				t.Fatal("actual publisher preparation rejected bounded maximum HTTP policy", err)
			}
			defer policy.Close()
			if err := policy.refresh(t.Context()); err != nil {
				t.Fatal("publisher could not install all 256 events with maximum state", err)
			}
			view, enabled, _ := policy.lease.Current()
			if !enabled || view.VisitorPolicyRevision != math.MaxInt64 {
				t.Fatal("publisher preparation did not install complete policy history")
			}
			for _, key := range body.Policy.VerificationKeys {
				if !view.HasSigningKey(key.Id) {
					t.Fatal("publisher truncated verification keys")
				}
			}
			for _, workload := range body.Policy.WorkloadLeases {
				lease, ok := view.Workload(workload.SessionId)
				if !ok || lease.KeySHA256 != workload.KeySha256 || !lease.ExpiresAt.Equal(workload.ExpiresAt) {
					t.Fatal("publisher truncated or changed workload authority")
				}
			}
			authorityNow := view.AuthorityTime(time.Now())
			permission := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
				Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}, ExpiresAt: authorityNow.Add(time.Minute)}
			token, err := visitortoken.Sign(view.Issuer, body.Policy.VerificationKeys[0].Id, private, permission, authorityNow)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := visitortoken.VerifyBearer(token, view, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for i := range 2048 {
				guard, err := policy.lease.Bind(verified, netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}), func() {})
				if err != nil {
					t.Fatal("publisher truncated hashed IP policy", err)
				}
				guard.Close()
			}
			if guard, err := policy.lease.Bind(verified, netip.MustParseAddr("198.51.100.1"), func() {}); guard != nil || !errors.Is(err, visitortoken.ErrPolicy) {
				t.Fatal("publisher dropped the IP restriction")
			}
		})
	}
}

func TestPublisherVisitorPolicyHTTPMaximumPublicRunSourceKey(t *testing.T) {
	body, _ := policyfixture.Maximum(t, time.Now().UTC())
	body.Policy.Resource = controlv1.VisitorResourceScope{Kind: "public_url", Id: certificateTestPublicURLID}
	body.Policy.Port = 443
	body.Policy.VisitorPolicyRevision = math.MaxInt64 - 256
	body.VisitorSourceKey = testVisitorSourceKeyBytes()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request controlv1.PublisherVisitorPolicyRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Resource != body.Policy.Resource || request.RunId != "pr_0123456789abcdefghijkl" || request.RunNumber != 1 {
			t.Error("public publisher sent the wrong policy identity")
			w.WriteHeader(400)
			return
		}
		response := body
		if request.AfterRevision != 0 {
			response.SnapshotRequired = false
			response.AfterRevision = body.Policy.VisitorPolicyRevision
			response.Policy.VisitorPolicyRevision = math.MaxInt64
			response.Revisions = make([]int64, 256)
			for index := range response.Revisions {
				response.Revisions[index] = response.AfterRevision + int64(index) + 1
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_0123456789abcdefghijkl", 1, "fixture-run-secret", nil)
	if err != nil {
		t.Fatal("public run source key did not fit the unchanged maximum-policy HTTP budget", err)
	}
	defer policy.Close()
	if err := policy.refresh(t.Context()); err != nil {
		t.Fatal("maximum public delta did not fit the original preparation budget", err)
	}
	view, enabled, _ := policy.lease.Current()
	if !enabled || view.VisitorPolicyRevision != math.MaxInt64 || policy.sourceKey != testPublicVisitorSourceKey {
		t.Fatal("public preparation omitted source authority or policy history")
	}
}

var _ visitorPolicyClient = (*clientcontrol.Client)(nil)
