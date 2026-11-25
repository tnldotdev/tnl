package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	policyDiagnosticTeam    = "tm_0123456789abcdefghijkl"
	policyDiagnosticService = "svc_0123456789abcdefghijkl"
)

// run the real parser, session, command, control client and top-level renderer.
func policyDiagnosticCLI(t *testing.T, handle http.HandlerFunc) func(...string) (string, string, error) {
	t.Helper()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("policy command lost its control session")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"},
					Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example.test", LoginFlow: "device_code"}}})
		case "GET /v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{Memberships: []authorityv1.Membership{
				{TeamId: policyDiagnosticTeam, Role: "owner", MemberSlug: "current-actor", ManagedLabel: "current-actor"},
			}})
		case "GET /v1/teams/" + policyDiagnosticTeam:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: policyDiagnosticTeam, Kind: "organization", DisplayName: "diagnostics"})
		default:
			handle(w, r)
		}
	}))
	t.Cleanup(server.Close)
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	state := filepath.Join(t.TempDir(), "state")
	return func(args ...string) (string, string, error) {
		t.Helper()
		args = append([]string{"--no-config", "--no-telemetry"}, args...)
		args = append(args, "--server="+server.URL, "--access-token="+access.String(), "--state-dir="+state, "--team="+policyDiagnosticTeam)
		var stdout, stderr bytes.Buffer
		err := run(t.Context(), args, &stdout, &stderr)
		if _, render := terminalResult(err); render != nil {
			writeCommandError(&stderr, render)
		}
		return stdout.String(), stderr.String(), err
	}
}

func assertPolicyDiagnosticFrame(t *testing.T, text string, reason failure.Reason) {
	t.Helper()
	help := failure.HelpURL(reason, "")
	if strings.Count(text, "Error: ") != 1 || help != "" && strings.Count(text, string(reason)) != 1 {
		t.Fatalf("policy error did not render once with its stable code:\n%s", text)
	}
	if help != "" && !strings.Contains(text, help) {
		t.Fatalf("policy error lost its help URL:\n%s", text)
	}
	for _, line := range strings.Split(text, "\n") {
		for _, character := range line {
			if character < 32 || character > 126 {
				t.Fatalf("policy diagnostic contains an unescaped character: %q", line)
			}
		}
	}
}

func TestPolicyDiagnosticCLIIPPrefixLimitAndZeroMutation(t *testing.T) {
	prefixes := make([]string, 257)
	for index := range prefixes {
		prefixes[index] = fmt.Sprintf("2001:db8::%x", index)
	}
	for _, test := range []struct {
		name   string
		input  []string
		want   []string
		limit  bool
		denied bool
	}{
		{name: "deduplication preserves overlaps", input: []string{"192.0.2.7/24", "192.0.2.0/24", "::ffff:192.0.2.7/120", "192.0.2.7", "192.0.2.0/25"},
			want: []string{"192.0.2.0/24", "192.0.2.0/25", "192.0.2.7/32"}},
		{name: "256 unique plus aliases", input: append(slices.Clone(prefixes[:256]), prefixes[0], prefixes[0]+"/128")},
		{name: "257 unique", input: prefixes, denied: true, limit: true},
		{name: "invalid mapped prefix", input: []string{"192.0.2.0/24", "::ffff:192.0.2.0/95"}, denied: true},
		{name: "untrusted input", input: []string{"private-foreign-resource\x1b[31m\nsecret"}, denied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := controlv1.Service{Id: policyDiagnosticService, TeamId: policyDiagnosticTeam,
				Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1, PublisherPool: true}
			reads, writes := 0, 0
			invoke := policyDiagnosticCLI(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /v1/services":
					_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{
						{Id: current.Id, TeamId: current.TeamId, Name: "web", Protocol: current.Protocol},
					}})
				case "GET /v1/services/" + policyDiagnosticService:
					_ = json.NewEncoder(w).Encode(current)
				case "GET /v1/services/" + policyDiagnosticService + "/configuration":
					reads++
					w.Header().Set("ETag", `"sha256:`+strings.Repeat("a", 64)+`"`)
					_ = json.NewEncoder(w).Encode(controlv1.ProjectServiceConfiguration{Target: "app"})
				case "PUT /v1/services/" + policyDiagnosticService:
					writes++
					var body controlv1.UpdateServiceRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					} else if body.Configuration == nil || body.Configuration.Http == nil || body.Configuration.Http.Access == nil ||
						body.Configuration.Http.Access.Ip == nil {
						t.Error("accepted policy lost its saved IP list")
					} else {
						got := *body.Configuration.Http.Access.Ip
						if test.want != nil && !slices.Equal(got, test.want) || test.want == nil && len(got) != 256 {
							t.Error("command changed normalized count or collapsed overlapping prefixes", got)
						}
					}
					_ = json.NewEncoder(w).Encode(current)
				default:
					t.Errorf("unexpected policy request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			args := []string{"url", "access", "set", policyDiagnosticService, "restricted"}
			for _, prefix := range test.input {
				args = append(args, "--ip="+prefix)
			}
			stdout, stderr, err := invoke(args...)
			if !test.denied {
				if err != nil || writes != 1 || reads != 1 {
					t.Fatalf("valid normalized policy failed: reads=%d writes=%d err=%v\n%s", reads, writes, err, stderr)
				}
				return
			}
			if err == nil || writes != 0 || reads != 0 || stdout != "" ||
				errors.Is(err, authorization.ErrIPPrefixLimit) != test.limit {
				t.Fatalf("invalid policy reached configuration or lost its cause: reads=%d writes=%d err=%v", reads, writes, err)
			}
			assertPolicyDiagnosticFrame(t, stderr, failure.InvalidCommand)
			if test.limit && !strings.Contains(stderr, "at most 256 normalized prefixes") {
				t.Fatalf("human CLI hid the approved normalized limit:\n%s", stderr)
			}
			if strings.Contains(stderr, "private-foreign-resource") || strings.Contains(stderr, "secret") {
				t.Fatal("invalid IP input reached human output")
			}
		})
	}
}

func TestPolicyDiagnosticIPLimitDoesNotExposeIndependentFault(t *testing.T) {
	fault := errors.New("private cleanup fault")
	err := failure.Wrap("validate visitor IP list", failure.InvalidCommand, authorization.ErrIPPrefixLimit)
	joined := errors.Join(err, fault)
	var output bytes.Buffer
	writeCommandError(&output, clioutput.WrapCommand("tnl url access set", joined))
	if strings.Contains(output.String(), "256") || strings.Contains(output.String(), fault.Error()) ||
		!errors.Is(joined, fault) || !errors.Is(joined, authorization.ErrIPPrefixLimit) {
		t.Fatal("independent failure was hidden by an owned policy explanation", output.String())
	}
}

func TestPolicyDiagnosticIPLimitPreservesMachineContract(t *testing.T) {
	err := failure.Wrap("validate visitor IP list", failure.InvalidCommand, authorization.ErrIPPrefixLimit)
	for _, format := range []string{"json", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			writeCommandError(&output, &machineCommandError{clioutput.WrapCommand("tnl publish", err)})
			var got struct {
				SchemaVersion int    `json:"schema_version"`
				Type          string `json:"type"`
				commandDiagnostic
			}
			if json.Unmarshal(output.Bytes(), &got) != nil {
				t.Fatal("machine error is not JSON", output.String())
			}
			definition, _ := failure.DefinitionFor(failure.InvalidCommand)
			if got.SchemaVersion != 1 || got.Type != "error" || got.Reason != string(failure.InvalidCommand) ||
				got.Code != got.Reason || got.Message != definition.Message || got.Action != definition.Action ||
				got.HelpURL != failure.HelpURL(failure.InvalidCommand, "") || got.Retryable {
				t.Fatal("human policy guidance changed the machine diagnostic contract", output.String())
			}
		})
	}
}
