package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publicapi "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const policyDiagnosticNamespace = "current-actor.example.test"

type namespaceDiagnosticStore struct {
	publicapi.ServiceStore
	publicapi.AuthorizationStore
	t     *testing.T
	err   error
	calls int
}

func TestPolicyDiagnosticNamespaceUntrustedServerAndIndependentFault(t *testing.T) {
	maximum := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, test := range []struct {
		name      string
		namespace any
		status    int
		body      int
		code      controlv1.ProblemCode
		allowed   string
		reason    failure.Reason
	}{
		{"approved field only", policyDiagnosticNamespace, 404, 404, controlv1.NotFound, policyDiagnosticNamespace, failure.ServerResourceNotFound},
		{"maximum hostname without truncation", maximum, 404, 404, controlv1.NotFound, maximum, failure.ServerResourceNotFound},
		{"missing field", nil, 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"wrong type", []string{policyDiagnosticNamespace}, 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"invalid hostname", "https://" + policyDiagnosticNamespace, 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"noncanonical hostname", "Current-Actor.example.test.", 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"huge hostname", strings.Repeat("private-value", 2000), 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"newline", policyDiagnosticNamespace + "\nprivate-value", 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"escape", policyDiagnosticNamespace + "\x1b[31m", 404, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"wrong transport status", policyDiagnosticNamespace, 500, 404, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"unknown problem status", policyDiagnosticNamespace, 404, 499, controlv1.NotFound, "", failure.ServerResourceNotFound},
		{"unknown code", policyDiagnosticNamespace, 404, 404, "future_code", "", failure.ServerRequestInvalid},
		{"unknown code and status", policyDiagnosticNamespace, 599, 599, "future_code", "", failure.ServerAPIInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			invoke := namespaceDiagnosticCommand(t, func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(test.status)
				details := map[string]any{"allowed_namespace": test.namespace, "foreign_service_id": policyDiagnosticService,
					"foreign_namespace": "foreign.example.test", "owner_identity": "private-value", "future_detail": map[string]any{"token": "private-value"}}
				_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: test.code, Status: test.body,
					Title: "arbitrary private-value\x1b[31m\n" + policyDiagnosticNamespace, Detail: strings.Repeat("private-value", 1000),
					Details: &details, RequestId: "req_fixture"})
			})
			stdout, stderr, err := invoke("publish", "3000", "--foreground", "--hostname=existing.foreign.example.test")
			if err == nil || stdout != "" || calls != 1 {
				t.Fatalf("malicious problem caused publication work or hid its failure: calls=%d err=%v\n%s", calls, err, stderr)
			}
			assertPolicyDiagnosticFrame(t, stderr, test.reason)
			compact := strings.NewReplacer(" ", "", "\n", "", "|", "").Replace(stderr)
			if test.allowed != "" {
				if !strings.Contains(compact, test.allowed) {
					t.Fatal("approved bounded namespace was lost or truncated", stderr)
				}
			} else if strings.Contains(stderr, policyDiagnosticNamespace) {
				t.Fatal("unvalidated field or arbitrary server title reached human output", stderr)
			}
			for _, private := range []string{"private-value", "foreign.example.test", policyDiagnosticService, "arbitrary"} {
				if strings.Contains(stderr, private) {
					t.Fatal("unapproved server metadata reached human output", stderr)
				}
			}
			definition, _ := failure.DefinitionFor(test.reason)
			machine := commandDiagnosticFor(err)
			if machine.Message != definition.Message || machine.Action != definition.Action ||
				machine.Reason != string(test.reason) {
				t.Fatal("human-only namespace guidance changed machine output", machine)
			}
			if test.allowed == "" {
				return
			}
			fault := errors.New("private independent cleanup failure")
			joined := errors.Join(err, fault)
			var output bytes.Buffer
			writeCommandError(&output, joined)
			assertPolicyDiagnosticFrame(t, output.String(), failure.Unexpected)
			unexpected, _ := failure.DefinitionFor(failure.Unexpected)
			if !strings.Contains(output.String(), unexpected.Message) || strings.Contains(output.String(), "hostname is not permitted") ||
				strings.Contains(output.String(), policyDiagnosticNamespace) || strings.Contains(output.String(), fault.Error()) ||
				!errors.Is(joined, fault) || !errors.Is(joined, err) || !errors.Is(joined, clientcontrol.ErrNotFound) {
				t.Fatal("independent operation or cleanup failure was presented as an authorized namespace denial", output.String())
			}
			var problem *clientcontrol.ProblemError
			if !errors.As(joined, &problem) || problem.Problem.RequestId != "req_fixture" {
				t.Fatal("human rendering discarded the original control problem", joined)
			}
		})
	}
}

func (s *namespaceDiagnosticStore) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{IdentityID: "current-actor"}, nil
}

func (s *namespaceDiagnosticStore) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return controlstate.IdentityContext{}, nil
}

func (s *namespaceDiagnosticStore) CreateServiceAt(_ context.Context, team, actor, _, _ string, placement controlstate.ServicePlacement, _ time.Time, _ controlstate.ServiceMetadata, _ *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	if team != policyDiagnosticTeam || actor != "current-actor" || placement.DomainID != "dom_fixture" ||
		!strings.HasSuffix(placement.Hostname, ".foreign.example.test") {
		s.t.Error("namespace command changed its actor or exact publication selection")
	}
	s.calls++
	return controlstate.ServiceRecord{}, s.err
}

func namespaceDiagnosticCommand(t *testing.T, handler http.HandlerFunc) func(...string) (string, string, error) {
	t.Helper()
	return policyDiagnosticCLI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/teams/"+policyDiagnosticTeam+"/domains" {
			_ = json.NewEncoder(w).Encode(authorityv1.DomainPage{Domains: []authorityv1.Domain{
				{Id: "dom_fixture", CanonicalDomain: "example.test", Kind: "managed", State: "ready"},
			}})
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("team_id") == policyDiagnosticTeam &&
			(r.URL.Path == "/v1/service-addresses/existing.foreign.example.test" || r.URL.Path == "/v1/service-addresses/missing.foreign.example.test") {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.NotFound, Status: http.StatusNotFound})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/services" {
			t.Errorf("namespace denial performed unexpected work: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		handler(w, r)
	})
}

func TestPolicyDiagnosticNamespaceAPIClientAndHumanCommand(t *testing.T) {
	hint := &controlstate.ServiceHostnameError{Namespace: policyDiagnosticNamespace}
	fault := errors.New("private cleanup fault")
	for _, test := range []struct {
		name   string
		err    error
		reason failure.Reason
		status int
		hint   bool
	}{
		{"current actor", hint, failure.ServerResourceNotFound, 404, true},
		{"membership lost", controlstate.ErrServiceAccess, failure.ServerResourceNotFound, 404, false},
		{"independent fault", errors.Join(hint, fault), failure.ServerAPIInternal, 500, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &namespaceDiagnosticStore{t: t, err: test.err}
			handler, err := publicapi.NewHandler(publicapi.Config{}, publicapi.Stores{Services: store}, store, nil)
			if err != nil {
				t.Fatal(err)
			}
			invoke := namespaceDiagnosticCommand(t, handler.ServeHTTP)
			var previous string
			for _, hostname := range []string{"existing.foreign.example.test", "missing.foreign.example.test"} {
				stdout, stderr, err := invoke("publish", "3000", "--foreground", "--hostname="+hostname)
				if err == nil || stdout != "" || store.calls == 0 {
					t.Fatalf("publication did not return the actual API denial: %v\n%s", err, stderr)
				}
				var problem *clientcontrol.ProblemError
				if !errors.As(err, &problem) || problem == nil || problem.Status != test.status {
					t.Fatal("command lost the control problem cause", err)
				}
				assertPolicyDiagnosticFrame(t, stderr, test.reason)
				if strings.Contains(stderr, policyDiagnosticNamespace) != test.hint ||
					strings.Contains(stderr, "foreign") || strings.Contains(stderr, "private cleanup") {
					t.Fatalf("human namespace hint lost current-actor authority or exposed private state:\n%s", stderr)
				}
				if previous != "" && previous != stderr {
					t.Fatal("human namespace denial distinguished existing and missing foreign names")
				}
				previous = stderr
			}
			if store.calls != 2 {
				t.Fatal("namespace denial was retried or caused additional publication work")
			}
		})
	}
}

func TestPolicyDiagnosticNamespacePreservesActualPublishNDJSON(t *testing.T) {
	store := &namespaceDiagnosticStore{t: t, err: &controlstate.ServiceHostnameError{Namespace: policyDiagnosticNamespace}}
	handler, err := publicapi.NewHandler(publicapi.Config{}, publicapi.Stores{Services: store}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	invoke := namespaceDiagnosticCommand(t, handler.ServeHTTP)
	stdout, stderr, err := invoke("publish", "3000", "--foreground", "--hostname=existing.foreign.example.test", "--output=ndjson")
	if !errors.Is(err, clientcontrol.ErrNotFound) || stderr != "" || store.calls != 1 {
		t.Fatalf("publication denial changed NDJSON output ownership or its original cause: %v\n%s\n%s", err, stdout, stderr)
	}
	var event publishEvent
	if json.Unmarshal([]byte(stdout), &event) != nil || strings.Count(stdout, "\n") != 1 {
		t.Fatal("publication denial did not emit one NDJSON event", stdout)
	}
	definition, _ := failure.DefinitionFor(failure.ServerResourceNotFound)
	if event.SchemaVersion != 1 || event.Cursor != 1 || event.Type != publishEventError ||
		event.Reason != string(failure.ServerResourceNotFound) || event.Code != event.Reason ||
		event.Message != definition.Message || event.Retryable == nil || *event.Retryable ||
		event.HelpURL != failure.HelpURL(failure.ServerResourceNotFound, "") ||
		strings.Contains(stdout, policyDiagnosticNamespace) || strings.Contains(stdout, "foreign") {
		t.Fatal("human namespace guidance changed the publish event contract", stdout)
	}
}
