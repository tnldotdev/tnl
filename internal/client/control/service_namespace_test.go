package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceNamespaceProblemRequiresValidatedFieldAndProvenance(t *testing.T) {
	const allowed = "current-actor.example.test"
	for _, test := range []struct {
		name          string
		status        int
		problemStatus int
		code          controlv1.ProblemCode
		details       map[string]any
		want          bool
	}{
		{"validated field", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed}, true},
		{"unknown keys ignored", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed, "foreign_service_id": "private-value"}, true},
		{"absent", 404, 404, controlv1.NotFound, nil, false},
		{"title is not a field", 404, 404, controlv1.NotFound, map[string]any{"title": allowed}, false},
		{"wrong type", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": []string{allowed}}, false},
		{"null", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": nil}, false},
		{"uppercase", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": "Current-Actor.example.test"}, false},
		{"trailing dot", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed + "."}, false},
		{"IP literal", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": "192.0.2.1"}, false},
		{"URL", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": "https://" + allowed}, false},
		{"long label", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": strings.Repeat("a", 64) + ".example.test"}, false},
		{"huge", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": strings.Repeat("a", 20000)}, false},
		{"newline", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed + "\nprivate-value"}, false},
		{"escape", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed + "\x1b[31m"}, false},
		{"Unicode", 404, 404, controlv1.NotFound, map[string]any{"allowed_namespace": "mémber.example.test"}, false},
		{"wrong transport status", 500, 404, controlv1.NotFound, map[string]any{"allowed_namespace": allowed}, false},
		{"wrong problem status", 404, 500, controlv1.NotFound, map[string]any{"allowed_namespace": allowed}, false},
		{"missing problem status", 404, 0, controlv1.NotFound, map[string]any{"allowed_namespace": allowed}, false},
		{"unknown code", 404, 404, "future_code", map[string]any{"allowed_namespace": allowed}, false},
		{"other code", 404, 404, controlv1.Forbidden, map[string]any{"allowed_namespace": allowed}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			problem := controlv1.Problem{Code: test.code, Status: test.problemStatus, Title: allowed,
				Detail: "private-value", Details: &test.details, RequestId: "req_fixture"}
			wire, err := json.Marshal(problem)
			if err != nil {
				t.Fatal(err)
			}
			err = responseError(test.status, nil, wire)
			var namespace *ServiceNamespaceError
			if errors.As(err, &namespace) != test.want {
				t.Fatal("namespace diagnostic trusted an unvalidated field or lost an approved one", err)
			}
			var retained *ProblemError
			if !errors.As(err, &retained) || retained.Status != test.status || retained.Problem.RequestId != problem.RequestId ||
				retained.Problem.Detail != problem.Detail {
				t.Fatal("namespace classification lost the original problem cause", err)
			}
			if test.want {
				value, ok := namespace.AllowedNamespace()
				wrapped := fmt.Errorf("publication: %w", err)
				fault := errors.New("private cleanup failure")
				joined := errors.Join(wrapped, fault)
				if !ok || value != allowed || !errors.Is(err, ErrNotFound) ||
					!failure.Only(wrapped, namespace) || failure.Only(joined, namespace) || !errors.Is(joined, fault) ||
					!errors.Is(joined, retained) {
					t.Fatal("typed namespace diagnostic lost not-found, problem or independent-fault identity", err)
				}
			}
		})
	}
}
