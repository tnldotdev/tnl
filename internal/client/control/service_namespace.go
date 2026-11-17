package control

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/naming"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ServiceNamespaceError retains a validated current-actor namespace diagnostic.
// it grants no authority and keeps the ordinary not-found and problem causes.
type ServiceNamespaceError struct {
	problem   *ProblemError
	namespace string
}

func (e *ServiceNamespaceError) Error() string {
	return "controlclient: service hostname is not permitted"
}

func (e *ServiceNamespaceError) Unwrap() []error { return []error{ErrNotFound, e.problem} }

// AllowedNamespace returns only the bounded field approved during problem decode.
// callers must also exclude independent joined failures before presenting a hint.
func (e *ServiceNamespaceError) AllowedNamespace() (string, bool) {
	if e == nil || e.namespace == "" {
		return "", false
	}
	return e.namespace, true
}

func serviceNamespace(problem *ProblemError) (string, bool) {
	if problem.Status != http.StatusNotFound || problem.Problem.Status != http.StatusNotFound ||
		problem.Problem.Code != controlv1.NotFound || problem.Problem.Details == nil {
		return "", false
	}
	namespace, ok := (*problem.Problem.Details)["allowed_namespace"].(string)
	if !ok || len(namespace) > naming.MaxHostnameBytes {
		return "", false
	}
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", false
	}
	return namespace, true
}
