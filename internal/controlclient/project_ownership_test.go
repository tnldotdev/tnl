package controlclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestReleaseVisitorAssignmentUsesPersonAndExactSession(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/v1/visitor-ingress-assignments/pcs_exact" || r.Header.Get("Authorization") != "Bearer person-token" || r.ContentLength > 0 {
			t.Error("release changed its session, person credential or body contract")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = c.ReleaseVisitorIngressAssignment(t.Context(), "pcs_exact"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProjectManagedConflictRetainsProblemAndClassification(t *testing.T) {
	payload, err := json.Marshal(controlv1.Problem{Code: controlv1.ProjectManaged, Status: 409, Title: "managed resource", Detail: "change the declaration", RequestId: "request-id", Type: "https://tnl.dev/problems/project_managed"})
	if err != nil {
		t.Fatal(err)
	}
	err = responseError(409, http.Header{}, payload)
	var p *ProblemError
	if !errors.Is(err, ErrProjectManaged) || !errors.Is(err, ErrStatusConflict) || !errors.As(err, &p) || p.Problem.Code != controlv1.ProjectManaged || p.Problem.RequestId != "request-id" {
		t.Fatal("managed conflict lost its cause or machine problem", err)
	}
}
