package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

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
