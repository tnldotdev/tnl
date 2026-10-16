package controlapi

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestFeedbackPermissionFailureBoundaries(t *testing.T) {
	for _, test := range []struct {
		Name   string
		Err    error
		Status int
	}{{"sign-in", controlstate.ErrVisitorSignIn, 401}, {"permission", controlstate.ErrFeedbackAccess, 403}, {"authority outage", authorization.ErrUnavailable, 503}, {"database outage", errors.New("private database credential"), 503}} {
		t.Run(test.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeFeedbackProblem(w, "write feedback", test.Err)
			if w.Code != test.Status {
				t.Fatalf("status=%d want=%d", w.Code, test.Status)
			}
			if test.Name == "database outage" && bytes.Contains(w.Body.Bytes(), []byte("private database credential")) {
				t.Fatal("private error leaked")
			}
		})
	}
}
