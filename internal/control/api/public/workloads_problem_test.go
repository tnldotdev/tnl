package public

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestWorkloadVisitorPermissionUsesForbiddenProblem(t *testing.T) {
	for _, err := range []error{controlstate.ErrVisitorPermission, fmt.Errorf("private permission context: %w", controlstate.ErrVisitorPermission)} {
		response := httptest.NewRecorder()
		workloadVisitorProblem(t.Context(), response, err)
		assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusForbidden, controlv1.Forbidden)
		if strings.Contains(response.Body.String(), "private permission context") {
			t.Fatal("permission denial exposed private context")
		}
	}
}
