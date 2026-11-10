package public

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestProjectWorkloadGrantProblems(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{controlstate.ErrApplicationRegistration, 400, "invalid_request"},
		{controlstate.ErrPublisherIdentity, 403, "forbidden"},
		{controlstate.ErrAuthorityAccess, 403, "forbidden"},
	} {
		t.Run(test.code+test.err.Error(), func(t *testing.T) {
			cause := errors.Join(test.err, errors.New("private resource or credential"))
			response := httptest.NewRecorder()
			projectConfigurationProblem(response, "apply project configuration", cause)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) || strings.Contains(response.Body.String(), "private resource or credential") {
				t.Fatal("workload grant error was misclassified or exposed its cause", response.Code, response.Body.String())
			}
			if !errors.Is(cause, test.err) {
				t.Fatal("classification lost error identity")
			}
		})
	}
}
