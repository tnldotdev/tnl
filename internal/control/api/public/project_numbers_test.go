package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type projectNumberStore struct {
	ProjectConfigurationStore
	revision int64
	calls    int
}

func (s *projectNumberStore) ApplyProjectConfiguration(_ context.Context, r controlstate.ApplyProjectConfigurationRequest) (controlstate.AppliedProjectConfiguration, error) {
	s.calls++
	s.revision = r.ExpectedRevision
	return controlstate.AppliedProjectConfiguration{Revision: r.ExpectedRevision + 1}, nil
}

func TestProjectHTTPPreservesLargeRevision(t *testing.T) {
	store := &projectNumberStore{}
	h := &handler{dependencies: Stores{ProjectConfiguration: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"team_id":"team_1","deployment":"local","service_declarations":{},"expected_revision":"9007199254740993","configuration":{}}`))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.ApplyProjectConfiguration(response, request, "project")
	if response.Code != http.StatusOK || store.revision != 9007199254740993 || store.calls != 1 {
		t.Fatalf("apply: %d %s revision=%d calls=%d", response.Code, response.Body.String(), store.revision, store.calls)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || string(body["revision"]) != `"9007199254740994"` {
		t.Fatalf("response lost its decimal revision: %s (%v)", response.Body.String(), err)
	}
	for _, value := range []string{`9007199254740993`, `"9223372036854775808"`, `"1.5"`} {
		response = httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"team_id":"team_1","deployment":"local","service_declarations":{},"expected_revision":`+value+`,"configuration":{}}`))
		h.ApplyProjectConfiguration(response, request, "project")
		if response.Code != http.StatusBadRequest || store.calls != 1 {
			t.Fatalf("invalid revision reached state: %s: %d %s", value, response.Code, response.Body.String())
		}
	}
}
