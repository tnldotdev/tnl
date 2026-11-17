package public

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type projectNumberStore struct {
	ProjectConfigurationStore
	revision      int64
	calls         int
	configuration controlstate.ProjectConfiguration
}

func (s *projectNumberStore) ApplyProjectConfiguration(_ context.Context, r controlstate.ApplyProjectConfigurationRequest) (controlstate.AppliedProjectConfiguration, error) {
	s.calls++
	s.revision = r.ExpectedRevision
	s.configuration = r.Configuration
	return controlstate.AppliedProjectConfiguration{Revision: r.ExpectedRevision + 1}, nil
}

func TestProjectHTTPNormalizedIPPrefixLimit(t *testing.T) {
	for _, count := range []int{256, 257} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			store := &projectNumberStore{}
			h := &handler{dependencies: Stores{ProjectConfiguration: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			ip := make([]string, count)
			for index := range ip {
				ip[index] = fmt.Sprintf("2001:db8::%x", index)
			}
			ip = append(ip, ip[0], ip[0]+"/128")
			encoded, err := json.Marshal(ip)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"team_id":"team_1","deployment":"local","service_declarations":{},"expected_revision":"0","configuration":{"services":{"web":{"target":"app","http":{"access":{"ip":` + string(encoded) + `}}}}}}`
			request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.ApplyProjectConfiguration(response, request, "project")
			if count == 257 {
				if response.Code != http.StatusBadRequest || store.calls != 0 ||
					!strings.Contains(response.Body.String(), "http.access.ip") || !strings.Contains(response.Body.String(), "256 normalized") {
					t.Fatal("project prefix limit reached mutation or lost the setting/count diagnostic", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK || store.calls != 1 {
				t.Fatal("256 normalized project prefixes plus aliases were rejected", response.Code, response.Body.String())
			}
			access := store.configuration.Services["web"].HTTP.Access
			if len(access.IP) != 256 || access.VisitorMode() != "restricted" {
				t.Fatal("project aliases were not collapsed or granted access", access)
			}
		})
	}
}

func TestProjectHTTPPreservesLargeRevision(t *testing.T) {
	store := &projectNumberStore{}
	h := &handler{dependencies: Stores{ProjectConfiguration: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
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

func TestProjectHTTPRejectsDeploymentWideExposureBeforeMutation(t *testing.T) {
	store := &projectNumberStore{}
	h := &handler{dependencies: Stores{ProjectConfiguration: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
	for _, value := range []string{"true", "false"} {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"team_id":"team_1","deployment":"production","service_declarations":{},"expected_revision":"0","configuration":{"settings":{"public":`+value+`},"services":{},"oauth":false,"webhooks":{}}}`))
		request.Header.Set("Authorization", "Bearer access-token")
		response := httptest.NewRecorder()
		h.ApplyProjectConfiguration(response, request, "project")
		if response.Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatalf("deployment-wide exposure reached state: %s: %d %s", value, response.Code, response.Body.String())
		}
		var problem struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != "invalid_request" {
			t.Fatal("retired field lost its invalid-request classification", problem, err)
		}
	}
}
