package serviceapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/problemtype"
)

func TestDecodeJSONPolicy(t *testing.T) {
	const object = `{"value":7}`
	for _, test := range []struct {
		name, contentType, body string
		status                  int
		problem, detail         string
	}{
		{"object", "application/json", object, 0, "", ""},
		{"leading whitespace", "application/json", " \n" + object, 0, "", ""},
		{"charset", "application/json; charset=utf-8", object, 0, "", ""},
		{"at limit", "application/json", object + strings.Repeat(" ", MaximumRequestBytes-len(object)), 0, "", ""},
		{"missing type", "", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"wrong type", "text/plain", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"malformed type", "application/json; charset", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"unknown field", "application/json", `{"other":7}`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
		{"null", "application/json", `null`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
		{"array", "application/json", `[]`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
		{"malformed", "application/json", `{`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
		{"wrong value type", "application/json", `{"value":"seven"}`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
		{"second value", "application/json", object + `{}`, 400, "invalid_json", "Request body must contain exactly one JSON value"},
		{"trailing garbage", "application/json", object + `x`, 400, "invalid_json", "Request body must contain exactly one JSON value"},
		{"beyond limit", "application/json", object + strings.Repeat(" ", MaximumRequestBytes-len(object)+1), 400, "invalid_json", "Request body must contain exactly one JSON value"},
		{"object beyond limit", "application/json", strings.Repeat(" ", MaximumRequestBytes) + object, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			var value struct {
				Value int `json:"value"`
			}
			if ok := DecodeJSON(response, request, &value); ok != (test.status == 0) {
				t.Fatalf("DecodeJSON = %t, response = %s", ok, response.Body.String())
			}
			if test.status == 0 {
				if value.Value != 7 || response.Body.Len() != 0 || len(response.Header()) != 0 {
					t.Fatalf("value = %v, response = %v", value, response)
				}
				return
			}
			assertProblem(t, response, test.status, test.problem, test.detail)
		})
	}
}

func TestAuthenticateClusterRequest(t *testing.T) {
	const secret = "private-cluster-secret-012345678901"
	secrets, err := NewBearerSecrets(secret, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, authorization string
		accepted            bool
	}{
		{"authenticated", "Bearer " + secret, true},
		{"missing", "", false},
		{"wrong scheme", "Basic " + secret, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/internal/v1/relays", nil)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			if accepted := AuthenticateClusterRequest(response, request, secrets); accepted != test.accepted {
				t.Fatalf("authenticated = %t", accepted)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("cache policy = %q", response.Header().Get("Cache-Control"))
			}
			if test.accepted {
				if response.Code != http.StatusOK || response.Body.Len() != 0 {
					t.Fatalf("authentication wrote a response: %d, %s", response.Code, response.Body.String())
				}
				return
			}
			if response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("challenge header = %q", response.Header().Get("WWW-Authenticate"))
			}
			assertProblem(t, response, http.StatusUnauthorized, "unauthenticated", "A valid cluster secret is required")
		})
	}
}

func TestWriteServiceErrorBoundary(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/ingresses", nil)
	failure := errors.New("database failed")
	var reported error
	report := func(err error) { reported = err }
	response := httptest.NewRecorder()
	if WriteServiceError(response, request, nil, report, "failed") || reported != nil || response.Body.Len() != 0 {
		t.Fatal("successful service call wrote an error")
	}

	canceled, cancel := context.WithCancel(request.Context())
	cancel()
	response = httptest.NewRecorder()
	if !WriteServiceError(response, request.WithContext(canceled), failure, report, "failed") ||
		reported != nil || response.Body.Len() != 0 {
		t.Fatal("canceled request wrote or reported an error")
	}

	response = httptest.NewRecorder()
	problem := NewProblemError(http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current")
	if !WriteServiceError(response, request, problem, report, "failed") || reported != nil {
		t.Fatal("known service problem was not forwarded")
	}
	assertProblem(t, response, http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current")

	response = httptest.NewRecorder()
	if !WriteServiceError(response, request, failure, report, "failed") || !errors.Is(reported, failure) {
		t.Fatal("unexpected failure was not reported")
	}
	assertProblem(t, response, http.StatusInternalServerError, "internal", "failed")
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, kind, detail string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem status/headers = %d, %v", response.Code, response.Header())
	}
	var problem struct {
		Type, Title, Code, Detail string
		RequestID                 string `json:"request_id"`
		Status                    int
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Type != problemtype.URL(kind) || problem.Title != strings.ReplaceAll(kind, "_", " ") ||
		problem.Status != status || problem.Code != kind || problem.RequestID == "" || problem.Detail != detail {
		t.Fatalf("problem = %+v", problem)
	}
}
