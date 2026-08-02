package serviceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONPolicy(t *testing.T) {
	const object = `{"value":7}`
	for _, test := range []struct {
		name, contentType, body string
		status                  int
		problem, detail         string
	}{
		{"object", "application/json", object, 0, "", ""},
		{"charset", "application/json; charset=utf-8", object, 0, "", ""},
		{"at limit", "application/json", object + strings.Repeat(" ", MaximumRequestBytes-len(object)), 0, "", ""},
		{"missing type", "", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"wrong type", "text/plain", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"malformed type", "application/json; charset", object, 415, "unsupported_media_type", "Content-Type must be application/json"},
		{"unknown field", "application/json", `{"other":7}`, 400, "invalid_json", "Request body must be one JSON object matching the service schema"},
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

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, kind, detail string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("problem status/headers = %d, %v", response.Code, response.Header())
	}
	var problem struct {
		Type, Title, Detail string
		Status              int
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Type != "https://tnl.dev/problems/"+kind || problem.Title != strings.ReplaceAll(kind, "_", " ") ||
		problem.Status != status || problem.Detail != detail {
		t.Fatalf("problem = %+v", problem)
	}
}
