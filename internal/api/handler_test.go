package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/0xcadams/tnl/pkg/protocol/corev1"
)

func TestCapabilities(t *testing.T) {
	want := fixtureCapabilities(t)
	handler := NewHandler(want)
	request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
	request.Header.Set(requestIDHeader, "req_client123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	assertResponseHeaders(t, response, "application/json", "req_client123")

	var got corev1.Capabilities
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestRequestIDGeneration(t *testing.T) {
	handler := NewHandler(fixtureCapabilities(t))
	pattern := regexp.MustCompile(`^req_[A-Za-z0-9]+$`)

	for name, incoming := range map[string][]string{
		"missing":   nil,
		"invalid":   {"not a request ID"},
		"duplicate": {"req_first", "req_second"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
			for _, value := range incoming {
				request.Header.Add(requestIDHeader, value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			requestID := response.Header().Get(requestIDHeader)
			if !pattern.MatchString(requestID) || len(incoming) == 1 && requestID == incoming[0] {
				t.Fatalf("request ID = %q", requestID)
			}
		})
	}
}

func TestProblemResponses(t *testing.T) {
	handler := NewHandler(fixtureCapabilities(t))
	tests := map[string]struct {
		method      string
		path        string
		status      int
		code        corev1.ProblemCode
		problemType string
		allow       string
	}{
		"unknown path": {
			method:      http.MethodGet,
			path:        "/v1/unknown",
			status:      http.StatusNotFound,
			code:        corev1.NotFound,
			problemType: "https://tnl.dev/problems/not-found",
		},
		"unsupported method": {
			method:      http.MethodPost,
			path:        capabilitiesPath,
			status:      http.StatusMethodNotAllowed,
			code:        corev1.InvalidArgument,
			problemType: "https://tnl.dev/problems/method-not-allowed",
			allow:       http.MethodGet,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set(requestIDHeader, "req_problem")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			assertResponseHeaders(t, response, "application/problem+json", "req_problem")
			if got := response.Header().Get("Allow"); got != test.allow {
				t.Fatalf("Allow = %q, want %q", got, test.allow)
			}

			var problem corev1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Status != test.status || problem.Code != test.code || problem.Type != test.problemType {
				t.Fatalf("problem = %#v", problem)
			}
			if problem.RequestId != "req_problem" || problem.Details == nil || len(problem.Details) != 0 {
				t.Fatalf("problem metadata = %#v", problem)
			}
		})
	}
}

func TestCapabilitiesResponseIsBounded(t *testing.T) {
	capabilities := fixtureCapabilities(t)
	capabilities.Transport.RelayProfile = strings.Repeat("x", maxJSONResponseBytes)
	request := httptest.NewRequest(http.MethodGet, capabilitiesPath, nil)
	response := httptest.NewRecorder()

	NewHandler(capabilities).ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	var problem corev1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != corev1.Internal {
		t.Fatalf("problem code = %q, want %q", problem.Code, corev1.Internal)
	}
}

func fixtureCapabilities(t *testing.T) corev1.Capabilities {
	t.Helper()
	data, err := os.ReadFile("../../api/fixtures/core/v1/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var capabilities corev1.Capabilities
	if err := json.Unmarshal(data, &capabilities); err != nil {
		t.Fatal(err)
	}
	return capabilities
}

func assertResponseHeaders(
	t *testing.T,
	response *httptest.ResponseRecorder,
	contentType string,
	requestID string,
) {
	t.Helper()
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Content-Type":           contentType,
		requestIDHeader:          requestID,
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}
