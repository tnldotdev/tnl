package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestWriteProvidesACompleteCorrelatedProblem(t *testing.T) {
	response := httptest.NewRecorder()
	requestID := Write(response, http.StatusConflict, "ingress_lease_stale", "ingress lease stale", "register a new ingress process run", "")
	if response.Code != http.StatusConflict || response.Header().Get("Content-Type") != "application/problem+json" ||
		!opaqueid.Valid(requestID, opaqueid.RequestPrefix) {
		t.Fatalf("problem response = %d, %v; request_id = %q", response.Code, response.Header(), requestID)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 7 || body["type"] != URL("ingress_lease_stale") || body["code"] != "ingress_lease_stale" ||
		body["title"] != "ingress lease stale" || body["status"] != float64(http.StatusConflict) ||
		body["detail"] != "register a new ingress process run" || body["request_id"] != requestID {
		t.Fatalf("problem body = %#v", body)
	}
}

func TestProblemHelpContextKeepsCanonicalType(t *testing.T) {
	response := httptest.NewRecorder()
	Write(response, http.StatusUnauthorized, "unauthenticated", "unauthenticated", "cluster secret required", "cluster-secret")
	if got := response.Header().Get("Link"); got != `<https://tnl.dev/p/unauthenticated?case=cluster-secret>; rel="help"` {
		t.Fatalf("help header = %q", got)
	}
	var body Problem
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != URL("unauthenticated") || body.Code != "unauthenticated" {
		t.Fatalf("problem identity = %q / %q", body.Type, body.Code)
	}
	if got := HelpURL("unauthenticated", "cluster-secret&token=secret"); got != URL("unauthenticated") {
		t.Fatalf("untrusted help context = %q", got)
	}
}

func TestWriteWithDetailsKeepsEnvelopeCorrelationAndHelp(t *testing.T) {
	response := httptest.NewRecorder()
	requestID := WriteWithDetails(response, http.StatusNotFound, "not_found", "service hostname is not permitted",
		"use a hostname below current-actor.example.test", "", map[string]any{"allowed_namespace": "current-actor.example.test"})
	var body map[string]any
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || response.Code != http.StatusNotFound ||
		response.Header().Get("Content-Type") != "application/problem+json" ||
		response.Header().Get("Link") != `<https://tnl.dev/p/not-found>; rel="help"` ||
		!opaqueid.Valid(requestID, opaqueid.RequestPrefix) || len(body) != 7 {
		t.Fatal("structured details changed the problem envelope or HTTP headers", response.Body.String())
	}
	details, ok := body["details"].(map[string]any)
	if !ok || len(details) != 1 || details["allowed_namespace"] != "current-actor.example.test" ||
		body["type"] != URL("not_found") || body["code"] != "not_found" || body["status"] != float64(404) ||
		body["request_id"] != requestID || body["title"] != "service hostname is not permitted" ||
		body["detail"] != "use a hostname below current-actor.example.test" {
		t.Fatal("structured details lost authored content or request correlation", response.Body.String())
	}
}
