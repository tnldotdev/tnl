package problemtype

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestWriteProvidesACompleteCorrelatedProblem(t *testing.T) {
	response := httptest.NewRecorder()
	requestID := Write(response, http.StatusConflict, "ingress_lease_stale", "ingress lease stale", "register a new ingress process run")
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
