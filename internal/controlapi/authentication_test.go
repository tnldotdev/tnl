package controlapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouteSessionAuthenticationRejectsAmbiguousHeadersBeforeStore(t *testing.T) {
	// Any call through this embedded nil store panics, proving parsing happens first.
	h := &handler{store: struct{ Store }{}}
	for _, values := range [][]string{nil, {"Bearer first", "Bearer second"}, {"Bearer first,second"}} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.Header["Authorization"] = values
		response := httptest.NewRecorder()
		if _, ok := h.authenticateRouteSessionRequest(response, request, "route_session_1", 1); ok || response.Code != http.StatusUnauthorized {
			t.Fatalf("headers %q: authenticated=%v, status=%d", values, ok, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "bEaReR opaque-token")
	if token, ok := requestBearerToken(request); !ok || token != "opaque-token" {
		t.Fatalf("mixed-case bearer = %q, %v", token, ok)
	}
}
