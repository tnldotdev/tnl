package authorityapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlAuthenticationRejectsAmbiguousHeadersBeforeStore(t *testing.T) {
	// Any call through this embedded nil store panics, proving parsing happens first.
	h := &handler{store: struct{ Store }{}}
	for _, values := range [][]string{nil, {"Bearer first", "Bearer second"}, {"Bearer first,second"}} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header["Authorization"] = values
		response := httptest.NewRecorder()
		if _, ok := h.authenticateControlRequest(response, request); ok || response.Code != http.StatusUnauthorized {
			t.Fatalf("headers %q: authenticated=%v, status=%d", values, ok, response.Code)
		}
	}
}
