package stream

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPDenialClosesOnlyHTTP1Connection(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusMisdirectedRequest, http.StatusServiceUnavailable} {
		for _, version := range []int{1, 2} {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.ProtoMajor = version
			response := httptest.NewRecorder()
			DenyHTTP(response, request, status)
			connection := ""
			if version == 1 {
				connection = "close"
			}
			if response.Code != status || response.Header().Get("Connection") != connection {
				t.Fatal("denial changed status or closed unrelated HTTP/2 streams", version, response.Code, response.Header())
			}
		}
	}
}
