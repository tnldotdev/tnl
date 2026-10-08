package localproxy

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/diagnostic"
)

func TestResponseObserverPreservesCompressionAndRejectsBeforeSendingHeaders(t *testing.T) {
	observed := false
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("header observer disabled upstream compression")
		}
		response.Header().Set("Location", "https://provider.example/authorize?state=secret")
		response.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	handler, err := NewWithMountsHooks(upstream.URL, "app.example", 1, nil, ResponseHooks{
		Observe: func(response *http.Response) error {
			observed = true
			if response.Header.Get("Location") == "" {
				t.Error("observer did not see upstream headers")
			}
			return diagnostic.Wrap(diagnostic.RequestRejected, errors.New("authorization redirect rejected"))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil)
	request.Host = "app.example"
	request.TLS = &tls.ConnectionState{ServerName: "app.example"}
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !observed || response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("rejected response leaked upstream redirect: %d %v %s", response.Code, response.Header(), response.Body)
	}
}
