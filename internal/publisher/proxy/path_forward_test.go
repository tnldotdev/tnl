package proxy_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func TestPublicURLForwardingPreservesApplicationPaths(t *testing.T) {
	for _, test := range []struct {
		name, request string
	}{
		{name: "root", request: "/"},
		{name: "trailing slash", request: "/v1/"},
		{name: "encoded slash id", request: "/objects/a%2Fb?mode=a%2Fb"},
		{name: "encoded space id", request: "/objects/a%20b"},
		{name: "encoded unicode id", request: "/objects/%E2%9C%93"},
		{name: "punctuation", request: "/objects/a:b;version=1@current"},
		{name: "literal dot segments", request: "/v1/../admin"},
		{name: "repeated slash", request: "/v1//objects"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var captures atomic.Int64
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captures.Add(1)
				if r.RequestURI != test.request || r.Header.Get("Authorization") != "Bearer application-credential" {
					t.Error("target path or credential was changed during forwarding")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			proxy, err := publisherproxy.NewWithMountsHooksOptions(upstream.URL, "preview.example", 1, nil, publisherproxy.ResponseHooks{}, publisherproxy.TargetOptions{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequestWithContext(t.Context(), "GET", test.request, nil)
			request.Host = "preview.example"
			request.Header.Set("Authorization", "Bearer application-credential")
			request.TLS = &tls.ConnectionState{ServerName: "preview.example"}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || captures.Load() != 1 {
				t.Fatal("valid HTTP path did not reach the verified target")
			}
		})
	}
}
