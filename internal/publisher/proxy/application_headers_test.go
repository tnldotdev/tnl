package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplicationHeadersPreservedThroughResponseObservers(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "caller" || r.Header.Get("Authorization") != "app-auth" || r.Header.Get("X-App") != "kept" {
			t.Error("application header changed")
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	observed := false
	options := TargetOptions{RootCAs: upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	proxy, err := New(Config{Target: upstream.URL, Hostname: "route.example", Port: 443, MaxConnsPerHost: 1, TargetOptions: options, Hooks: ResponseHooks{Observe: func(r *http.Response) error {
		observed = true
		if r.Request.Header.Get("X-API-Key") != "caller" || r.Request.Header.Get("Authorization") != "app-auth" || r.Request.Header.Get("X-App") != "kept" {
			t.Error("application headers changed in a response observation")
		}
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/v1/models", nil)
	r.Host = "route.example"
	r.TLS = &tls.ConnectionState{ServerName: "route.example"}
	r.Header.Set("X-API-Key", "caller")
	r.Header.Set("Authorization", "app-auth")
	r.Header.Set("X-App", "kept")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	if w.Code != 204 || !observed {
		t.Fatal("authenticated public URL proxy failed")
	}
}
