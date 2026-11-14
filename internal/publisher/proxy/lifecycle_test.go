package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMountedTargetRecoversAfterInvalidReplacement(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	target := upstream.URL
	handler, err := New(Config{Target: upstream.URL, Hostname: "preview.example", Port: 443, Mounts: []Mount{{Prefix: "/api", ResolveTarget: func(context.Context) (string, string, error) { return target, target, nil }}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	for _, step := range []struct {
		target string
		status int
	}{{upstream.URL, 204}, {"http://user:secret@localhost", 502}, {upstream.URL, 204}} {
		target = step.target
		request := httptest.NewRequest(http.MethodGet, "/api/check", nil)
		request.TLS = &tls.ConnectionState{ServerName: "preview.example"}
		request.Host = "preview.example"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != step.status {
			t.Fatalf("status = %d, want %d", response.Code, step.status)
		}
	}
}

func TestProxyCloseReleasesIdleTargets(t *testing.T) {
	closed := make(chan struct{}, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)
	handler, err := New(Config{Target: upstream.URL, Hostname: "preview.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.TLS = &tls.ConnectionState{ServerName: "preview.example"}
	request.Host = "preview.example"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatal(response.Code)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	awaitProxyTest(t, closed)
}
