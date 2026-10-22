package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDynamicTargetFollowsReplacementWithoutReusingOldConnections(t *testing.T) {
	var accepts atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "current app")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepts.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	identity := "container-one"
	proxy, err := NewWithMountsHooksOptionsAdmittedDynamic(upstream.URL, "route.example", 4, nil, ResponseHooks{}, TargetOptions{}, func(*http.Request) (string, string, error) {
		return upstream.URL, identity, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	visit := func() {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = "route.example"
		r.TLS = &tls.ConnectionState{ServerName: "route.example"}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Body.String() != "current app" {
			t.Fatalf("dynamic target visit = %d %q", w.Code, w.Body.String())
		}
	}
	visit()
	visit()
	if got := accepts.Load(); got != 1 {
		t.Fatalf("unchanged target did not reuse a connection: %d", got)
	}
	identity = "container-two"
	visit()
	if got := accepts.Load(); got != 2 {
		t.Fatalf("replacement at the same address reused the old container connection: %d", got)
	}
}
