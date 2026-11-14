package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestProxyUsesSharedResponseHooks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example" || r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("proxy changed its visitor Host or forwarded a readiness secret")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	var observed, failed, modified int
	handler, err := New(Config{Target: upstream.URL, Hostname: "app.example", Hooks: httpstream.ResponseHooks{
		Observe: func(*http.Response) error { observed++; return nil },
		ObserveStatus: func(_ *http.Request, status int) {
			if status != http.StatusNotFound {
				t.Error("proxy lost upstream status", status)
			}
			failed++
		},
		ModifyHTML: func(*http.Response) error { modified++; return nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, probe := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "app.example"
		r.TLS = &tls.ConnectionState{ServerName: "app.example"}
		r.Header.Set(httpstream.ReadinessProbeHeader, "private-proof")
		if probe {
			r = httpstream.WithReadinessProbe(r)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatal("shared hooks changed upstream status", w.Code)
		}
	}
	if observed != 2 || failed != 2 || modified != 1 {
		t.Fatal("proxy bypassed shared hook/readiness mechanics", observed, failed, modified)
	}
}
