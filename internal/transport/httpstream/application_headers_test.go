package httpstream_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestApplicationHeadersPreservedThroughResponseObservers(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "caller" || r.Header.Get("Authorization") != "app-auth" || r.Header.Get("X-App") != "kept" {
			t.Error("application header changed")
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	var observed atomic.Bool
	client := hookStreamClient(t, upstream, httpstream.ResponseHooks{Observe: func(r *http.Response) error {
		observed.Store(true)
		if r.Request.Host != "route.example" || r.Request.URL.Host == r.Request.Host {
			t.Error("response observer lost visitor authority or replaced the target URL")
		}
		if r.Request.Header.Get("X-API-Key") != "caller" || r.Request.Header.Get("Authorization") != "app-auth" || r.Request.Header.Get("X-App") != "kept" {
			t.Error("application headers changed in a response observation")
		}
		return nil
	}}, nil)
	r, err := http.NewRequestWithContext(t.Context(), "GET", "http://route.example/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-API-Key", "caller")
	r.Header.Set("Authorization", "app-auth")
	r.Header.Set("X-App", "kept")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 204 || !observed.Load() {
		t.Fatal("authenticated HTTP forwarding failed")
	}
}
