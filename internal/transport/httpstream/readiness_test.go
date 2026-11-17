package httpstream_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestReadinessHeadersDoNotWaitForHTMLBodyModification(t *testing.T) {
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" || r.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("readiness proof reached target or probe disabled compression")
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "<html>")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	var modified, observed atomic.Bool
	client := hookStreamClient(t, backend, httpstream.ResponseHooks{
		ModifyHTML: func(*http.Response) error {
			modified.Store(true)
			t.Error("readiness ran the HTML body modifier")
			return nil
		},
		Observe: func(*http.Response) error { observed.Store(true); return nil },
	}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, httpstream.WithReadinessProbe(r))
		})
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", "http://app.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpstream.ReadinessProbeHeader, "private-readiness-proof")
	request.Header.Set("Accept-Encoding", "gzip")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || modified.Load() || !observed.Load() {
		t.Fatalf("probe headers = %#v", response)
	}
	response.Body.Close()
	select {
	case <-backendDone:
	case <-ctx.Done():
		t.Fatal("header-only probe did not cancel the streaming body")
	}
}
