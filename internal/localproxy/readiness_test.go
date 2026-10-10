package localproxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessHeadersDoNotWaitForHTMLBodyModification(t *testing.T) {
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	var modified atomic.Bool
	handler, err := NewWithMountsHooks(backend.URL, "app.example", 0, nil, ResponseHooks{ModifyHTML: func(*http.Response) error {
		modified.Store(true)
		t.Error("readiness ran the HTML body modifier")
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{ServerName: "app.example"}
		handler.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", proxy.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "app.example"
	request.Header.Set(ReadinessProbeHeader, "1")
	response, err := proxy.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || modified.Load() {
		t.Fatalf("probe headers = %#v", response)
	}
	response.Body.Close()
	select {
	case <-backendDone:
	case <-ctx.Done():
		t.Fatal("header-only probe did not cancel the streaming body")
	}
}
