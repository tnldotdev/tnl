package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// independent real-session check: one admitted TLS stream owns C while each
// HTTP/2 request owns permission, including after another request is revoked.
func TestPublicURLStreamCapacityHTTP2PermissionIsolation(t *testing.T) {
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var reached atomic.Int32
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.Header.Get(visitorTokenHeader) != "" {
			t.Error("visitor credential reached target")
		}
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		if r.URL.Path == "/signed" {
			<-r.Context().Done()
			return
		}
		select {
		case <-r.Context().Done():
		case <-release:
			_, _ = io.WriteString(w, "finished")
		}
	}))
	f.update.Anonymous = true
	if err := f.policy.Apply(f.policy.Begin(), f.update); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	transport := &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: rootsForCertificate(t, f.certificate), ServerName: f.update.View.Hostname},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if dials.Add(1) != 1 {
				return nil, errors.New("HTTP/2 tried replacing its admitted visitor stream")
			}
			stream, err := f.open(1, 0, 1)
			if err == nil {
				_, err = stream.Write(f.metadata)
			}
			return stream, err
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	open := func(path string, signed bool) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://"+f.update.View.Hostname+path, nil)
		if signed {
			r.Header.Set(visitorTokenHeader, f.token.Reveal())
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
			t.Fatalf("expected admitted HTTP/2: %d %s", response.StatusCode, response.Proto)
		}
		prefix := make([]byte, 6)
		if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
			t.Fatal("missing target prefix", err)
		}
		return response
	}
	first, sibling := open("/signed", true), open("/anonymous", false)
	defer first.Body.Close()
	defer sibling.Body.Close()
	f.wait(0, 1)
	f.update.View.VisitorPolicyRevision++
	now := time.Now()
	f.update.View.ControlTime = time.Time{}
	f.update.View.ObservedAt, f.update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := f.policy.Apply(f.policy.Begin(), f.update); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, first.Body); err == nil {
		t.Fatal("revoked request ended successfully")
	}
	third := open("/future", false)
	defer third.Body.Close()
	f.wait(0, 1)
	unblock()
	for _, response := range []*http.Response{sibling, third} {
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "finished" {
			t.Fatal("revocation canceled a sibling or damaged the shared TLS owner", string(body), err)
		}
	}
	if reached.Load() != 3 || dials.Load() != 1 {
		t.Fatal("target replay or replacement visitor stream", reached.Load(), dials.Load())
	}
	t.Log("three real target requests; revoked request fenced; two siblings completed; one TLS stream and one authorized slot")
}
