//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type testRoundTrip func(*http.Request) (*http.Response, error)

func (f testRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// use the real workload client and authority response validation. the in-memory
// HTTP fixture controls only revocation outcomes, not session lifecycle checks.
func testBackend(t *testing.T, revoke func() int) *backend {
	t.Helper()
	id := "wls_" + strings.Repeat("a", 22)
	s := authorityv1.WorkloadSession{Id: id, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, Credential: "wlc_" + strings.Repeat("b", 43), TeamId: "tm_" + strings.Repeat("c", 22), ProjectKey: "project", Workload: "spike", Provider: controlv1.WorkloadOIDC, Binding: strings.Repeat("d", 64), IdentityExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(time.Minute), ServiceIds: []string{"svc_" + strings.Repeat("e", 22)}}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	client, err := workload.New("https://control.test", &http.Client{Transport: testRoundTrip(func(r *http.Request) (*http.Response, error) {
		status, body := http.StatusOK, data
		if !strings.HasSuffix(r.URL.Path, "/exchange") {
			status, body = revoke(), nil
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), s.TeamId, s.ProjectKey, strings.Repeat("f", 64), s.Workload, "signed-fixture-assertion", nil); err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancelCause(t.Context())
	return &backend{client: client, cancel: cancel, transport: &http.Transport{}, exchanged: true}
}

func TestBackendCloseRetriesUncertainRevocation(t *testing.T) {
	calls := 0
	b := testBackend(t, func() int {
		calls++
		if calls == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusNoContent
	})
	if err := b.close(); err == nil {
		t.Fatal("uncertain revocation was hidden")
	}
	if err := b.close(); err != nil {
		t.Fatal("revocation retry failed", err)
	}
	if err := b.close(); err != nil {
		t.Fatal("successful close was not idempotent", err)
	}
	if calls != 2 {
		t.Fatalf("revocation calls=%d", calls)
	}
}
