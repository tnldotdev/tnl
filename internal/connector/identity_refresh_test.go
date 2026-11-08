package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type identityRefreshFixture struct {
	backend                *connectorConnectionBackend
	initial                authorityv1.WorkloadSession
	exchanges, attachments atomic.Int32
	attached               chan struct{}
}

func newIdentityRefreshFixture(t *testing.T) *identityRefreshFixture {
	t.Helper()
	f := &identityRefreshFixture{attached: make(chan struct{}, 16)}
	now := time.Now()
	id := "wls_" + strings.Repeat("s", 22)
	current := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: "tm_" + strings.Repeat("t", 22), ProjectKey: "project", Workload: "job", Provider: controlv1.WorkloadOIDC, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: []string{}, ExpiresAt: now.Add(time.Minute), IdentityExpiresAt: now.Add(2 * time.Second), LeaseExpiresAt: now.Add(2 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	var mu sync.Mutex
	var public ed25519.PublicKey
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			f.exchanges.Add(1)
			var body authorityv1.WorkloadExchange
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			key, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			public = key
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		case strings.HasSuffix(r.URL.Path, "/assertions"):
			f.attachments.Add(1)
			var body authorityv1.WorkloadAssertion
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			signature, err := base64.RawURLEncoding.DecodeString(body.Signature)
			digest := sha256.Sum256([]byte(body.Assertion))
			if err != nil || !ed25519.Verify(public, workloadproof.Attach(id, digest), signature) || r.Header.Get("Authorization") != "Bearer "+current.Credential {
				t.Error("refresh lost original key possession")
				w.WriteHeader(403)
				return
			}
			if body.Assertion != "fresh.private.jwt" {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"status":403,"code":"forbidden"}`))
				return
			}
			current.IdentityExpiresAt = now.Add(time.Minute)
			current.LeaseExpiresAt = current.IdentityExpiresAt
			current.AssertionExpiresAt = new(current.IdentityExpiresAt)
			defer func() { f.attached <- struct{}{} }()
		default:
			t.Error("refresh started unrelated work")
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(current)
	}))
	t.Cleanup(server.Close)
	client, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.initial, err = client.Exchange(t.Context(), current.TeamId, current.ProjectKey, strings.Repeat("a", 64), current.Workload, "initial.private.jwt", nil)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, cancel := context.WithCancel(t.Context())
	f.backend = &connectorConnectionBackend{connectorConnectionSession: connectorConnectionSession{workload: client, deadline: f.initial.ExpiresAt}, lifetime: lifetime, cancel: cancel, metadata: meta.PublicMetadata{Services: map[string]meta.Service{}}}
	f.backend.rememberAssertion("initial.private.jwt", f.initial.IdentityExpiresAt, f.initial)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.backend.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *identityRefreshFixture) start(acquire func(context.Context) (string, error)) {
	f.backend.mu.Lock()
	f.backend.refreshAssertion = acquire
	f.backend.startWorkloadRefreshLocked()
	f.backend.mu.Unlock()
}

func TestConnectionBackgroundRefreshRereadsRotatingFile(t *testing.T) {
	f := newIdentityRefreshFixture(t)
	file := filepath.Join(t.TempDir(), "current.jwt")
	if err := os.WriteFile(file, []byte("initial.private.jwt"), 0600); err != nil {
		t.Fatal(err)
	}
	read := make(chan struct{}, 16)
	f.start(func(ctx context.Context) (string, error) {
		value, err := workload.Acquire(ctx, workloadmanifest.Acquisition{Method: "token-file", TokenFile: file}, nil, os.Getenv)
		read <- struct{}{}
		return value, err
	})
	select {
	case <-read:
	case <-time.After(3 * time.Second):
		t.Fatal("native owner did not read its refresh source")
	}
	if f.attachments.Load() != 0 {
		t.Fatal("unchanged proof created control work")
	}
	nextFile := file + ".next"
	if err := os.WriteFile(nextFile, []byte("fresh.private.jwt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(nextFile, file); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.attached:
	case <-time.After(2 * time.Second):
		t.Fatal("rotated proof was not attached before expiry")
	}
	// join the publication step; an HTTP response alone is not native readiness.
	unlock, err := f.backend.lockWorkloadSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	current, err := f.backend.workload.Session()
	if err != nil || !current.IdentityExpiresAt.After(f.initial.IdentityExpiresAt) || current.Id != f.initial.Id || current.Credential != f.initial.Credential || current.Subject.WorkloadSessionId == nil || *current.Subject.WorkloadSessionId != f.initial.Id || !current.ExpiresAt.Equal(f.initial.ExpiresAt) || f.exchanges.Load() != 1 || f.attachments.Load() != 1 {
		t.Fatal("background refresh replaced or broadened its original session", err)
	}
}

func TestConnectionBackgroundRefreshFailureNeverReplacesIdentity(t *testing.T) {
	for _, source := range []string{"missing", "wrong identity", "unchanged"} {
		t.Run(source, func(t *testing.T) {
			f := newIdentityRefreshFixture(t)
			f.start(func(context.Context) (string, error) {
				switch source {
				case "missing":
					return "", workload.ErrAssertionUnavailable
				case "unchanged":
					return "initial.private.jwt", nil
				default:
					return "wrong.private.jwt", nil
				}
			})
			joined := make(chan struct{})
			go func() { f.backend.workers.Wait(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(3 * time.Second):
				t.Fatal("failed refresh outlived its confirmed deadline")
			}
			after, _ := f.backend.workload.Session()
			if !reflect.DeepEqual(after, f.initial) || f.exchanges.Load() != 1 {
				t.Fatal("refresh failure minted replacement authority")
			}
			if source != "wrong identity" && f.attachments.Load() != 0 {
				t.Fatal("missing or unchanged proof created an attachment")
			}
		})
	}
}

func TestConnectionBackgroundRefreshCancellationJoinsAcquisition(t *testing.T) {
	f := newIdentityRefreshFixture(t)
	entered, stopped := make(chan struct{}), make(chan struct{})
	f.start(func(ctx context.Context) (string, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return "fresh.private.jwt", nil
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("acquisition did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := f.backend.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("close returned before acquisition joined")
	}
	if f.attachments.Load() != 0 || f.exchanges.Load() != 1 {
		t.Fatal("late canceled acquisition changed authority")
	}
}

func TestConnectionBackgroundRefreshFencesReplacementWhileAcquiring(t *testing.T) {
	f := newIdentityRefreshFixture(t)
	previous := f.backend.workload
	release, entered := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.backend.refreshWorkloadProof(t.Context(), previous, func(context.Context) (string, error) { close(entered); <-release; return "fresh.private.jwt", nil })
	}()
	<-entered
	f.backend.mu.Lock()
	f.backend.workload = nil
	f.backend.mu.Unlock()
	close(release)
	if err := <-done; !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("old acquisition crossed a replacement fence", err)
	}
	f.backend.mu.Lock()
	f.backend.workload = previous
	f.backend.mu.Unlock()
	if f.attachments.Load() != 0 {
		t.Fatal("replaced session received an attachment")
	}
}

func TestConnectionIdentityRefreshScheduling(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		lifetime time.Duration
		retry    bool
		want     time.Duration
	}{
		{5 * time.Minute, false, 200 * time.Second}, {30 * time.Second, false, 20 * time.Second},
		{5 * time.Minute, true, 5 * time.Second}, {time.Second, true, 250 * time.Millisecond}, {0, false, 0},
	} {
		if got := identityRefreshDelay(now, now.Add(test.lifetime), test.retry); got != test.want {
			t.Fatal("refresh schedule changed", got, test.want)
		}
	}
}
