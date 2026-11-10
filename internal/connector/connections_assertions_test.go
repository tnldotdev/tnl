package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/identity/workload"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func connectionAssertionBackendFixture(t *testing.T) (*connectorConnectionBackend, authorityv1.WorkloadSession) {
	t.Helper()
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, _ authorityv1.WorkloadSession) {
		t.Error("cached assertion performed network work", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
	session, err := b.workload.Session()
	if err != nil {
		t.Fatal(err)
	}
	return b, session
}

func TestConnectionAssertionCacheIndependentDeadlines(t *testing.T) {
	b, session := connectionAssertionBackendFixture(t)
	expires := time.Now().Add(2 * time.Minute)
	before := time.Now()
	b.rememberAssertion("first", expires, session)
	after := time.Now()
	digest := sha256.Sum256([]byte("first"))
	key := hex.EncodeToString(digest[:])
	entry := b.assertions[key]
	want := connectorruntime.AssertionVerification{Digest: key, Binding: session.Binding, ExpiresAt: expires}
	if entry.proof != want {
		t.Fatal("cached proof lost its exact assertion, binding or expiry", entry.proof)
	}
	if entry.checkedUntil.Before(before.Add(30*time.Second)) || entry.checkedUntil.After(after.Add(30*time.Second)) {
		t.Fatal("current authorization did not retain its 30-second window", entry.checkedUntil)
	}
	if !b.reuseAssertion("first") || b.assertions[key] != entry {
		t.Fatal("warm reuse changed a cached deadline")
	}
	if b.reuseAssertion("first ") {
		t.Fatal("proof was reused for different assertion bytes")
	}
	for _, tc := range []struct {
		name            string
		checkedUntil    time.Time
		proofExpires    time.Time
		wantReuse       bool
		wantPreparedErr error
	}{
		{"fresh", entry.checkedUntil, expires, true, nil},
		{"authorization stale", time.Now().Add(-time.Second), expires, false, nil},
		{"assertion expired", entry.checkedUntil, time.Now().Add(-time.Second), false, connectorruntime.ErrUnprepared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := entry
			current.checkedUntil, current.proof.ExpiresAt = tc.checkedUntil, tc.proofExpires
			b.assertions[key] = current
			b.publishLocked()
			if got := b.reuseAssertion("first"); got != tc.wantReuse {
				t.Fatalf("reuse=%v, want %v", got, tc.wantReuse)
			}
			prepared, err := b.SnapshotFor("api", "first")
			if !errors.Is(err, tc.wantPreparedErr) {
				t.Fatalf("prepared read error=%v, want %v", err, tc.wantPreparedErr)
			}
			if err == nil && (prepared.Verification == nil || *prepared.Verification != current.proof) {
				t.Fatal("prepared proof inherited the current-authorization deadline")
			}
		})
	}
	b.rememberAssertion("first", expires, session)
	if !b.reuseAssertion("first") || b.assertions[key].proof != want {
		t.Fatal("rechecking authorization changed the assertion proof")
	}
	shortExpiry := time.Now().Add(10 * time.Second)
	b.rememberAssertion("short", shortExpiry, session)
	short := b.assertions[b.verification.Digest]
	if !short.checkedUntil.Equal(shortExpiry) || !short.proof.ExpiresAt.Equal(shortExpiry) {
		t.Fatal("current authorization outlived the assertion's maximum expiry")
	}
}

func TestConnectionAssertionCacheExpiryAndEviction(t *testing.T) {
	b := &connectorConnectionBackend{}
	session := authorityv1.WorkloadSession{Id: "session", Binding: strings.Repeat("a", 64)}
	expires := time.Now().Add(time.Hour)
	var expiredKey string
	for i := range 128 {
		b.rememberAssertion(strconv.Itoa(i), expires, session)
		if i == 0 {
			expiredKey = b.verification.Digest
		}
	}
	if len(b.assertions) != 128 {
		t.Fatal("cache did not retain 128 entries", len(b.assertions))
	}
	for key, entry := range b.assertions {
		entry.checkedUntil = time.Now().Add(-time.Second)
		if key == expiredKey {
			entry.proof.ExpiresAt = time.Now().Add(-time.Second)
		}
		b.assertions[key] = entry
	}
	previous := maps.Clone(b.assertions)
	b.rememberAssertion("after expiry", expires, session)
	if _, found := b.assertions[expiredKey]; found || len(b.assertions) != 128 {
		t.Fatal("expired proof was not removed before capacity eviction")
	}
	for key, entry := range previous {
		if key != expiredKey && b.assertions[key] != entry {
			t.Fatal("cleanup removed or changed an unexpired proof with stale authorization")
		}
	}
	previous = maps.Clone(b.assertions)
	b.rememberAssertion("after capacity", expires, session)
	if len(b.assertions) != 128 || b.assertions[b.verification.Digest].proof != *b.verification {
		t.Fatal("capacity eviction did not retain the new proof within the 128-entry bound")
	}
	evicted := 0
	for key, entry := range previous {
		if retained, found := b.assertions[key]; !found {
			evicted++
		} else if retained != entry {
			t.Fatal("eviction changed a retained entry")
		}
	}
	if evicted != 1 {
		t.Fatal("capacity eviction must remove exactly one arbitrary entry", evicted)
	}
	previous = maps.Clone(b.assertions)
	otherSession := session
	otherSession.Id = "other session"
	for _, tc := range []struct {
		assertion string
		expires   time.Time
	}{
		{"", expires},
		{"already expired", time.Now().Add(-time.Second)},
	} {
		b.rememberAssertion(tc.assertion, tc.expires, otherSession)
		if b.verification != nil || b.verifiedSession != session.Id || !maps.Equal(b.assertions, previous) {
			t.Fatal("invalid proof changed the verified session or retained entries")
		}
	}
}

func TestConnectionAssertionCacheSessionIsolation(t *testing.T) {
	b, session := connectionAssertionBackendFixture(t)
	expires := time.Now().Add(time.Minute)
	b.rememberAssertion("first", expires, session)
	b.rememberAssertion("second", expires, session)
	b.publishLocked()
	previous := b.snapshot.Load()
	previousClient := b.workload
	next := session
	next.Id = "wls_" + strings.Repeat("n", 22)
	next.Subject.WorkloadSessionId = new(next.Id)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/workload-sessions/exchange" {
			t.Error("session cache check performed network work", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(next)
	}))
	t.Cleanup(server.Close)
	client, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), next.TeamId, next.ProjectKey, strings.Repeat("a", 64), next.Workload, "new", []string{"api", "db"}); err != nil {
		t.Fatal(err)
	}
	b.workload = client
	if b.reuseAssertion("first") || b.reuseAssertion("second") {
		t.Fatal("a new session inherited proofs for the same binding")
	}
	b.rememberAssertion("new", expires, next)
	if b.verifiedSession != next.Id || len(b.assertions) != 1 || !b.reuseAssertion("new") {
		t.Fatal("new session did not replace the complete assertion cache")
	}
	if b.reuseAssertion("first") || b.reuseAssertion("second") || len(previous.assertions) != 2 {
		t.Fatal("session change retained old admission or mutated a published snapshot")
	}
	b.workload = previousClient
	if b.reuseAssertion("new") {
		t.Fatal("new-session proof was reusable by the old session")
	}
}

func TestConnectionAssertionCachePublishedSnapshotOwnership(t *testing.T) {
	b, session := connectionAssertionBackendFixture(t)
	expires := time.Now().Add(time.Minute)
	b.rememberAssertion("first", expires, session)
	first := *b.verification
	b.rememberAssertion("second", expires, session)
	second := *b.verification
	b.publishLocked()
	previous := b.snapshot.Load()
	for _, assertion := range []string{"", "first"} {
		want := second
		if assertion != "" {
			want = first
		}
		prepared, err := b.SnapshotFor("api", assertion)
		if err != nil || prepared.Verification == nil || *prepared.Verification != want {
			t.Fatal("published proof missing", err)
		}
		prepared.Verification.Binding = "caller changed"
		again, err := b.SnapshotFor("api", assertion)
		if err != nil || again.Verification == nil || *again.Verification != want {
			t.Fatal("caller mutated a published proof", err)
		}
	}
	verification := b.Verification()
	verification.Binding = "caller changed"
	if *b.verification != second {
		t.Fatal("caller mutated the owner's current proof")
	}
	b.verification.Binding = "owner changed"
	entry := b.assertions[first.Digest]
	entry.proof.Binding = "owner changed"
	b.assertions[first.Digest] = entry
	delete(b.assertions, second.Digest)
	b.rememberAssertion("third", expires, session)
	third := *b.verification
	b.publishLocked()
	if len(previous.assertions) != 2 || previous.assertions[first.Digest] != first || previous.assertions[second.Digest] != second || *previous.verification != second {
		t.Fatal("owner mutation changed a previously published proof map or current proof")
	}
	current := b.snapshot.Load()
	if current == previous || len(current.assertions) != 2 || current.assertions[first.Digest] != entry.proof || current.assertions[third.Digest] != third || *current.verification != third {
		t.Fatal("new snapshot did not independently publish the current proofs")
	}
	if _, err := b.SnapshotFor("api", "second"); !errors.Is(err, connectorruntime.ErrUnprepared) {
		t.Fatal("new snapshot retained a removed proof", err)
	}
}
