package clientstate

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestGuestSessionIsSavedForTheServerAndProtected(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	guest := GuestSession{
		GuestID: "gst_0123456789abcdefghijkl", AccessToken: token.String(),
		TeamID: "tm_0123456789abcdefghijkl", MembershipID: "mem_0123456789abcdefghijkl",
		DomainID: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example",
		ExpiresAt: time.Now().UTC().Add(72 * time.Hour),
	}
	if err := store.SaveGuestSession(t.Context(), guest); err != nil {
		t.Fatal(err)
	}
	invalid := guest
	invalid.AccessToken = "invalid"
	if err := store.SaveGuestSession(t.Context(), invalid); err == nil {
		t.Fatal("invalid guest credential was accepted")
	} else if reason, _, typed := failure.Describe(err); !typed || reason != failure.GuestSessionInvalid {
		t.Fatalf("invalid guest credential = %q, typed %t", reason, typed)
	}
	if _, err := LockGuestSessionContext(t.Context(), nil); err == nil {
		t.Fatal("missing guest state store was accepted")
	} else if reason, _, typed := failure.Describe(err); !typed || reason != failure.ClientStateUnavailable {
		t.Fatalf("missing guest state store = %q, typed %t", reason, typed)
	}
	stored, err := database.queries.GetGuestSession(t.Context(), "https://control.example")
	if err != nil || len(stored.StoredAccessToken) == 0 {
		t.Fatalf("guest credential missing from client state: %v", err)
	}
	var sourceColumns int
	if err := database.db.QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_table_info('guest_sessions') WHERE name = 'source_ip'`).Scan(&sourceColumns); err != nil || sourceColumns != 0 {
		t.Fatalf("guest client state retained a source IP column: %d, %v", sourceColumns, err)
	}
	if runtime.GOOS == "darwin" && bytes.Contains(stored.StoredAccessToken, []byte(token)) {
		t.Fatal("guest credential stored in plaintext on macOS")
	}
	read, found, err := store.GuestSession(t.Context())
	if err != nil || !found || read != guest {
		t.Fatalf("guest = %+v, found = %t, error = %v", read, found, err)
	}
	other, err := database.Server(t.Context(), "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := other.GuestSession(t.Context()); err != nil || found {
		t.Fatalf("other server guest = %t, %v", found, err)
	}
	if err := store.RemoveGuestSession(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GuestSession(t.Context()); err != nil || found {
		t.Fatalf("removed guest = %t, %v", found, err)
	}
}
