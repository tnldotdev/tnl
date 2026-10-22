package clientstate

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrivateServicePortPersistsAndScopesIdentityServerAndService(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	ctx := t.Context()
	db, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ListenPrivateService(ctx, "ident_one", "svc_one", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	port := first.Addr().(*net.TCPAddr).Port
	first.Close()
	db.Close()
	db, err = Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err = db.Server(ctx, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ListenPrivateService(ctx, "ident_one", "svc_one", "mysql")
	if err != nil || second.Addr().(*net.TCPAddr).Port != port {
		t.Fatalf("restart port: %v %v", second, err)
	}
	defer second.Close()
	for _, key := range [][2]string{{"ident_two", "svc_one"}, {"ident_one", "svc_two"}} {
		listener, err := store.ListenPrivateService(ctx, key[0], key[1], "mysql")
		if err != nil {
			t.Fatal(err)
		}
		if listener.Addr().(*net.TCPAddr).Port == port {
			t.Fatalf("shared port for %v", key)
		}
		listener.Close()
	}
	other, err := db.Server(ctx, "https://other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := other.ListenPrivateService(ctx, "ident_one", "svc_one", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	if listener.Addr().(*net.TCPAddr).Port == port {
		t.Fatal("different server reused the same GUI port")
	}
	listener.Close()
}

func TestInstallPortSelectionIsReadOnlyAndSupervisorBindsTheExactPort(t *testing.T) {
	db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	address := probe.Addr().String()
	var before int64
	if err := db.db.QueryRowContext(t.Context(), `SELECT last_used_at FROM server_profiles WHERE origin=?`, store.controlEndpoint).Scan(&before); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Hour)
	db.now = func() time.Time { return now }
	selected, err := store.PrivateServiceListenAddress(t.Context(), "identity", "service", "mysql", address)
	if err != nil || selected != address {
		t.Fatalf("read-only choice tried to bind occupied port: %s %v", selected, err)
	}
	var after int64
	var rows int
	if err := db.db.QueryRowContext(t.Context(), `SELECT last_used_at FROM server_profiles WHERE origin=?`, store.controlEndpoint).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRowContext(t.Context(), `SELECT count(*) FROM private_service_ports`).Scan(&rows); err != nil || rows != 0 || after != before {
		t.Fatalf("install-time selection mutated state: %d %v", rows, err)
	}
	if listener, err := store.ListenPrivateServiceAt(t.Context(), "identity", "service", selected); err == nil {
		listener.Close()
		t.Fatal("supervisor silently changed occupied selected port")
	} else {
		var occupied *PortOccupiedError
		if !errors.As(err, &occupied) {
			t.Fatalf("expected exact occupied boundary: %v", err)
		}
	}
	probe.Close()
	listener, err := store.ListenPrivateServiceAt(t.Context(), "identity", "service", selected)
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	saved, found, err := store.PrivateServicePort(t.Context(), "identity", "service")
	if err != nil || !found || saved != port {
		t.Fatalf("supervisor failed to save selected port: %d %t %v", saved, found, err)
	}
	chosen, err := store.PrivateServiceListenAddress(t.Context(), "identity", "service", "mysql", "")
	if err != nil || chosen != selected {
		t.Fatalf("restart changed selected port: %s %v", chosen, err)
	}
	for _, endpoint := range []string{selected, net.JoinHostPort("::1", strconv.Itoa(port))} {
		if _, err := store.PrivateServiceListenAddress(t.Context(), "identity", "other", "mysql", endpoint); !errors.Is(err, ErrPrivatePortReserved) {
			t.Fatalf("install-time selection stole inactive reservation: %v", err)
		}
		if listener, err := store.ListenPrivateServiceAt(t.Context(), "identity", "other", endpoint); err == nil {
			listener.Close()
			t.Fatal("supervisor stole inactive reservation")
		} else if !errors.Is(err, ErrPrivatePortReserved) {
			t.Fatalf("expected reserved boundary: %v", err)
		}
	}
}

func TestPrivatePortOverrideHonorsFutureReservationsWithoutRenumbering(t *testing.T) {
	db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := store.ListenPrivateService(t.Context(), "identity", "service-one", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if other, err := store.ListenPrivateServiceOverride(t.Context(), "identity", "service-two", address); err == nil {
		other.Close()
		t.Fatal("override stole a stopped service's future reservation")
	}
	override, err := store.ListenPrivateServiceOverride(t.Context(), "identity", "service-one", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer override.Close()
	saved, found, err := store.PrivateServicePort(t.Context(), "identity", "service-one")
	if err != nil || !found || saved != port {
		t.Fatalf("override renumbered saved port: %d %v", saved, err)
	}
}

func TestSavedPrivateServicePortConflictNeverReassigns(t *testing.T) {
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := store.ListenPrivateService(t.Context(), "ident_one", "svc_one", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	_, err = store.ListenPrivateService(t.Context(), "ident_one", "svc_one", "postgres")
	var occupied *PortOccupiedError
	if !errors.As(err, &occupied) || occupied.Port != port || !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("saved port conflict: %v", err)
	}
	saved, found, err := store.PrivateServicePort(t.Context(), "ident_one", "svc_one")
	if err != nil || !found || saved != port {
		t.Fatalf("reassigned port: %d %t %v", saved, found, err)
	}
	if err := store.RemovePrivateServicePort(t.Context(), "ident_one", "svc_one"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.PrivateServicePort(t.Context(), "ident_one", "svc_one"); err != nil || found {
		t.Fatalf("removed port remains: %t %v", found, err)
	}
}
