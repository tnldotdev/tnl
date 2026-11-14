package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
)

type servicePortListener struct {
	port     int
	closed   int
	closeErr error
}

func (l *servicePortListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *servicePortListener) Close() error              { l.closed++; return l.closeErr }
func (l *servicePortListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port}
}

func servicePortStore(t *testing.T) *Store {
	t.Helper()
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestServicePortAllocationTriesFriendlyTiersBeforeFallback(t *testing.T) {
	for _, test := range []struct {
		name string
		skip int
		want int
	}{
		{"preferred", 0, 15432},
		{"next alternative", 1, 25432},
		{"neighbors", 5, 5433},
		{"patterns", 12, 11111},
		{"mirrored", 17, 12321},
		{"fallback", 28, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := servicePortStore(t)
			reader := openFileDatabase(t, store.database.Root())
			ctx := t.Context()
			seed := sha256.Sum256([]byte(store.controlEndpoint + "\x00identity\x00service"))
			candidates := privatePortCandidates("postgres", seed)
			var attempted []int
			var selected *servicePortListener
			listener, err := store.listenService(ctx, "identity", "service", "postgres", func(port int) (net.Listener, error) {
				attempted = append(attempted, port)
				if len(attempted) <= test.skip {
					return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
				}
				// the callback is the bind boundary, before the SQLite write.
				var rows int
				if err := reader.db.QueryRowContext(ctx, `SELECT count(*) FROM service_ports`).Scan(&rows); err != nil || rows != 0 {
					t.Fatal("port was saved before binding", rows, err)
				}
				selected = &servicePortListener{port: port}
				return selected, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			want := test.want
			if want == 0 {
				want = candidates[test.skip]
			}
			if !slices.Equal(attempted, candidates[:test.skip+1]) || listener.Addr().(*net.TCPAddr).Port != want || selected.closed != 0 {
				t.Fatal("allocation skipped or changed the ordered candidates", attempted)
			}
			saved, found, err := store.ServicePort(ctx, "identity", "service")
			if err != nil || !found || saved != want {
				t.Fatal("successful bound port was not saved", saved, found, err)
			}
			// installation plans and subsequent listeners use the saved result,
			// not the now-available first preference.
			address, err := store.ServiceListenAddress(ctx, "identity", "service", "postgres", "")
			if err != nil || address != net.JoinHostPort("127.0.0.1", strconv.Itoa(want)) {
				t.Fatal("install planning changed the saved port", address, err)
			}
			attempted = nil
			restarted, err := store.listenService(ctx, "identity", "service", "postgres", func(port int) (net.Listener, error) {
				attempted = append(attempted, port)
				return &servicePortListener{port: port}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			_ = restarted.Close()
			if !slices.Equal(attempted, []int{want}) {
				t.Fatal("restart rebalanced to a nicer port", attempted)
			}
		})
	}
}

func TestServicePortAllocationPreservesStoppedReservationsAcrossScopes(t *testing.T) {
	store := servicePortStore(t)
	ctx := t.Context()
	reserve := func(current *Store, identity, service string, want int) {
		t.Helper()
		listener, err := current.listenService(ctx, identity, service, "postgres", func(port int) (net.Listener, error) {
			if port != want {
				t.Fatalf("reserved port was reused or preference skipped: %d, want %d", port, want)
			}
			return &servicePortListener{port: port}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = listener.Close()
	}
	reserve(store, "identity", "first", 15432)
	reserve(store, "identity", "second", 25432)
	reserve(store, "other-identity", "first", 35432)
	other, err := store.database.Server(ctx, "https://other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	reserve(other, "identity", "first", 45432)
	address, err := store.ServiceListenAddress(ctx, "identity", "next", "postgres", "")
	if err != nil || address != "127.0.0.1:55432" {
		t.Fatal("install planning ignored stopped service reservations", address, err)
	}
}

func TestServicePortAllocationDoesNotHideErrorsOrLeakFailedListeners(t *testing.T) {
	t.Run("socket failure is final", func(t *testing.T) {
		store := servicePortStore(t)
		calls := 0
		denied := &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EACCES}
		if _, err := store.listenService(t.Context(), "identity", "service", "http", func(int) (net.Listener, error) {
			calls++
			return nil, denied
		}); !errors.Is(err, denied) || calls != 1 {
			t.Fatal("unrelated socket failure caused fallback", calls, err)
		}
	})
	t.Run("candidate exhaustion", func(t *testing.T) {
		store := servicePortStore(t)
		attempted := make(map[int]bool)
		_, err := store.listenService(t.Context(), "identity", "service", "mysql", func(port int) (net.Listener, error) {
			if attempted[port] {
				t.Fatal("candidate was attempted twice", port)
			}
			attempted[port] = true
			return nil, syscall.EADDRINUSE
		})
		if err == nil || len(attempted) != 128 {
			t.Fatal("allocation did not respect the total candidate budget", len(attempted), err)
		}
		if _, found, err := store.ServicePort(t.Context(), "identity", "service"); err != nil || found {
			t.Fatal("failed allocation saved an assignment", found, err)
		}
	})
	t.Run("failed persistence closes listener", func(t *testing.T) {
		store := servicePortStore(t)
		if _, err := store.database.db.ExecContext(t.Context(), `CREATE TRIGGER reject_port BEFORE INSERT ON service_ports BEGIN SELECT RAISE(ABORT,'port persistence failed'); END`); err != nil {
			t.Fatal(err)
		}
		closeErr := errors.New("listener cleanup failed")
		listener := &servicePortListener{port: 8443, closeErr: closeErr}
		calls := 0
		_, err := store.listenService(t.Context(), "identity", "service", "http", func(int) (net.Listener, error) {
			calls++
			return listener, nil
		})
		if err == nil || !errors.Is(err, closeErr) || calls != 1 || listener.closed != 1 {
			t.Fatal("failed persistence leaked its listener or lost cleanup failure", calls, listener.closed, err)
		}
		if _, found, err := store.ServicePort(t.Context(), "identity", "service"); err != nil || found {
			t.Fatal("failed write retained an assignment", found, err)
		}
	})
	t.Run("cancellation closes bound listener", func(t *testing.T) {
		store := servicePortStore(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		listener := &servicePortListener{port: 16443}
		_, err := store.listenService(ctx, "identity", "service", "kubernetes", func(int) (net.Listener, error) {
			cancel()
			return listener, nil
		})
		if !errors.Is(err, context.Canceled) || listener.closed != 1 {
			t.Fatal("canceled persistence retained its bound listener", listener.closed, err)
		}
	})
}

func TestServicePortAllocationSerializesConcurrentFirstAssignments(t *testing.T) {
	store := servicePortStore(t)
	ctx := t.Context()
	otherDatabase := openFileDatabase(t, store.database.Root())
	other, err := otherDatabase.Server(ctx, store.controlEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	const count = 8
	results := make(chan int, count)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range count {
		workers.Go(func() {
			<-start
			current := store
			if index%2 != 0 {
				current = other
			}
			listener, err := current.listenService(ctx, "identity", fmt.Sprintf("service-%d", index), "postgres", func(port int) (net.Listener, error) {
				return &servicePortListener{port: port}, nil
			})
			if err != nil {
				t.Error(err)
				return
			}
			results <- listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var ports []int
	for port := range results {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	want := []int{15432, 25432, 35432, 45432, 55432, 5433, 5434, 5435}
	slices.Sort(want)
	if !slices.Equal(ports, want) {
		t.Fatal("concurrent allocations collided or skipped friendly candidates", ports)
	}
}

func TestServicePortInstallPlanningUsesActualProtocolWithoutClaiming(t *testing.T) {
	store := servicePortStore(t)
	for protocol, want := range map[string]string{
		"http": "127.0.0.1:8443", "postgres": "127.0.0.1:15432",
		"mysql": "127.0.0.1:13306", "kubernetes": "127.0.0.1:16443", "tcp": "127.0.0.1:11111",
	} {
		address, err := store.ServiceListenAddress(t.Context(), "identity", "service", protocol, "")
		if err != nil || address != want {
			t.Fatal("install plan lost the service protocol", protocol, address, err)
		}
	}
	var rows int
	if err := store.database.db.QueryRowContext(t.Context(), `SELECT count(*) FROM service_ports`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("install planning claimed a listener", rows, err)
	}
}
