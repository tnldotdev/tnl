package certificatestore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// hostStorage models shared host records and atomic named locks, without a Go
// filesystem. separate caches and asynchronous calls share the same authority.
type hostStorage struct {
	mu         sync.Mutex
	records    map[string][]byte
	locks      map[string]chan struct{}
	writeError error
	syncError  error
	closeError error
}

func newHostStorage() *hostStorage {
	return &hostStorage{records: map[string][]byte{}, locks: map[string]chan struct{}{}}
}

func (s *hostStorage) Read(ctx context.Context, name string, limit int64) ([]byte, bool, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, found := s.records[name]
	if int64(len(data)) > limit {
		return nil, found, ErrPublisherStateConflict
	}
	return bytes.Clone(data), found, nil
}

func (s *hostStorage) Write(ctx context.Context, name string, data []byte) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[name] = bytes.Clone(data)
	return s.writeError // an uncertain outcome may already have replaced the record.
}

func (s *hostStorage) Sync(ctx context.Context, _ string) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncError
}

func (s *hostStorage) Lock(ctx context.Context, name string) (io.Closer, error) {
	s.mu.Lock()
	lock := s.locks[name]
	if lock == nil {
		lock = make(chan struct{}, 1)
		lock <- struct{}{}
		s.locks[name] = lock
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-lock:
		if err := context.Cause(ctx); err != nil {
			lock <- struct{}{}
			return nil, err
		}
		return &hostLock{release: func() error {
			s.mu.Lock()
			err := s.closeError
			s.mu.Unlock()
			lock <- struct{}{}
			return err
		}}, nil
	}
}

type hostLock struct {
	once    sync.Once
	release func() error
	err     error
}

func (l *hostLock) Close() error {
	l.once.Do(func() { l.err = l.release() })
	return l.err
}

func hostCache(t *testing.T, storage Storage) *CertificateCache {
	t.Helper()
	cache, err := New(storage, Scope{ControlURL: "https://control.example", TeamID: "team",
		PublisherIdentityID: "pub_0123456789abcdefghijkl"}, controlv1.CertificatePlan{
		CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"},
		ChallengeMethod: controlv1.Dns01,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cache.plan.CacheKey != "route.example" {
		t.Fatal("storage scoping changed the control-approved plan")
	}
	return cache
}

func hostCertificate(t *testing.T, pending Pending) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"route.example"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &pending.Key.PublicKey, pending.Key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCSRRequiresConcreteMatchingECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identifiers := []string{"app.example"}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCSR(csr, key, identifiers); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*ecdsa.PrivateKey{nil, other} {
		if err := validateCSR(csr, invalid, identifiers); err == nil {
			t.Fatal("CSR accepted a missing or different key")
		}
	}
}

func TestHostCertificateInterruptedTransitionsReuseExactMaterial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newHostStorage()
		cache := hostCache(t, storage)
		hostname := "route.example"
		if _, err := cache.Pending(t.Context(), hostname); err != nil {
			t.Fatal(err)
		}
		unavailable := failure.Wrap("host write", failure.PublisherIdentityStateUnavailable, errors.New("interrupted"))
		storage.writeError = unavailable
		if pending, err := cache.NewPending(t.Context(), hostname); !errors.Is(err, unavailable) || pending.Key != nil {
			t.Fatal("uncertain renewal released a key", err)
		}
		snapshot, err := cache.read(t.Context())
		if err != nil || snapshot.Pending == nil {
			t.Fatal("uncertain renewal was not an atomic snapshot", err)
		}
		defer snapshot.destroy()
		storage.writeError, storage.syncError = nil, unavailable
		reopened := hostCache(t, storage)
		if pending, err := reopened.Pending(t.Context(), hostname); !errors.Is(err, unavailable) || pending.Key != nil {
			t.Fatal("recovery released an undurable key", err)
		}
		storage.syncError = nil
		pending, err := reopened.Pending(t.Context(), hostname)
		if err != nil || !bytes.Equal(pending.CSRDER, snapshot.Pending.CSRDER) {
			t.Fatal("recovery replaced the uncertain CSR", err)
		}
		storage.writeError = unavailable
		if material, err := reopened.Stage(t.Context(), hostname, pending, hostCertificate(t, pending), time.Now().Add(time.Hour), "issued"); !errors.Is(err, unavailable) || material.Certificate.PrivateKey != nil {
			t.Fatal("uncertain staging released a certificate", err)
		}
		storage.writeError, storage.syncError = nil, unavailable
		reopened = hostCache(t, storage)
		if staged, found, err := reopened.Staged(t.Context(), hostname); !errors.Is(err, unavailable) || !found || staged.Certificate.PrivateKey != nil {
			t.Fatal("recovered staged material skipped durability", err)
		}
		storage.syncError = nil
		staged, found, err := reopened.Staged(t.Context(), hostname)
		if err != nil || !found || staged.IssuanceID != "issued" {
			t.Fatal("staged issuance was not recovered", err)
		}
		if _, found, err := reopened.Current(t.Context(), hostname); err != nil || found {
			t.Fatal("unacknowledged material became current", err)
		}
		storage.writeError = unavailable
		if err := reopened.Promote(t.Context(), hostname, "issued"); !errors.Is(err, unavailable) {
			t.Fatal("uncertain promotion reported success", err)
		}
		storage.writeError, storage.syncError = nil, unavailable
		reopened = hostCache(t, storage)
		if err := reopened.Promote(t.Context(), hostname, "issued"); !errors.Is(err, unavailable) {
			t.Fatal("idempotent promotion skipped durability", err)
		}
		storage.syncError = nil
		if err := reopened.Promote(t.Context(), hostname, "issued"); err != nil {
			t.Fatal(err)
		}
		current, found, err := reopened.Current(t.Context(), hostname)
		if err != nil || !found || !bytes.Equal(current.Certificate.Certificate[0], staged.Certificate.Certificate[0]) {
			t.Fatal("promotion changed recovered certificate", err)
		}
	})
}

func TestHostCertificateLocksSerializeSeparateCachesAndCancelWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := newHostStorage()
		first, second := hostCache(t, storage), hostCache(t, storage)
		lock, err := first.Lock(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			lock, err := second.Lock(ctx)
			if lock != nil {
				err = errors.Join(err, lock.Close(), errors.New("canceled waiter acquired lock"))
			}
			done <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("host lock did not honor cancellation", err)
		}
		// issuance does not block current-snapshot reads or short mutations.
		pending, err := second.Pending(t.Context(), "route.example")
		if err != nil {
			t.Fatal(err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		lock, err = second.Lock(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		var workers sync.WaitGroup
		results := make(chan Pending, 8)
		for range 8 {
			workers.Go(func() {
				recovered, err := hostCache(t, storage).Pending(t.Context(), "route.example")
				if err != nil {
					t.Error(err)
				}
				results <- recovered
			})
		}
		workers.Wait()
		for range 8 {
			if recovered := <-results; !bytes.Equal(recovered.CSRDER, pending.CSRDER) {
				t.Fatal("concurrent pending calls created another key")
			}
		}
	})
}

func TestHostCertificateReleaseFailureDoesNotExposeMaterial(t *testing.T) {
	storage := newHostStorage()
	cache := hostCache(t, storage)
	releaseErr := errors.New("host lock release failed")
	storage.closeError = releaseErr
	if pending, err := cache.Pending(t.Context(), "route.example"); !errors.Is(err, releaseErr) || pending.Key != nil {
		t.Fatal("pending key escaped a failed mutation-lock release", err)
	}
	storage.closeError = nil
	pending, err := cache.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	storage.closeError = releaseErr
	if staged, err := cache.Stage(t.Context(), "route.example", pending, hostCertificate(t, pending), time.Now().Add(time.Hour), "issued"); !errors.Is(err, releaseErr) || staged.Certificate.PrivateKey != nil {
		t.Fatal("staged certificate escaped a failed mutation-lock release", err)
	}
	if err := cache.Promote(t.Context(), "route.example", "issued"); !errors.Is(err, releaseErr) {
		t.Fatal("promotion discarded lock cleanup failure", err)
	}
}

type awaitingHostWrite struct {
	*hostStorage
	started chan struct{}
	joined  chan struct{}
}

func (s *awaitingHostWrite) Write(ctx context.Context, _ string, _ []byte) error {
	close(s.started)
	<-ctx.Done()
	close(s.joined)
	return context.Cause(ctx)
}

func TestHostCertificateCanceledBridgeWriteJoinsAndReleasesLocks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := &awaitingHostWrite{hostStorage: newHostStorage(), started: make(chan struct{}), joined: make(chan struct{})}
		cache := hostCache(t, storage)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			pending, err := cache.Pending(ctx, "route.example")
			if pending.Key != nil {
				err = errors.Join(err, errors.New("canceled bridge write released a key"))
			}
			done <- err
		}()
		<-storage.started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		select {
		case <-storage.joined:
		default:
			t.Fatal("pending returned before the host write joined")
		}
		if pending, err := hostCache(t, storage.hostStorage).Pending(t.Context(), "route.example"); err != nil || pending.Key == nil {
			t.Fatal("canceled bridge retained mutation or checkpoint locks", err)
		}
	})
}

func TestHostCertificatePartialFirstCheckpointFailsClosed(t *testing.T) {
	storage := newHostStorage()
	cache := hostCache(t, storage)
	storage.writeError = errors.New("interrupted before first plan checkpoint")
	if pending, err := cache.Pending(t.Context(), "route.example"); err == nil || pending.Key != nil {
		t.Fatal("incomplete first checkpoint released a key", err)
	}
	storage.writeError = nil
	reopened := hostCache(t, storage)
	if pending, err := reopened.Pending(t.Context(), "route.example"); !errors.Is(err, ErrPublisherStateConflict) || pending.Key != nil {
		t.Fatal("partial checkpoint was reconstructed from an uncertain key", err)
	}
	if pending, err := reopened.NewPending(t.Context(), "route.example"); !errors.Is(err, ErrPublisherStateConflict) || pending.Key != nil {
		t.Fatal("partial checkpoint authorized a replacement key", err)
	}
}

type cancelAfterCertificateWrite struct {
	*hostStorage
	cancel context.CancelFunc
}

func (s *cancelAfterCertificateWrite) Write(ctx context.Context, name string, data []byte) error {
	err := s.hostStorage.Write(ctx, name, data)
	if err == nil && name != "certificate-plans-v1.json" {
		s.cancel()
	}
	return err
}

func TestCertificateFirstCheckpointFinishesAfterCommittedWrite(t *testing.T) {
	storage := newHostStorage()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cache := hostCache(t, &cancelAfterCertificateWrite{hostStorage: storage, cancel: cancel})
	if pending, err := cache.Pending(ctx, "route.example"); !errors.Is(err, context.Canceled) || pending.Key != nil || len(pending.CSRDER) != 0 {
		t.Fatal("canceled issuance released pending material", err)
	}
	reopened := hostCache(t, storage)
	snapshot, err := reopened.read(t.Context())
	if err != nil || snapshot.Pending == nil {
		t.Fatal("cancellation stranded the committed key without its plan checkpoint", err)
	}
	defer snapshot.destroy()
	if pending, err := reopened.Pending(t.Context(), "route.example"); err != nil || !bytes.Equal(pending.CSRDER, snapshot.Pending.CSRDER) {
		t.Fatal("replacement run could not reuse the original pending CSR", err)
	}
}
