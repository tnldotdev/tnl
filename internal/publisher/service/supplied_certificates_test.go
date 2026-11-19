package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/certificatestore"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/certificatetest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type suppliedWorkerControl struct {
	*lifecycleControl
	ack func(context.Context, string, string) (controlv1.SuppliedServiceCertificateInstallation, error)
}

type suppliedMemoryStorage struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (s *suppliedMemoryStorage) Read(_ context.Context, key string, _ int64) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.records[key]
	return bytes.Clone(value), found, nil
}
func (s *suppliedMemoryStorage) Write(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = bytes.Clone(value)
	return nil
}
func (*suppliedMemoryStorage) Sync(context.Context, string) error { return nil }
func (*suppliedMemoryStorage) Lock(context.Context, string) (io.Closer, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func suppliedMemoryCertificateStore(t *testing.T, cfg *RunConfig) {
	t.Helper()
	files := &suppliedMemoryStorage{records: map[string][]byte{}}
	cfg.CertificateStore = certificateStoreFunc(func(team, publisher string, plan controlv1.CertificatePlan) (*certificatestore.CertificateCache, error) {
		return certificatestore.New(files, certificatestore.Scope{ControlURL: "https://control.example.test", TeamID: team, PublisherIdentityID: publisher}, plan)
	})
}

func (c *suppliedWorkerControl) MarkSuppliedServiceCertificateInstalled(ctx context.Context, service, run string, number int64, chain, previous string, token credentials.ServiceRunToken) (controlv1.SuppliedServiceCertificateInstallation, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.setup.RunToken {
		return controlv1.SuppliedServiceCertificateInstallation{}, ErrPrivateStream
	}
	return c.ack(ctx, chain, previous)
}

func TestSuppliedCertificateWorkerInstallationAndReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base := lifecycleFixture(t)
		suppliedMemoryCertificateStore(t, &cfg)
		now := time.Now().Truncate(time.Second)
		issuer := certificatetest.New(t, now)
		first := issuer.Issue(t, []string{base.prep.Hostname}, now, now.Add(2*time.Minute), nil)
		second := issuer.Issue(t, []string{base.prep.Hostname}, now, now.Add(4*time.Minute), nil)
		selected := first
		var sourceMu sync.Mutex
		cfg.SuppliedCertificate = func(context.Context) (CertificateMaterial, error) {
			sourceMu.Lock()
			defer sourceMu.Unlock()
			return CertificateMaterial{CertificatePEM: bytes.Clone(selected.Chain), PrivateKeyPEM: bytes.Clone(selected.Key)}, nil
		}
		entered, release := make(chan struct{}), make(chan struct{})
		var fingerprint string
		var calls atomic.Int32
		control := &suppliedWorkerControl{lifecycleControl: base}
		control.ack = func(ctx context.Context, chain, previous string) (controlv1.SuppliedServiceCertificateInstallation, error) {
			if calls.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return controlv1.SuppliedServiceCertificateInstallation{}, ctx.Err()
				}
			}
			validated, err := certificateidentity.ValidateSuppliedChain([]byte(chain), []string{base.prep.Hostname}, time.Now(), issuer.Roots)
			if err != nil {
				return controlv1.SuppliedServiceCertificateInstallation{}, err
			}
			if previous != fingerprint {
				t.Error("worker did not fence replacement with its acknowledged leaf")
			}
			fingerprint = validated.Fingerprint
			return controlv1.SuppliedServiceCertificateInstallation{CertificateSha256: fingerprint, ExpiresAt: validated.ExpiresAt}, nil
		}
		approved, err := base.GetPublisherService(t.Context(), cfg.ServiceID, "")
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := newManagedPrepared(base.prep, approved, cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		exporter := new(CertificateExport)
		unbind, err := exporter.bind(ctx, prepared)
		if err != nil {
			t.Fatal(err)
		}
		defer unbind()
		checkExport := func(want certificatetest.Material, deadline time.Time) {
			t.Helper()
			value, err := exporter.Snapshot(t.Context())
			if err != nil || !value.ExpiresAt.Equal(deadline) {
				t.Fatal("export missed the installed certificate", err)
			}
			defer clear(value.PrivateKeyPEM)
			bundle, err := tls.X509KeyPair(value.CertificatePEM, value.PrivateKeyPEM)
			if err != nil || !bytes.Equal(bundle.Certificate[0], want.Certificate.Certificate[0]) {
				t.Fatal("exported chain/key do not match the installed leaf", err)
			}
		}
		maintain, cleanup, err := configureServiceRun(ctx, cfg, prepared, base.setup, control, cfg.State, nil)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- maintain() }()
		synctest.Wait()
		select {
		case <-entered:
		default:
			t.Fatal("supplied ACK was not entered")
		}
		if _, err := prepared.currentCertificate(); err == nil {
			t.Fatal("unacknowledged supplied key became available to visitor TLS")
		}
		if _, err := exporter.Snapshot(t.Context()); !errors.Is(err, ErrCertificateUnavailable) {
			t.Fatal("export exposed a pending install", err)
		}
		close(release)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("initial material was not installed once")
		}
		certificate, err := prepared.currentCertificate()
		if err != nil || !bytes.Equal(certificate.Certificate[0], first.Certificate.Certificate[0]) {
			t.Fatal("supplied leaf was not installed", err)
		}
		checkExport(first, now.Add(2*time.Minute))
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("unchanged source created another control installation")
		}
		sourceMu.Lock()
		selected = second
		selected.Key = []byte("bad replacement")
		sourceMu.Unlock()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		checkExport(first, now.Add(2*time.Minute))
		sourceMu.Lock()
		selected = second
		sourceMu.Unlock()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		certificate, err = prepared.currentCertificate()
		if err != nil || calls.Load() != 2 || !bytes.Equal(certificate.Certificate[0], second.Certificate.Certificate[0]) {
			t.Fatal("replacement did not reach the same run", err, calls.Load())
		}
		checkExport(second, now.Add(4*time.Minute))
		cancel()
		if _, err := exporter.Snapshot(t.Context()); !errors.Is(err, ErrCertificateUnavailable) {
			t.Fatal("export outlived run cancellation", err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("supplied worker did not join cancellation", err)
		}
		base.mu.Lock()
		defer base.mu.Unlock()
		if base.installs != 0 {
			t.Fatal("supplied publication acknowledged a managed issuance")
		}
	})
}

func TestSuppliedCertificateWorkerRecoversLostACKAndStopsAtChainExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base := lifecycleFixture(t)
		suppliedMemoryCertificateStore(t, &cfg)
		now := time.Now().Truncate(time.Second)
		issuer := certificatetest.New(t, now)
		material := issuer.Issue(t, []string{base.prep.Hostname}, now, now.Add(time.Minute), nil)
		cfg.SuppliedCertificate = func(context.Context) (CertificateMaterial, error) {
			return CertificateMaterial{CertificatePEM: bytes.Clone(material.Chain), PrivateKeyPEM: bytes.Clone(material.Key)}, nil
		}
		control := &suppliedWorkerControl{lifecycleControl: base}
		calls := 0
		control.ack = func(_ context.Context, chain, previous string) (controlv1.SuppliedServiceCertificateInstallation, error) {
			calls++
			validated, err := certificateidentity.ValidateSuppliedChain([]byte(chain), []string{base.prep.Hostname}, time.Now(), issuer.Roots)
			if err != nil {
				return controlv1.SuppliedServiceCertificateInstallation{}, err
			}
			if calls == 1 {
				return controlv1.SuppliedServiceCertificateInstallation{}, io.ErrUnexpectedEOF
			}
			// control may narrow leaf validity to the verified chain deadline.
			return controlv1.SuppliedServiceCertificateInstallation{CertificateSha256: validated.Fingerprint, ExpiresAt: now.Add(5 * time.Second)}, nil
		}
		approved, _ := base.GetPublisherService(t.Context(), cfg.ServiceID, "")
		prepared, err := newManagedPrepared(base.prep, approved, cfg)
		if err != nil {
			t.Fatal(err)
		}
		exporter := new(CertificateExport)
		unbind, err := exporter.bind(t.Context(), prepared)
		if err != nil {
			t.Fatal(err)
		}
		defer unbind()
		maintain, cleanup, err := configureServiceRun(t.Context(), cfg, prepared, base.setup, control, cfg.State, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		done := make(chan error, 1)
		go func() { done <- maintain() }()
		synctest.Wait()
		if _, err := prepared.currentCertificate(); err == nil {
			t.Fatal("lost ACK prematurely exposed serving material")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if _, err := prepared.currentCertificate(); err != nil || calls != 2 {
			t.Fatal("lost ACK was not recovered", err, calls)
		}
		exported, err := exporter.Snapshot(t.Context())
		if err != nil || !exported.ExpiresAt.Equal(now.Add(5*time.Second)) {
			t.Fatal("export used the leaf deadline rather than the verified chain deadline", err)
		}
		clear(exported.PrivateKeyPEM)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-done; !errors.Is(err, errCertificateExpired) {
			t.Fatal("supplied certificate outlived its control-confirmed chain", err)
		}
		if _, err := prepared.currentCertificate(); err == nil {
			t.Fatal("expired supplied certificate remained available")
		}
		if _, err := exporter.Snapshot(t.Context()); !errors.Is(err, ErrCertificateUnavailable) {
			t.Fatal("expired supplied certificate remained exportable", err)
		}
	})
}

func TestSuppliedCertificateSourceErrorPreservesCauseWithoutPrivateMessage(t *testing.T) {
	cause := errors.New("PRIVATE KEY MATERIAL")
	worker := suppliedCertificateWorker{source: func(context.Context) (CertificateMaterial, error) {
		return CertificateMaterial{}, cause
	}}
	_, err := worker.advance(t.Context(), "")
	if !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("certificate source failure lost its cause or exposed private context")
	}
}
