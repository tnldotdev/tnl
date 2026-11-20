package invocation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// control is a fake authority; Publish still owns real certificate work, relay
// hellos, claimed WSS/yamux sessions, readiness and joined local shutdown.
type cliFallbackObservationControl struct {
	publisherservice.RunControl
	saved       controlv1.Service
	prep        controlv1.ServiceRunPreparation
	setup       controlv1.ServiceRunSetup
	closes      atomic.Int32
	hookMu      sync.Mutex
	beforeHello func()
}

func (*cliFallbackObservationControl) ControlURL() string { return "https://control.example.test" }
func (c *cliFallbackObservationControl) GetPublisherService(context.Context, string, string) (controlv1.Service, error) {
	return c.saved, nil
}
func (c *cliFallbackObservationControl) PrepareServiceRun(_ context.Context, _, key, _ string, _ controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	prep := c.prep
	prep.IdempotencyKey = key
	return prep, nil
}
func (c *cliFallbackObservationControl) StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error) {
	return c.setup, nil
}
func (c *cliFallbackObservationControl) HeartbeatServiceRun(_ context.Context, _, _ string, _ credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	now := time.Now()
	return controlv1.ServiceRunState{ServiceId: c.saved.Id, ServiceRunId: c.prep.ServiceRunId, RunNumber: c.prep.RunNumber,
		State: "ready", Healthy: &health.Healthy, ObservedAt: now, PublisherExpiresAt: now.Add(time.Minute),
		EndpointRevision: c.saved.EndpointRevision, PublicEndpointReady: true, PublisherConnections: c.setup.PublisherConnections}, nil
}
func (c *cliFallbackObservationControl) CloseServiceRun(context.Context, string, string, credentials.ServiceRunToken) error {
	c.closes.Add(1)
	return nil
}
func (*cliFallbackObservationControl) ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error {
	return nil
}
func (*cliFallbackObservationControl) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, _ string) (controlv1.VisitorPolicyUpdate, error) {
	now := time.Now()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "app.example", Issuer: "https://control.example.test", Enabled: true,
			VisitorPolicyRevision: 1, MetadataRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime),
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: key.Public().(ed25519.PublicKey)}}}}, nil
}
func (*cliFallbackObservationControl) ListConnectorPeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	return controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{}}, nil
}
func (*cliFallbackObservationControl) WaitPublisherRun(ctx context.Context, scope controlv1.PublisherWatchRun) (controlv1.PublisherWatchChange, error) {
	if scope.ConnectorRevision == nil {
		return controlv1.PublisherWatchChange{ServiceRunId: scope.ServiceRunId, PolicyBookmark: "fixture"}, nil
	}
	<-ctx.Done()
	return controlv1.PublisherWatchChange{}, ctx.Err()
}
func (c *cliFallbackObservationControl) CreateServiceCertificateIssuance(_ context.Context, service, run string, number int64, _ credentials.ServiceRunToken, der []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		return controlv1.ServiceCertificateIssuance{}, err
	}
	chain := string(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...))
	return controlv1.ServiceCertificateIssuance{Id: "fixture-issuance", PublisherIdentityId: c.prep.PublisherIdentityId,
		ServiceId: service, ServiceRunId: run, RunNumber: number, CertificatePlan: *c.prep.CertificatePlan,
		State: controlv1.CertificateIssuanceStateWaitingForInstall, CertificatePem: &chain, NotBefore: &leaf.NotBefore, NotAfter: &leaf.NotAfter}, nil
}
func (*cliFallbackObservationControl) MarkServiceCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.ServiceRunToken) error {
	return nil
}

type cliFallbackObservationSlot struct {
	publisherservice.SlotSession
	entered chan<- struct{}
	release <-chan struct{}
	done    chan struct{}
	once    sync.Once
	err     error
}

func (s *cliFallbackObservationSlot) Close() error {
	s.once.Do(func() {
		s.err = s.SlotSession.Close()
		s.entered <- struct{}{}
		<-s.release
		close(s.done)
	})
	return s.err
}

func cliFallbackAwait[T any](t *testing.T, event <-chan T) T {
	t.Helper()
	select {
	case value := <-event:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("real CLI fallback owner did not reach its observation")
		var zero T
		return zero
	}
}

func cliFallbackObservationFixture(t *testing.T) (*clientstate.Database, *clientstate.Tunnel, controlv1.Service, publisherservice.RunConfig, *cliFallbackObservationControl, <-chan struct{}) {
	t.Helper()
	db, journal, saved, cfg := serviceCLIJournal(t, controlv1.Tcp, true)
	saved.Enabled, saved.TrustRevision, saved.EndpointRevision = true, 1, 1
	saved.TeamId, saved.DomainId = serviceTestID(t, opaqueid.TeamPrefix), new(serviceTestID(t, opaqueid.DomainPrefix))
	saved.Endpoint.Port = 25443
	now := time.Now()
	traffic := trafficlimits.Default()
	control := &cliFallbackObservationControl{saved: saved}
	control.prep = controlv1.ServiceRunPreparation{ServiceId: saved.Id, TeamId: saved.TeamId, DomainId: *saved.DomainId,
		ServiceRunId: serviceTestID(t, opaqueid.ServiceRunPrefix), RunNumber: 7, RunToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PublisherIdentityId: serviceTestID(t, opaqueid.PublisherIdentityPrefix), PublisherGrantId: serviceTestID(t, opaqueid.PublisherGrantPrefix),
		PublisherKeyId: serviceTestID(t, opaqueid.PublisherIdentityKeyPrefix), Hostname: saved.Endpoint.Hostname, ExpiresAt: now.Add(time.Minute),
		CertificatePlan: &controlv1.CertificatePlan{CacheKey: saved.Endpoint.Hostname, Scope: saved.Endpoint.Hostname, Identifiers: []string{saved.Endpoint.Hostname}, ChallengeMethod: controlv1.Dns01},
		Traffic: controlv1.TrafficLimits{Connections: traffic.Connections, Rate: traffic.Rate, RatePerNs: int64(traffic.RatePer), Burst: traffic.Burst,
			UploadBytes: traffic.UploadBytes, DownloadBytes: traffic.DownloadBytes}}
	control.setup = controlv1.ServiceRunSetup{ServiceId: saved.Id, ServiceRunId: control.prep.ServiceRunId, RunNumber: 7,
		RunToken: control.prep.RunToken, VisitorSourceKey: bytes.Repeat([]byte{1}, 32)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certificate := visitorfixture.Certificate(t, "relay.test")
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	for slot := range 2 {
		control.setup.PublisherConnections = append(control.setup.PublisherConnections, controlv1.ConnectionAssignment{
			PublisherConnectionId: serviceTestID(t, opaqueid.PublisherConnectionPrefix), ConnectionSlot: slot, ConnectionAssignmentRevision: 1,
			RelayServiceId: []string{"relay-a", "relay-b"}[slot], RelayAddress: listener.Addr().String(), TlsServerName: "relay.test",
			PublisherConnectionCredential: "fixture-assignment-credential", PublisherConnectionCredentialExpiresAt: now.Add(time.Minute)})
	}
	cfg.PublisherIdentityID, cfg.PublisherGrantID, cfg.PublisherKeyID = control.prep.PublisherIdentityId, control.prep.PublisherGrantId, control.prep.PublisherKeyId
	cfg.Control, cfg.HeartbeatInterval, cfg.Healthy = control, 10*time.Millisecond, func(context.Context) bool { return true }
	cfg.Access = func(context.Context) (string, error) { return "fixture-publisher-token", nil }
	cfg.Connectivity.DisableDirect = true
	cfg.TransportTLS = &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)}
	cfg.RelayQUIC = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return nil, net.ErrClosed })
	cfg.State, err = db.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var acceptor, workers sync.WaitGroup
	closed := make(chan struct{}, 2)
	acceptor.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				outer, err := muxsession.AcceptWebSocket(ctx, conn, serverTLS, muxsession.WebSocketConfig{})
				if err != nil {
					return
				}
				defer outer.Close()
				session, _, err := tunnel.Accept(ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
					ref := hello.ServiceConnection
					if ref == nil || ref.ConnectionSlot > 1 || ref.ServiceID != saved.Id || ref.ServiceRunID != control.prep.ServiceRunId || ref.RunNumber != 7 {
						return publisherservice.ErrPrivateStream
					}
					assignment := control.setup.PublisherConnections[ref.ConnectionSlot]
					if ref.PublisherConnectionID != assignment.PublisherConnectionId || ref.ConnectionAssignmentRevision != 1 ||
						ref.RelayServiceID != assignment.RelayServiceId || hello.Credential != assignment.PublisherConnectionCredential {
						return publisherservice.ErrPrivateStream
					}
					control.hookMu.Lock()
					beforeHello := control.beforeHello
					control.hookMu.Unlock()
					if beforeHello != nil {
						beforeHello()
					}
					return nil
				})
				if err != nil {
					return
				}
				defer func() { _ = session.Close(); closed <- struct{}{} }()
				_ = session.HandlePublisherDrain(ctx, func(context.Context) error { return nil })
				select {
				case <-outer.Done():
				case <-ctx.Done():
				}
			})
		}
	})
	t.Cleanup(func() { cancel(); _ = listener.Close(); acceptor.Wait(); workers.Wait() })
	return db, journal, saved, cfg, control, closed
}

func TestServiceCLIFallbackRestorationStaleAcceptedTLSNeverReports(t *testing.T) {
	_, journal, saved, cfg, control, remoteClosed := cliFallbackObservationFixture(t)
	bounds := make(chan *publisherservice.Bound, 1)
	attempted := make(chan error, 1)
	control.hookMu.Lock()
	control.beforeHello = func() { (<-bounds).Invalidate() }
	control.hookMu.Unlock()
	cfg.Connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
		if slot == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		bounds <- bound
		claimed, err := bound.ConnectSlot(ctx, slot, options)
		attempted <- err
		return claimed, err
	}
	var fallback, ready atomic.Int32
	output := &Presentation{TransportFallback: func(uint64, string) error { fallback.Add(1); return nil },
		Ready: func(string, uint64) error { ready.Add(1); return nil }}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done, joined := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(joined)
		done <- RunServiceCLI(ctx, journal, saved, cfg, output, publisherservice.Publish)
	}()
	defer func() { cancel(); cliFallbackAwait(t, joined) }()
	if err := cliFallbackAwait(t, attempted); !errors.Is(err, publisherservice.ErrPrivateStream) {
		t.Fatal("real accepted stale TLS was not rejected", err)
	}
	cancel()
	_ = cliFallbackAwait(t, done)
	cliFallbackAwait(t, remoteClosed)
	if fallback.Load() != 0 || ready.Load() != 0 || control.closes.Load() != 1 {
		t.Fatal("stale accepted TLS reported fallback/readiness or skipped run cleanup", fallback.Load(), ready.Load(), control.closes.Load())
	}
}

func TestServiceCLIFallbackRestorationRealPublishReportsBeforeReadyAndJoins(t *testing.T) {
	for _, mode := range []string{"held-success", "held-error", "canceled-while-held"} {
		t.Run(mode, func(t *testing.T) {
			db, journal, saved, cfg, control, remoteClosed := cliFallbackObservationFixture(t)
			metrics := observability.New("publisher")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), metrics))
			defer cancel()
			entered, reportRelease := make(chan struct{}), make(chan struct{})
			closeEntered, closeRelease := make(chan struct{}, 2), make(chan struct{})
			releaseReport := sync.OnceFunc(func() { close(reportRelease) })
			releaseClose := sync.OnceFunc(func() { close(closeRelease) })
			defer releaseReport()
			defer releaseClose()
			var reported atomic.Bool
			var fallback, notifications atomic.Int32
			ready := make(chan struct{}, 1)
			slots := make(chan *cliFallbackObservationSlot, 2)
			cfg.Connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
				claimed, err := bound.ConnectSlot(ctx, slot, options)
				if err != nil {
					return nil, err
				}
				session := &cliFallbackObservationSlot{SlotSession: claimed, entered: closeEntered, release: closeRelease, done: make(chan struct{})}
				slots <- session
				return session, nil
			}
			reportErr := errors.New("real TLS fallback reporting failed")
			output := &Presentation{TransportFallback: func(number uint64, transport string) error {
				if number != 7 || transport != string(tunnel.TransportWSS) || fallback.Add(1) != 1 {
					t.Error("real accepted fallback was misidentified or repeated")
				}
				close(entered)
				<-reportRelease
				reported.Store(true)
				if mode == "held-error" {
					return reportErr
				}
				return nil
			}, Ready: func(string, uint64) error {
				if !reported.Load() {
					t.Error("Ready notification overtook the real fallback report")
				}
				notifications.Add(1)
				ready <- struct{}{}
				return nil
			}}
			published, joined := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(joined)
				published <- RunServiceCLI(ctx, journal, saved, cfg, output, publisherservice.Publish)
			}()
			defer func() { releaseReport(); releaseClose(); cancel(); cliFallbackAwait(t, joined) }()
			cliFallbackAwait(t, entered)
			// both real hello handshakes finish while the report remains held.
			// this is not a requirement that presentation gate physical serving.
			var claimed [2]*cliFallbackObservationSlot
			for slot := range 2 {
				claimed[slot] = cliFallbackAwait(t, slots)
			}
			if notifications.Load() != 0 {
				t.Fatal("held fallback report announced Ready")
			}
			snapshot, err := db.Snapshot(t.Context())
			if err != nil || len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].State != clientstate.TunnelStateProvisioning {
				t.Fatal("held real fallback report advanced the journal to Ready", snapshot, err)
			}
			if mode == "canceled-while-held" {
				cancel()
			}
			select {
			case err := <-published:
				t.Fatal("CLI owner returned while real fallback reporting was held", err)
			default:
			}
			releaseReport()
			if mode == "held-success" {
				cliFallbackAwait(t, ready)
				cancel()
			}
			cliFallbackAwait(t, closeEntered)
			select {
			case err := <-published:
				t.Fatal("CLI owner returned before entered relay cleanup joined", err)
			default:
			}
			releaseClose()
			err = cliFallbackAwait(t, published)
			if mode == "held-error" && !errors.Is(err, reportErr) || mode != "held-error" && err != nil {
				t.Fatal("real publication lost the fallback reporting result", err)
			}
			wantReady := int32(0)
			if mode == "held-success" {
				wantReady = 1
			}
			if notifications.Load() != wantReady || fallback.Load() != 1 || control.closes.Load() != 1 {
				t.Fatal("real fallback repeated readiness/reporting or skipped run cleanup", notifications.Load(), fallback.Load(), control.closes.Load())
			}
			families, gatherErr := metrics.Gather()
			if gatherErr != nil {
				t.Fatal(gatherErr)
			}
			var successes float64
			for _, family := range families {
				if family.GetName() != "tnl_publisher_connection_attempts_total" {
					continue
				}
				for _, point := range family.Metric {
					labels := map[string]string{}
					for _, label := range point.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["tnl_transport"] == "wss" && labels["tnl_transport_preference"] == "quic" && labels["tnl_outcome"] == "success" {
						successes += point.GetCounter().GetValue()
					}
				}
			}
			if successes != 2 {
				t.Fatal("real accepted TLS fallbacks lost their successful connection observations", successes)
			}
			for _, session := range claimed {
				cliFallbackAwait(t, session.done)
				cliFallbackAwait(t, remoteClosed)
			}
			if journal.Context().Err() != nil {
				t.Fatal("CLI observation finalized its caller-owned journal")
			}
		})
	}
}
