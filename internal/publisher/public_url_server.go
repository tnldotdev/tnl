package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// PublicURLServerConfig configures publisher TLS termination and local HTTP forwarding.
type PublicURLServerConfig struct {
	Context               context.Context
	AuditSink             serviceaudit.Sink
	Hostname              string
	PreviewID             string
	PublicURLID           string
	PublishRunNumber      uint64
	PublishRunID          string
	Target                string
	ResolveTarget         func(context.Context) (string, string, error)
	ServiceProtocol       controlv1.PublicURLServiceProtocol
	Purpose               controlv1.PublicURLPurpose
	AccessMode            controlv1.VisitorAccessMode
	TargetTLSName         string
	TargetOptions         publisherproxy.TargetOptions
	Handler               http.Handler
	AdmitRequest          func(*http.Request) error
	ObserveResponse       func(*http.Response) error
	Mounts                []publisherproxy.Mount
	ShareAccess           *shareAccess
	BrowserAccess         *browserAccess
	BrowserLoginAvailable bool
	Feedback              *feedbackRuntime
	Limits                ApplicationLimits
	VisitorPolicy         *visitorlease.Lease
	VisitorTokens         *browserTokens
	VisitorSourceKey      [32]byte
	// authorized visitor connections across both relays; zero uses traffic defaults.
	StreamCapacity  int
	OnTargetFailure func()
	ObserveSummary  inspection.Observer
	PromoteVisitor  PromoteVisitor
	AdmitVisitor    AdmitVisitor
	ReadinessProof  *ReadinessProof
	OnWarning       func(string)
	InspectionMode  inspection.Mode
	Certificate     tls.Certificate
	CertificatePlan controlv1.CertificatePlan
}

type PublicURLServer struct {
	hostname           string
	policy             *visitorlease.Lease
	visitorSourceKey   [32]byte
	sourceHistory      map[[32]byte]*visitorSourceHistory
	sourceExpirations  visitorSourceExpirations
	sourceTime         int64
	certificatePlan    controlv1.CertificatePlan
	tls                *tls.Config
	certificate        atomic.Pointer[tls.Certificate]
	certificateTimer   *time.Timer
	certificateExpired chan struct{}
	queue              *publicURLListener
	http               *http.Server
	bodyTimeout        time.Duration
	mu                 sync.Mutex
	started            bool
	closed             bool
	draining           bool
	drainDone          chan struct{}
	drainErr           error
	streams            map[net.Conn]*publicVisitorAdmission
	streamCapacity     int
	authorizedStreams  int
	pendingStreams     int
	pendingRelays      map[string]int
	pendingSources     map[netip.Prefix]int
	handlers           sync.WaitGroup
	httpDone           chan error
	closeOnce          sync.Once
	closeErr           error
	admission          *applicationAdmission
	run                PublishRunIdentity
	promote            PromoteVisitor
	defaultPromote     PromoteVisitor
	guard              AdmitVisitor
	life               context.Context
	cancel             context.CancelFunc
	sessions           [publisherConnectionCount]*livePublisherSession
}

// Start starts publisher TLS termination and local HTTP forwarding.
func (r *PublicURLServer) Start() error {
	return r.start()
}

func (r *PublicURLServer) start() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return errors.New("publisher: public URL already started")
	}
	r.started = true
	r.mu.Unlock()
	r.startHTTP()
	return nil
}

func (r *PublicURLServer) Drain(ctx context.Context) error {
	r.stopAdmissions()
	r.mu.Lock()
	done := r.drainDone
	r.mu.Unlock()
	if done == nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return errors.Join(r.drainErr, ctx.Err())
	}
}

func (r *PublicURLServer) stopAdmissions() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.draining = true
	if r.drainDone == nil {
		r.drainDone = make(chan struct{})
		streams := make([]*publicVisitorAdmission, 0, len(r.streams))
		for _, stream := range r.streams {
			streams = append(streams, stream)
		}
		// one run-owned worker performs potentially blocking connection, queue,
		// and HTTP shutdown. a drain caller bounds its wait; Close joins the work.
		go r.drain(streams)
	}
}

func (r *PublicURLServer) drain(streams []*publicVisitorAdmission) {
	defer close(r.drainDone)
	r.http.SetKeepAlivesEnabled(false)
	var pending []<-chan struct{}
	for _, stream := range streams {
		if done := stream.stopPending(); done != nil {
			pending = append(pending, done)
		}
	}
	r.drainErr = r.http.Shutdown(r.life)
	for _, done := range pending {
		<-done
	}
}

func (r *PublicURLServer) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Lock()
		r.closed = true
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
			r.certificateTimer = nil
		}
		started := r.started
		drainDone := r.drainDone
		streams := make([]net.Conn, 0, len(r.streams))
		for _, admission := range r.streams {
			streams = append(streams, admission.connection)
		}
		r.mu.Unlock()
		result := errors.Join(r.http.Close(), r.queue.Close())
		for _, stream := range streams {
			_ = stream.Close()
		}
		r.handlers.Wait()
		if drainDone != nil {
			<-drainDone
		}
		if started {
			result = errors.Join(result, <-r.httpDone)
		}
		r.closeErr = result
	})
	return r.closeErr
}

func (r *PublicURLServer) startHTTP() {
	// the body owner precedes authentication/header clones and clears its read
	// deadline at upload completion, without limiting a streamed response.
	r.http.Handler = httpstream.Requests(r.http.Handler, r.bodyTimeout)
	go func() {
		err := r.http.Serve(r.queue)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		r.httpDone <- err
		close(r.httpDone)
	}()
}
