package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	TargetOptions         localproxy.TargetOptions
	Handler               http.Handler
	AdmitRequest          func(*http.Request) error
	ObserveResponse       func(*http.Response) error
	Mounts                []localproxy.Mount
	ShareAccess           *shareAccess
	BrowserAccess         *browserAccess
	BrowserLoginAvailable bool
	Feedback              *feedbackRuntime
	Limits                ApplicationLimits
	OnTargetFailure       func()
	ObserveSummary        inspection.Observer
	PromoteVisitor        PromoteVisitor
	AdmitVisitor          AdmitVisitor
	ReadinessProof        *ReadinessProof
	OnWarning             func(string)
	InspectionMode        inspection.Mode
	Certificate           tls.Certificate
	CertificatePlan       controlv1.CertificatePlan
}

type PublicURLServer struct {
	hostname              string
	certificatePlan       controlv1.CertificatePlan
	tls                   *tls.Config
	certificate           atomic.Pointer[tls.Certificate]
	certificateTimer      *time.Timer
	certificateExpired    chan struct{}
	queue                 *publicURLListener
	http                  *http.Server
	bodyTimeout           time.Duration
	mu                    sync.Mutex
	started               bool
	closed                bool
	draining              bool
	streams               map[net.Conn]struct{}
	visitorPolicyRevision int64
	handlers              sync.WaitGroup
	httpDone              chan error
	closeOnce             sync.Once
	closeErr              error
	admission             *applicationAdmission
	run                   PublishRunIdentity
	promote               PromoteVisitor
	defaultPromote        PromoteVisitor
	guard                 AdmitVisitor
	life                  context.Context
	cancel                context.CancelFunc
	sessions              [publisherConnectionCount]*livePublisherSession
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
	return r.http.Shutdown(ctx)
}

func (r *PublicURLServer) stopAdmissions() {
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
	r.http.SetKeepAlivesEnabled(false)
}

// invalidateVisitorPolicy closes existing application streams, including HTTP
// upgrades. the run and publisher connections continue admitting fresh visitors.
func (r *PublicURLServer) invalidateVisitorPolicy(revision int64) {
	r.mu.Lock()
	if revision <= r.visitorPolicyRevision {
		r.mu.Unlock()
		return
	}
	previous := r.visitorPolicyRevision
	r.visitorPolicyRevision = revision
	var streams []net.Conn
	if previous > 0 {
		for stream := range r.streams {
			streams = append(streams, stream)
		}
	}
	r.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
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
		streams := make([]net.Conn, 0, len(r.streams))
		for stream := range r.streams {
			streams = append(streams, stream)
		}
		r.mu.Unlock()
		result := errors.Join(r.http.Close(), r.queue.Close())
		for _, stream := range streams {
			_ = stream.Close()
		}
		r.handlers.Wait()
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
