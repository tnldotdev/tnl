package publisher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// Visitor identifies one authenticated relay stream and its original endpoints.
// Header is absent only for in-process test connections. it is never derived
// from HTTP headers or database startup fields.
type Visitor struct {
	Run         PublishRunIdentity
	Header      tunnelv1.VisitorStreamHeader
	Source      netip.AddrPort
	Destination netip.AddrPort
	// readiness is set only after an exact, single-use proof was consumed.
	Readiness bool
}

// PromoteVisitor overrides ingress application promotion. the engine supplies
// the exact-session sideband default. readiness never invokes this callback.
type PromoteVisitor func(context.Context, Visitor) error

// AdmitVisitor checks current application ownership on every use, including
// proven readiness GETs. unlike promotion, a successful check is not cached.
type AdmitVisitor func(context.Context, Visitor) error

// AuthorizeVisitorCertificate runs after visitor TLS and before database auth.
// the caller owns certificate issuance, trust, and current control authorization.
type AuthorizeVisitorCertificate func(context.Context, Visitor, tls.ConnectionState) error

// RevalidateVisitorCertificate returns a fresh database permission and its hard
// deadline. the publisher shares it only across exact active proofs and keeps
// checking established connections, including explicitly anonymous visitors.
type RevalidateVisitorCertificate func(context.Context, Visitor, tls.ConnectionState) (livevisitor.Decision, error)

type VisitorCertificateDecisionAuthorizer interface {
	AuthorizeVisitorCertificateDecision(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState) (time.Time, error)
}

// LiveVisitorCertificateAuthorization bypasses the new-connection positive
// cache. control owns current grant, IP filter, and publish-run checks.
func LiveVisitorCertificateAuthorization(client VisitorCertificateDecisionAuthorizer, scope controlclient.VisitorCertificateScope) RevalidateVisitorCertificate {
	return func(ctx context.Context, visitor Visitor, state tls.ConnectionState) (livevisitor.Decision, error) {
		if client == nil || scope.PublicURLID == "" || scope.PublishRunID == "" || scope.PublishRunNumber == 0 || scope.PublishRunToken == "" ||
			visitor.Run.PublicURLID != scope.PublicURLID || visitor.Run.Number != scope.PublishRunNumber ||
			visitor.Run.PublishRunID != "" && visitor.Run.PublishRunID != scope.PublishRunID ||
			visitor.Header.PublishRunID != "" && visitor.Header.PublishRunID != scope.PublishRunID ||
			visitor.Header.PublicURLID != "" && visitor.Header.PublicURLID != scope.PublicURLID ||
			visitor.Header.PublishRunNumber != 0 && visitor.Header.PublishRunNumber != scope.PublishRunNumber {
			return livevisitor.Decision{}, livevisitor.ErrDenied
		}
		if _, err := visitorAuthorizationKey(visitor, state); err != nil {
			return livevisitor.Decision{}, err
		}
		bound := scope
		bound.SourceIP = visitor.Source.Addr().Unmap()
		until, err := client.AuthorizeVisitorCertificateDecision(ctx, bound, state)
		if err != nil {
			var problem *controlclient.ProblemError
			if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, controlclient.ErrStatusConflict) ||
				errors.As(err, &problem) && (problem.Status == http.StatusUnauthorized || problem.Status == http.StatusForbidden || problem.Status == http.StatusNotFound || problem.Status == http.StatusConflict) {
				return livevisitor.Decision{}, nil
			}
			return livevisitor.Decision{}, err
		}
		if len(state.PeerCertificates) != 0 && state.PeerCertificates[0].NotAfter.Before(until) {
			until = state.PeerCertificates[0].NotAfter
		}
		return livevisitor.Decision{Allowed: true, ValidUntil: until}, nil
	}
}

func visitorAuthorizationKey(visitor Visitor, state tls.ConnectionState) (livevisitor.Key, error) {
	if !visitor.Source.IsValid() || visitor.Source.Addr().Zone() != "" || !state.HandshakeComplete || len(state.PeerCertificates) > 4 {
		return livevisitor.Key{}, livevisitor.ErrDenied
	}
	key := livevisitor.Key{PublicURLID: visitor.Run.PublicURLID, PublishRunID: visitor.Run.PublishRunID,
		PublishRunNumber: visitor.Run.Number, SourceIP: visitor.Source.Addr().Unmap()}
	if len(state.PeerCertificates) != 0 {
		leaf := state.PeerCertificates[0]
		now := time.Now()
		if leaf == nil || !now.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			return livevisitor.Key{}, livevisitor.ErrDenied
		}
		key.CertificateSHA256 = sha256.Sum256(leaf.Raw)
	}
	return key, nil
}

type VisitorCertificateAuthorizer interface {
	AuthorizeVisitorCertificate(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState) error
}

// VisitorCertificateAuthorization binds live control authorization to one run.
// source IP is always taken from trusted visitor metadata, never TLS input.
func VisitorCertificateAuthorization(client VisitorCertificateAuthorizer, scope controlclient.VisitorCertificateScope) AuthorizeVisitorCertificate {
	cache := &visitorDecisionCache[struct{}]{}
	return func(ctx context.Context, visitor Visitor, state tls.ConnectionState) error {
		if client == nil || scope.PublicURLID == "" || scope.PublishRunID == "" || scope.PublishRunNumber == 0 || scope.PublishRunToken == "" || !visitor.Source.IsValid() || visitor.Source.Addr().Zone() != "" ||
			visitor.Run.PublicURLID != scope.PublicURLID || visitor.Run.Number != scope.PublishRunNumber ||
			visitor.Run.PublishRunID != "" && visitor.Run.PublishRunID != scope.PublishRunID ||
			visitor.Header.PublishRunID != "" && visitor.Header.PublishRunID != scope.PublishRunID ||
			visitor.Header.PublicURLID != "" && visitor.Header.PublicURLID != scope.PublicURLID ||
			visitor.Header.PublishRunNumber != 0 && visitor.Header.PublishRunNumber != scope.PublishRunNumber {
			return errors.New("publisher: visitor certificate authorization has a different run")
		}
		bound := scope
		bound.SourceIP = visitor.Source.Addr().Unmap()
		cached, ok := client.(interface {
			AuthorizeVisitorCertificateDecision(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState) (time.Time, error)
		})
		if !ok {
			return client.AuthorizeVisitorCertificate(ctx, bound, state)
		}
		if !state.HandshakeComplete || len(state.PeerCertificates) > 4 {
			return errors.New("publisher: visitor certificate proof is invalid")
		}
		var fingerprint [sha256.Size]byte
		var certificateExpires time.Time
		if len(state.PeerCertificates) != 0 {
			leaf := state.PeerCertificates[0]
			certificateExpires = leaf.NotAfter
			if !time.Now().Before(certificateExpires) || time.Now().Before(leaf.NotBefore) {
				return errors.New("publisher: visitor certificate is outside its validity period")
			}
			fingerprint = sha256.Sum256(leaf.Raw)
		}
		proof, err := json.Marshal(struct {
			RunID, URLID, Source string
			Number               uint64
			Certificate          [sha256.Size]byte
		}{scope.PublishRunID, scope.PublicURLID, bound.SourceIP.String(), scope.PublishRunNumber, fingerprint})
		if err != nil {
			return err
		}
		_, err = cache.check(ctx, sha256.Sum256(proof), func(ctx context.Context) (struct{}, time.Time, bool, error) {
			expires, err := cached.AuthorizeVisitorCertificateDecision(ctx, bound, state)
			if !certificateExpires.IsZero() && certificateExpires.Before(expires) {
				expires = certificateExpires
			}
			return struct{}{}, expires, err == nil, err
		})
		return err
	}
}

const visitorPromotionTimeout = 10 * time.Second

type visitorPromotion struct {
	done chan struct{}
	err  error
}

type visitorSession struct {
	visitor    Visitor
	promote    PromoteVisitor
	guard      AdmitVisitor
	life       context.Context
	cancel     context.CancelFunc
	onPromoted func()
	mu         sync.Mutex
	promotion  *visitorPromotion
	closed     bool
	workers    sync.WaitGroup
}

// watchAuthorization is bounded by the owning visitor stream. stopping it joins
// both the connection closer and, for the last exact proof, the control checker.
func (v *visitorSession) watchAuthorization(lease *livevisitor.Lease, visitor, backend net.Conn) (func(), error) {
	if secured, ok := backend.(*tls.Conn); ok {
		backend = secured.NetConn()
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		lease.Close()
		return nil, net.ErrClosed
	}
	base := v.life
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	done := make(chan struct{})
	v.workers.Go(func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-lease.Done():
		}
		// close both raw sockets; neither a blocked Copy nor a database startup
		// read may outlive a denied permission or its owning publish run.
		_ = visitor.Close()
		_ = backend.Close()
	})
	v.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() { cancel(); <-done; lease.Close() })
	}, nil
}

func (v *visitorSession) admit(ctx context.Context, readiness ...bool) error {
	if v == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	closed := v.closed
	v.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if v.life != nil && v.life.Err() != nil {
		return v.life.Err()
	}
	visitor := v.visitor
	visitor.Readiness = len(readiness) > 0 && readiness[0]
	if v.guard != nil {
		if err := v.guard(ctx, visitor); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.life != nil && v.life.Err() != nil {
		return v.life.Err()
	}
	// a proof authorizes this GET only. it neither spends application capacity
	// nor creates an ingress decision that a later request could reuse.
	if visitor.Readiness {
		return nil
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return net.ErrClosed
	}
	if v.promotion == nil {
		work := &visitorPromotion{done: make(chan struct{})}
		v.promotion = work
		base := v.life
		if base == nil {
			base = context.Background()
		}
		v.workers.Go(func() {
			workCtx, cancel := context.WithTimeout(base, visitorPromotionTimeout)
			defer cancel()
			if v.promote != nil {
				work.err = v.promote(workCtx, visitor)
			}
			if work.err == nil {
				work.err = workCtx.Err()
			}
			if work.err == nil && v.onPromoted != nil {
				v.onPromoted()
			}
			// one shared decision is never replayed on an ambiguous transport
			// failure. request cancellation affects only its own waiter.
			close(work.done)
		})
	}
	work := v.promotion
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-work.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		if v.life != nil && v.life.Err() != nil {
			return v.life.Err()
		}
		return work.err
	}
}

func (v *visitorSession) close() {
	v.mu.Lock()
	v.closed = true
	if v.cancel != nil {
		v.cancel()
	}
	v.mu.Unlock()
	v.workers.Wait()
}

type livePublisherSession struct {
	session *tunnel.Session
	ref     tunnelv1.PublisherConnectionRef
	ctx     context.Context
	cancel  context.CancelFunc
}

type visitorSessionKey struct{}

// ReadinessProof is a short-lived, single-use proof for one exact run and GET
// path. it stays in memory and is removed before target forwarding.
type ReadinessProof struct {
	mu      sync.Mutex
	run     PublishRunIdentity
	path    string
	secret  string
	expires time.Time
}

func NewReadinessProof(run PublishRunIdentity, path string) (*ReadinessProof, error) {
	if run.PublicURLID == "" || run.Number == 0 || run.Hostname == "" || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "?#\r\n") || strings.HasPrefix(path, "/__tnl/") {
		return nil, errors.New("publisher: readiness proof requires an exact run and absolute path")
	}
	p := &ReadinessProof{run: run, path: path}
	if _, err := p.Renew(); err != nil {
		return nil, err
	}
	return p, nil
}

// Renew replaces any outstanding proof for a later check of the same run/path.
// the returned value belongs only in the probe's private request header.
func (p *ReadinessProof) Renew() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secret = hex.EncodeToString(secret[:])
	p.expires = time.Now().Add(2 * time.Minute)
	return p.secret, nil
}

func (p *ReadinessProof) HeaderValue() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secret
}

func (p *ReadinessProof) consume(r *http.Request, run PublishRunIdentity) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := r.Header.Values(localproxy.ReadinessProbeHeader)
	if p.secret == "" || time.Now().After(p.expires) || run != p.run || r.Method != http.MethodGet ||
		r.URL.EscapedPath() != p.path || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" || len(values) != 1 ||
		subtle.ConstantTimeCompare([]byte(values[0]), []byte(p.secret)) != 1 {
		return false
	}
	p.secret = ""
	return true
}
