package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

var ErrEndpoint = errors.New("service TLS or visitor authorization failed")

// VisitorHostnameRefusal identifies this visitor's failed TLS hostname check,
// not a configuration, required worker, or physical cleanup failure.
type VisitorHostnameRefusal struct{}

func (*VisitorHostnameRefusal) Error() string { return ErrEndpoint.Error() }
func (*VisitorHostnameRefusal) Unwrap() error { return ErrEndpoint }

type Decision struct {
	Allowed    bool
	ValidUntil time.Time
}

// Stream terminates visitor TLS at the publisher. the already
// selected service owns its certificate name; SNI cannot select another target.
// target trust is independent of the public WebPKI identity presented to clients.
type Stream struct {
	// ObserveHTTPSetup reports TLS (true), then completed HTTP setup (false).
	ObserveHTTPSetup       func(tlsDone bool)
	Protocol               config.ProtocolName
	Public                 bool
	Hostname               string
	RunHostname            string
	HTTPRequests           RequestLimits
	HTTPProxy              *proxy.Proxy
	HTTPDrain              httpstream.Drain
	RequestBodyIdleTimeout time.Duration
	Kubernetes             KubernetesLimits
	Authority              string
	Target                 string
	Handler                http.Handler
	Mounts                 []proxy.Mount
	ResolveHTTPTarget      func(*http.Request) (address, identity string, err error)
	InspectionMode         inspection.Mode
	ObserveSummary         inspection.Observer
	AdmitRequest           func(*http.Request) error
	PrepareRequest         func(*http.Request) (func(context.Context) error, error)
	HTTPResponseHooks      httpstream.ResponseHooks
	ConnectorHTTP          ConnectorHTTPFrontend
	TLS                    *tls.Config
	TargetTLS              *tls.Config
	Visitor                Authentication
	// FinishVisitor joins delivery after entered work, socket cleanup, and
	// callbacks have joined, before connector admission is stopped.
	FinishVisitor func(error) error
}

func (s Stream) Forward(ctx context.Context, visitor net.Conn) (result error) {
	var valid bool
	s.Visitor, valid = normalizeManagedVisitor(s.Visitor)
	protocol, _ := observability.ParseProtocol(string(s.Protocol))
	fields := observability.Fields{Component: "publisher", ServiceProtocol: protocol, AccessPath: "public_endpoint", Exposure: "private"}
	if s.Public {
		fields.Exposure = "public"
	}
	var connector ConnectorAdmission
	var httpProof ConnectorHTTPProof
	if v, ok := s.Visitor.(ConnectorVisitor); ok {
		connector = v.Admission
		httpProof = v.HTTPProof
		fields.AccessPath = "connector"
	}
	if _, ok := s.Visitor.(HTTPVisitor); ok {
		fields.Exposure = "public"
	}
	ctx = observability.WithFields(ctx, fields)
	ctx, endVisitor := observability.Start(ctx, "publisher.visitor")
	defer func() { endVisitor(result) }()
	ctx, admissionDone := observability.PublisherOperation(ctx, "visitor_admission")
	defer func() { admissionDone(result) }()
	canonical, nameErr := naming.CanonicalizeHostname(s.Hostname)
	transport := targettransport.Transport{Protocol: s.Protocol, TLS: s.TargetTLS}
	inline := s.Protocol == config.ProtocolHTTP && s.Handler != nil && s.Target == "" && s.TargetTLS == nil
	if HandlerOnly && !inline {
		return ErrEndpoint
	}
	if transport.Validate() != nil || nameErr != nil || canonical != s.Hostname || s.Target == "" && !inline || s.Handler != nil && !inline || s.TLS == nil || s.TLS.GetConfigForClient != nil || !valid ||
		(len(s.Mounts) != 0 || s.ResolveHTTPTarget != nil) && (s.Protocol != config.ProtocolHTTP || inline) {
		return ErrEndpoint
	}
	if _, ok := s.Visitor.(HTTPVisitor); ok && s.Protocol != config.ProtocolHTTP {
		return ErrEndpoint
	}
	var cleanupMu sync.Mutex
	var cleanupErr error
	recordClose := func(err error) {
		if err != nil && !failure.Only(err, net.ErrClosed) {
			cleanupMu.Lock()
			cleanupErr = errors.Join(cleanupErr, err)
			cleanupMu.Unlock()
		}
	}
	visitor = &streamSocket{Conn: visitor, closed: recordClose, lifetime: ctx}
	defer func() {
		if connector != nil {
			defer connector.Stop()
		}
		_ = visitor.Close()
		cleanupMu.Lock()
		result = errors.Join(result, cleanupErr)
		cleanupMu.Unlock()
		if s.FinishVisitor != nil {
			result = errors.Join(result, s.FinishVisitor(result))
		}
	}()
	if connector != nil {
		if err := connectorCheck(ctx, connector); err != nil {
			return err
		}
		visitor = &connectorServiceConn{conn: visitor, ctx: ctx, admission: connector}
	}
	// target dials can outlive their requesting HTTP handlers, which httpstream
	// joins separately. keep entered target work until physical cleanup finishes.
	var targetWorkMu sync.Mutex
	var targetWork sync.WaitGroup
	acceptTargetWork := true
	life, cancelLife := context.WithCancel(ctx)
	ctx = life
	defer cancelLife()
	setupUntil := time.Now().Add(10 * time.Second)
	if connector != nil && connector.SetupDeadline().Before(setupUntil) {
		setupUntil = connector.SetupDeadline()
	}
	setup, cancelSetup := context.WithDeadline(ctx, setupUntil)
	defer cancelSetup()
	promoted := false
	deadline, _ := setup.Deadline()
	if err := visitor.SetDeadline(deadline); err != nil {
		return err
	}
	// keep raw target sockets separately from TLS wrappers. cancellation may
	// race with dialing or block in a connector read that does not accept a context.
	var socketsMu sync.Mutex
	targetSockets := make(map[*streamSocket]struct{})
	socketsClosed := false
	closeSockets := func() {
		socketsMu.Lock()
		socketsClosed = true
		targets := make([]*streamSocket, 0, len(targetSockets))
		for target := range targetSockets {
			targets = append(targets, target)
		}
		socketsMu.Unlock()
		_ = visitor.Close()
		for _, target := range targets {
			_ = target.Close()
		}
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(setup, func() { defer close(callbackDone); closeSockets() })
	setupCallbackStopped := false
	stopSetupCallback := func() bool {
		if !setupCallbackStopped {
			setupCallbackStopped = stop()
		}
		return setupCallbackStopped
	}
	defer func() {
		if !stopSetupCallback() {
			<-callbackDone
		}
	}()
	trackTarget := func(conn net.Conn) net.Conn {
		tracked := &streamSocket{Conn: conn, lifetime: ctx}
		tracked.closed = func(err error) {
			recordClose(err)
			socketsMu.Lock()
			delete(targetSockets, tracked)
			socketsMu.Unlock()
		}
		socketsMu.Lock()
		targetSockets[tracked] = struct{}{}
		canceled := socketsClosed || !promoted && setup.Err() != nil || life.Err() != nil
		socketsMu.Unlock()
		if canceled {
			_ = tracked.Close()
		}
		return tracked
	}
	defer func() {
		targetWorkMu.Lock()
		acceptTargetWork = false
		targetWorkMu.Unlock()
		cancelLife()
		closeSockets()
		targetWork.Wait()
	}()
	defer func() {
		// preserve setup failures before owned cleanup cancels its context.
		// cancellation must not replace an independent authorization failure.
		if !promoted && setup.Err() != nil {
			result = errors.Join(result, context.Cause(setup))
		}
	}()
	enterTargetWork := func() (func(), bool) {
		targetWorkMu.Lock()
		defer targetWorkMu.Unlock()
		if !acceptTargetWork {
			return nil, false
		}
		targetWork.Add(1)
		return targetWork.Done, true
	}
	wrapHandler := func(next http.Handler) http.Handler {
		if connector == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if connectorCheck(r.Context(), connector) == nil {
				next.ServeHTTP(w, r)
			}
		})
	}
	dial := func(call context.Context) (net.Conn, error) {
		if connector != nil {
			if err := connectorCheck(call, connector); err != nil {
				return nil, err
			}
		}
		conn, err := observability.DialTarget(call, "tcp", s.Target)
		if err != nil {
			return nil, targetDialResult(call, err)
		}
		conn = trackTarget(conn)
		if connector != nil {
			if err := connectorCheck(call, connector); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = &connectorServiceConn{conn: conn, ctx: ctx, admission: connector}
		}
		return conn, nil
	}
	promote := func() error {
		stopped := stopSetupCallback()
		if setup.Err() != nil {
			return context.Cause(setup)
		}
		if !stopped {
			return context.Canceled
		}
		if connector != nil {
			if err := connector.FinishSetup(); err != nil {
				return err
			}
		}
		promoted = true
		return nil
	}
	var backend net.Conn
	var greeting *managedMySQLHandshake
	var err error
	defer func() {
		if backend != nil {
			_ = backend.Close()
		}
	}()
	if !HandlerOnly {
		switch s.Protocol {
		case config.ProtocolPostgres:
			_, negotiationDone := observability.PublisherOperation(setup, "visitor_negotiation")
			err := acceptPostgresTLS(visitor)
			negotiationDone(err)
			if err != nil {
				return err
			}
		case config.ProtocolMySQL:
			backend, err = dial(setup)
			if err != nil {
				return err
			}
			if err = backend.SetDeadline(deadline); err != nil {
				return err
			}
			_, negotiationDone := observability.PublisherOperation(setup, "visitor_negotiation")
			greeting, err = acceptMySQLTLS(visitor, backend, s.TargetTLS != nil)
			negotiationDone(err)
			if err != nil {
				return err
			}
		}
	}
	frontTLS := s.TLS.Clone()
	frontTLS.MinVersion = max(frontTLS.MinVersion, tls.VersionTLS12)
	frontTLS.ClientAuth = s.Visitor.clientAuth()
	_, publicHTTP := s.Visitor.(HTTPVisitor)
	if publicHTTP {
		frontTLS.ClientCAs = httpVisitorIssuerNames
	}
	frontTLS.NextProtos = nil
	if s.Protocol == config.ProtocolHTTP {
		frontTLS.MinVersion = max(frontTLS.MinVersion, tls.VersionTLS13)
		frontTLS.NextProtos = []string{"h2", "http/1.1"}
	}
	frontTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		hostname, err := naming.CanonicalizeHostname(hello.ServerName)
		alias := publicHTTP && s.Protocol == config.ProtocolHTTP && s.Public && s.RunHostname != "" && hostname == s.RunHostname
		if (err != nil || hostname != s.Hostname && !alias) && !(s.Protocol == config.ProtocolMySQL && hello.ServerName == "") {
			return nil, &VisitorHostnameRefusal{}
		}
		return nil, nil
	}
	tlsCtx, tlsDone := observability.PublisherOperation(setup, "visitor_tls")
	secured, err := negotiateVisitorTLS(tlsCtx, visitor, frontTLS)
	observability.PublisherTLS(tlsCtx, "visitor", secured.ConnectionState(), err)
	tlsDone(err)
	if err != nil {
		return err
	}
	var client net.Conn = secured
	if connector != nil {
		client = &connectorServiceConn{conn: secured, ctx: ctx, admission: connector}
	}
	if httpVisitor, ok := s.Visitor.(HTTPVisitor); ok {
		if s.ObserveHTTPSetup != nil {
			s.ObserveHTTPSetup(true)
		}
		if s.Protocol != config.ProtocolHTTP {
			return ErrEndpoint
		}
		if err := promote(); err != nil {
			return err
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		admissionDone(nil)
		if s.ObserveHTTPSetup != nil {
			s.ObserveHTTPSetup(false)
		}
		// capture the input stop before owned cleanup cancels the lifetime.
		return errors.Join(httpVisitor.Frontend.Forward(ctx, secured, HTTPTarget{Address: s.Target, Handler: s.Handler, Transport: transport, Drain: s.HTTPDrain,
			RequestBodyIdleTimeout: s.RequestBodyIdleTimeout,
			Mounts:                 s.Mounts, ResolveTarget: s.ResolveHTTPTarget,
			Connections: targetConnections(s.HTTPRequests), proxy: s.HTTPProxy,
			lifetime: ctx, track: trackTarget, enter: enterTargetWork}), context.Cause(ctx))
	}
	authCtx, authDone := observability.PublisherOperation(setup, "visitor_authorization")
	decision, err := s.Visitor.authorize(authCtx, secured.ConnectionState())
	observability.PublisherAuthorization(authCtx, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
	authDone(managedAuthorizationError(decision, err))
	if err != nil {
		// the connector admission owns this result, including its exact stop
		// cause. adding a separate endpoint failure would misreport an abort.
		if connector != nil {
			return err
		}
		return errors.Join(ErrEndpoint, err)
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return managedAuthorizationError(decision, nil)
	}
	if !HandlerOnly && s.Protocol == config.ProtocolKubernetes {
		if err := promote(); err != nil {
			return err
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		admissionDone(nil)
		return s.forwardKubernetes(ctx, client, secured.ConnectionState(), HTTPTarget{Address: s.Target, Transport: transport, connector: connector, lifetime: ctx, track: trackTarget, enter: enterTargetWork}, decision, wrapHandler)
	}
	if s.Protocol == config.ProtocolHTTP {
		admissionDone(nil)
		if err := promote(); err != nil {
			return err
		}
		if err = visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		live, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); s.guardVisitor(live, client, nil, secured.ConnectionState(), decision) }()
		defer func() { cancel(); <-done }()
		target := HTTPTarget{Address: s.Target, Mounts: s.Mounts, ResolveTarget: s.ResolveHTTPTarget, Transport: transport,
			RequestBodyIdleTimeout: s.RequestBodyIdleTimeout,
			Connections:            targetConnections(s.HTTPRequests), connector: connector, lifetime: ctx, track: trackTarget, enter: enterTargetWork}
		wrap := func(next http.Handler) http.Handler {
			return wrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var authorization ConnectorHTTPAuthorization
				if httpProof != nil {
					var err error
					authorization, err = httpProof.HTTPAuthorization(r.Context())
					if err != nil {
						DenyHTTP(w, r, HTTPDecisionStatus(err))
						return
					}
					// only the checked admission snapshot supplies the source.
					r.RemoteAddr = netip.AddrPortFrom(authorization.Source.Unmap(), 1).String()
				}
				w, r, finishInspection := inspection.BeginHTTP(w, r, s.InspectionMode, s.ObserveSummary)
				defer finishInspection()
				// a connector request is not an owner readiness proof.
				r.Header.Del(httpstream.ReadinessProbeHeader)
				// connector admission is the credential, but every HTTP request still
				// rechecks current policy before any target bytes on the shared socket.
				check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				check, authDone := observability.PublisherOperation(check, "visitor_authorization")
				decision, err := s.Visitor.authorize(check, secured.ConnectionState())
				observability.PublisherAuthorization(check, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
				authDone(managedAuthorizationError(decision, err))
				cancel()
				if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
					DenyHTTP(w, r, HTTPDecisionStatus(err))
					return
				}
				if strings.HasPrefix(r.URL.Path, "/__tnl/") {
					if httpProof == nil || s.ConnectorHTTP == nil {
						DenyHTTP(w, r, http.StatusForbidden)
						return
					}
					// reserved work spends no application budget and never opens
					// a target. the service frontend owns browser/feedback dispatch.
					if !s.ConnectorHTTP.ConnectorReserved(w, r, authorization) {
						http.NotFound(w, r)
					}
					return
				}
				if s.AdmitRequest != nil {
					if err := s.AdmitRequest(r); err != nil {
						DenyHTTP(w, r, http.StatusServiceUnavailable)
						return
					}
				}
				var commit func(context.Context) error
				if s.PrepareRequest != nil {
					var err error
					commit, err = s.PrepareRequest(r)
					if err != nil {
						DenyHTTP(w, r, http.StatusServiceUnavailable)
						return
					}
				}
				reservation, ok := reserveRequest(s.HTTPRequests, w, r)
				if !ok {
					return
				}
				defer reservation.Finish()
				if commit != nil {
					if err := commit(r.Context()); err != nil {
						reservation.Refund()
						DenyHTTP(w, r, http.StatusServiceUnavailable)
						return
					}
				}
				if s.ConnectorHTTP != nil && httpProof != nil {
					r = s.ConnectorHTTP.ConnectorApplication(w, r)
				}
				next.ServeHTTP(w, httpstream.WithVisitorHost(r, s.Hostname))
			}))
		}
		// the underlying visitor and target sockets remain connector-gated.
		// preserve *tls.Conn here so net/http can serve the negotiated HTTP/2;
		// every handler also rechecks admission before application work.
		target.Handler, target.Drain = s.Handler, s.HTTPDrain
		return errors.Join(target.Serve(live, secured, s.Hostname, wrap, s.HTTPResponseHooks), context.Cause(ctx))
	}
	if HandlerOnly {
		return ErrEndpoint
	}
	if backend == nil {
		backend, err = dial(setup)
		if err != nil {
			return err
		}
		if err = backend.SetDeadline(deadline); err != nil {
			return err
		}
	}
	if s.Protocol == config.ProtocolMySQL {
		authCtx, authDone := observability.PublisherOperation(setup, "native_auth")
		backend, err = connectMySQLTarget(authCtx, client, backend, greeting, s.TargetTLS)
		authDone(err)
	} else {
		backend, err = transport.Secure(setup, backend)
	}
	if err != nil {
		return err
	}
	if connector != nil && s.TargetTLS != nil {
		backend = &connectorServiceConn{conn: backend, ctx: ctx, admission: connector}
	}
	if s.Protocol == config.ProtocolPostgres {
		_, authDone := observability.PublisherOperation(setup, "native_auth")
		err = forwardPostgresAuthentication(client, backend)
		authDone(err)
		if err != nil {
			return err
		}
	}
	if err := promote(); err != nil {
		return err
	}
	if err = visitor.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err = backend.SetDeadline(time.Time{}); err != nil {
		return err
	}
	live, cancel := context.WithCancel(ctx)
	admissionDone(nil)
	defer cancel()
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		s.guardVisitor(live, client, backend, secured.ConnectionState(), decision)
	}()
	defer func() { cancel(); <-guardDone }()
	observed, streamDone := observability.PublisherStream(live, backend)
	_, err = streamcopy.Copy(client, observed)
	err = errors.Join(err, context.Cause(ctx))
	streamDone(err)
	return err
}

func (s Stream) guardVisitor(ctx context.Context, client net.Conn, target net.Conn, state tls.ConnectionState, decision Decision) {
	defer client.Close()
	if target != nil {
		defer target.Close()
	}
	authorize := func(check context.Context) (Decision, error) {
		check, authDone := observability.PublisherOperation(check, "visitor_authorization")
		next, err := s.Visitor.authorize(check, state)
		observability.PublisherAuthorization(check, next.Allowed && next.ValidUntil.After(time.Now()), next.Allowed && next.ValidUntil.After(time.Now()), err)
		authDone(managedAuthorizationError(next, err))
		return next, err
	}
	_, connector := s.Visitor.(ConnectorVisitor)
	var expiredObservation time.Time
	for {
		if connector {
			// admission owns renewable connector authority. a cached deadline may
			// have elapsed while that same admission received a current renewal.
			next, err := authorize(ctx)
			if err != nil || !next.Allowed {
				return
			}
			decision = next
		}
		remaining := time.Until(decision.ValidUntil)
		if remaining <= 0 {
			// renewal can overtake CheckUse after it releases the admission lock.
			// recheck an elapsed observation without granting authority; an
			// unchanged expired deadline or current denial still closes the stream.
			if connector && decision.ValidUntil.After(expiredObservation) {
				expiredObservation = decision.ValidUntil
				continue
			}
			return
		}
		delay := max(time.Millisecond, min(30*time.Second, remaining/2))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if connector {
			continue
		}
		if !decision.ValidUntil.After(time.Now()) {
			return
		}
		check, cancel := context.WithTimeout(ctx, min(5*time.Second, time.Until(decision.ValidUntil)))
		next, err := authorize(check)
		cancel()
		if err == nil {
			if !next.Allowed || !next.ValidUntil.After(time.Now()) {
				return
			}
			decision = next
		}
	}
}

func managedAuthorizationError(decision Decision, err error) error {
	if err != nil {
		return err
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return failure.Wrap("authorize service visitor", failure.ConnectAccessRequired, ErrEndpoint)
	}
	return nil
}

var managedPostgresSSL = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}
var managedPostgresGSS = [8]byte{0, 0, 0, 8, 4, 210, 22, 48}

func acceptPostgresTLS(client net.Conn) error {
	var request [8]byte
	if _, err := io.ReadFull(client, request[:]); err != nil {
		return err
	}
	if request == managedPostgresGSS {
		if _, err := client.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, err := io.ReadFull(client, request[:]); err != nil {
			return err
		}
	}
	if request != managedPostgresSSL {
		return ErrEndpoint
	}
	_, err := client.Write([]byte{'S'})
	return err
}
