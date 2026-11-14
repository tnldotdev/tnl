package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

var ErrEndpoint = errors.New("service TLS or visitor authorization failed")

type Decision struct {
	Allowed    bool
	ValidUntil time.Time
}

// Stream terminates visitor TLS at the publisher. the already
// selected service owns its certificate name; SNI cannot select another target.
// target trust is independent of the public WebPKI identity presented to clients.
type Stream struct {
	Protocol       config.ProtocolName
	Public         bool
	Hostname       string
	HTTPRequests   RequestLimits
	Kubernetes     KubernetesLimits
	Authority      string
	Target         string
	Handler        http.Handler
	InspectionMode inspection.Mode
	ObserveSummary inspection.Observer
	AdmitRequest   func(*http.Request) error
	TLS            *tls.Config
	TargetTLS      *tls.Config
	Visitor        Authentication
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
	if v, ok := s.Visitor.(ConnectorVisitor); ok {
		connector = v.Admission
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
	if transport.Validate() != nil || nameErr != nil || canonical != s.Hostname || s.Target == "" && !inline || s.Handler != nil && !inline || s.TLS == nil || s.TLS.GetConfigForClient != nil || !valid {
		return ErrEndpoint
	}
	if _, ok := s.Visitor.(HTTPVisitor); ok && s.Protocol != config.ProtocolHTTP {
		return ErrEndpoint
	}
	if connector != nil {
		if err := connectorCheck(ctx, connector); err != nil {
			return err
		}
		visitor = &connectorServiceConn{conn: visitor, ctx: ctx, admission: connector}
	}
	// connector HTTP handlers and upgraded copies are part of the stream lifetime,
	// not merely net/http's connection close notification.
	var handlerMu sync.Mutex
	var handlers sync.WaitGroup
	acceptHandlers := true
	life, cancelLife := context.WithCancel(ctx)
	if connector != nil {
		ctx = life
	}
	defer cancelLife()
	setupUntil := time.Now().Add(10 * time.Second)
	if connector != nil && connector.SetupDeadline().Before(setupUntil) {
		setupUntil = connector.SetupDeadline()
	}
	setup, cancelSetup := context.WithDeadline(ctx, setupUntil)
	defer cancelSetup()
	promoted := false
	defer func() {
		if !promoted && setup.Err() != nil {
			result = context.Cause(setup)
		}
	}()
	deadline, _ := setup.Deadline()
	if err := visitor.SetDeadline(deadline); err != nil {
		return err
	}
	// keep the raw target socket separately from TLS wrappers. cancellation may
	// race with dialing or block in a connector read that does not accept a context.
	var socketsMu sync.Mutex
	var targetSocket net.Conn
	closeSockets := func() {
		socketsMu.Lock()
		target := targetSocket
		socketsMu.Unlock()
		_ = visitor.Close()
		if target != nil {
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
	trackTarget := func(conn net.Conn) {
		socketsMu.Lock()
		targetSocket = conn
		canceled := setup.Err() != nil || connector != nil && life.Err() != nil
		socketsMu.Unlock()
		if canceled {
			_ = conn.Close()
		}
	}
	if connector != nil {
		defer func() {
			connector.Stop()
			handlerMu.Lock()
			acceptHandlers = false
			handlerMu.Unlock()
			cancelLife()
			closeSockets()
			handlers.Wait()
		}()
	}
	enterConnectorWork := func() (func(), bool) {
		if connector == nil {
			return func() {}, true
		}
		handlerMu.Lock()
		defer handlerMu.Unlock()
		if !acceptHandlers {
			return nil, false
		}
		handlers.Add(1)
		return handlers.Done, true
	}
	wrapHandler := func(next http.Handler) http.Handler {
		if connector == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			finish, ok := enterConnectorWork()
			if !ok {
				return
			}
			defer finish()
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
			return nil, err
		}
		trackTarget(conn)
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
		trackTarget(backend)
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
	frontTLS := s.TLS.Clone()
	frontTLS.MinVersion = max(frontTLS.MinVersion, tls.VersionTLS12)
	frontTLS.ClientAuth = s.Visitor.clientAuth()
	frontTLS.NextProtos = nil
	if s.Protocol == config.ProtocolHTTP {
		frontTLS.NextProtos = []string{"h2", "http/1.1"}
	}
	frontTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != s.Hostname && !(s.Protocol == config.ProtocolMySQL && hello.ServerName == "") {
			return nil, ErrEndpoint
		}
		return nil, nil
	}
	secured := tls.Server(visitor, frontTLS)
	var client net.Conn = secured
	if connector != nil {
		client = &connectorServiceConn{conn: secured, ctx: ctx, admission: connector}
	}
	tlsCtx, tlsDone := observability.PublisherOperation(setup, "visitor_tls")
	err = secured.HandshakeContext(tlsCtx)
	observability.PublisherTLS(tlsCtx, "visitor", secured.ConnectionState(), err)
	tlsDone(err)
	if err != nil {
		return err
	}
	if httpVisitor, ok := s.Visitor.(HTTPVisitor); ok {
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
		return httpVisitor.Frontend.Forward(ctx, secured, HTTPTarget{Address: s.Target, Handler: s.Handler, Transport: transport})
	}
	authCtx, authDone := observability.PublisherOperation(setup, "visitor_authorization")
	decision, err := s.Visitor.authorize(authCtx, secured.ConnectionState())
	observability.PublisherAuthorization(authCtx, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
	authDone(managedAuthorizationError(decision, err))
	if err != nil {
		return errors.Join(ErrEndpoint, err)
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return managedAuthorizationError(decision, nil)
	}
	if s.Protocol == config.ProtocolKubernetes {
		if err := promote(); err != nil {
			return err
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		admissionDone(nil)
		return s.forwardKubernetes(ctx, client, secured.ConnectionState(), HTTPTarget{Address: s.Target, Transport: transport, connector: connector, lifetime: ctx, track: trackTarget, enter: enterConnectorWork}, decision, wrapHandler)
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
		scheme := "http"
		if s.TargetTLS != nil {
			scheme = "https"
		}
		target := HTTPTarget{Address: s.Target, Transport: transport, connector: connector, lifetime: ctx, track: trackTarget, enter: enterConnectorWork}
		wrap := func(next http.Handler) http.Handler {
			return wrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w, r, finishInspection := inspection.BeginHTTP(w, r, s.InspectionMode, s.ObserveSummary)
				defer finishInspection()
				// a connector request is not an owner readiness proof.
				r.Header.Del(publisherproxy.ReadinessProbeHeader)
				// connector admission is the credential, but every HTTP request still
				// rechecks current policy before any target bytes on the shared socket.
				check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				check, authDone := observability.PublisherOperation(check, "visitor_authorization")
				decision, err := s.Visitor.authorize(check, secured.ConnectionState())
				observability.PublisherAuthorization(check, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
				authDone(managedAuthorizationError(decision, err))
				cancel()
				if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
					DenyHTTP(w, HTTPDecisionStatus(err))
					return
				}
				if s.AdmitRequest != nil {
					if err := s.AdmitRequest(r); err != nil {
						DenyHTTP(w, http.StatusServiceUnavailable)
						return
					}
				}
				release, ok := admitRequest(s.HTTPRequests, w, r)
				if !ok {
					return
				}
				defer release()
				next.ServeHTTP(w, r)
			}))
		}
		// the underlying visitor and target sockets remain connector-gated.
		// preserve *tls.Conn here so net/http can serve the negotiated HTTP/2;
		// every handler also rechecks admission before application work.
		if inline {
			return httpstream.ServeHandler(live, secured, wrap(s.Handler))
		}
		return httpstream.Serve(live, secured, &url.URL{Scheme: scheme, Host: s.Target}, target.Dial, wrap)
	}
	if backend == nil {
		backend, err = dial(setup)
		if err != nil {
			return err
		}
		trackTarget(backend)
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
	if connector != nil {
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
