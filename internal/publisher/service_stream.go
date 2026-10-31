package publisher

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
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

var ErrEndpoint = errors.New("service TLS or visitor authorization failed")

type ServiceVisitorDecision struct {
	Allowed    bool
	ValidUntil time.Time
}

// ServiceStream terminates native client TLS at the publisher. the already
// selected service owns its certificate name; SNI cannot select another target.
// target trust is independent of the public WebPKI identity presented to clients.
type ServiceStream struct {
	Protocol     config.ProtocolName
	Public       bool
	Hostname     string
	HTTPRequests *ServiceHTTPRequestLimits
	Kubernetes   KubernetesLimits
	Authority    string
	Target       string
	TLS          *tls.Config
	TargetTLS    *tls.Config
	Visitor      ServiceVisitorAuthentication
}

func (s ServiceStream) Forward(ctx context.Context, visitor net.Conn) (result error) {
	var afterNativeEOF func()
	if reader, ok := visitor.(interface{ ContinueAfterTLSCloseNotify() }); ok {
		afterNativeEOF = reader.ContinueAfterTLSCloseNotify
	}
	var valid bool
	s.Visitor, valid = normalizeManagedVisitor(s.Visitor)
	protocol, _ := observability.ParseProtocol(string(s.Protocol))
	fields := observability.Fields{Component: "publisher", ServiceProtocol: protocol, AccessPath: "direct", Exposure: "private"}
	if s.Public {
		fields.Exposure = "public"
	}
	var native ServiceNativeAdmission
	if v, ok := s.Visitor.(NativeVisitor); ok {
		native = v.Admission
		fields.AccessPath = "connector"
	}
	if _, ok := s.Visitor.(PublicHTTPVisitor); ok {
		fields.Exposure = "public"
	}
	ctx = observability.WithFields(ctx, fields)
	ctx, endVisitor := observability.Start(ctx, "publisher.visitor")
	defer func() { endVisitor(result) }()
	ctx, admissionDone := observability.PublisherOperation(ctx, "visitor_admission")
	defer func() { admissionDone(result) }()
	canonical, nameErr := naming.CanonicalizeHostname(s.Hostname)
	transport := targettransport.Transport{Protocol: s.Protocol, TLS: s.TargetTLS}
	if transport.Validate() != nil || nameErr != nil || canonical != s.Hostname || s.Target == "" || s.TLS == nil || s.TLS.GetConfigForClient != nil || !valid {
		return ErrEndpoint
	}
	if _, ok := s.Visitor.(PublicHTTPVisitor); ok && s.Protocol != config.ProtocolHTTP {
		return ErrEndpoint
	}
	if native != nil {
		if err := nativeCheck(ctx, native); err != nil {
			return err
		}
		visitor = &nativeServiceConn{conn: visitor, ctx: ctx, admission: native}
	}
	// native HTTP handlers and upgraded copies are part of the stream lifetime,
	// not merely net/http's connection close notification.
	var handlerMu sync.Mutex
	var handlers sync.WaitGroup
	acceptHandlers := true
	life, cancelLife := context.WithCancel(ctx)
	if native != nil {
		ctx = life
	}
	defer cancelLife()
	setupUntil := time.Now().Add(10 * time.Second)
	if native != nil && native.SetupDeadline().Before(setupUntil) {
		setupUntil = native.SetupDeadline()
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
	// race with dialing or block in a native read that does not accept a context.
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
		canceled := setup.Err() != nil || native != nil && life.Err() != nil
		socketsMu.Unlock()
		if canceled {
			_ = conn.Close()
		}
	}
	if native != nil {
		defer func() {
			native.Stop()
			handlerMu.Lock()
			acceptHandlers = false
			handlerMu.Unlock()
			cancelLife()
			closeSockets()
			handlers.Wait()
		}()
	}
	enterNativeWork := func() (func(), bool) {
		if native == nil {
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
		if native == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			finish, ok := enterNativeWork()
			if !ok {
				return
			}
			defer finish()
			if nativeCheck(r.Context(), native) == nil {
				next.ServeHTTP(w, r)
			}
		})
	}
	dial := func(call context.Context) (net.Conn, error) {
		if native != nil {
			if err := nativeCheck(call, native); err != nil {
				return nil, err
			}
		}
		conn, err := observability.DialTarget(call, "tcp", s.Target)
		if err != nil {
			return nil, err
		}
		trackTarget(conn)
		if native != nil {
			if err := nativeCheck(call, native); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = &nativeServiceConn{conn: conn, ctx: ctx, admission: native}
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
		if native != nil {
			if err := native.FinishSetup(); err != nil {
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
	frontTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != s.Hostname && !(s.Protocol == config.ProtocolMySQL && hello.ServerName == "") {
			return nil, ErrEndpoint
		}
		return nil, nil
	}
	secured := tls.Server(visitor, frontTLS)
	var client net.Conn = secured
	if native != nil {
		client = &nativeServiceConn{conn: secured, ctx: ctx, admission: native, afterEOF: afterNativeEOF}
	}
	tlsCtx, tlsDone := observability.PublisherOperation(setup, "visitor_tls")
	err = secured.HandshakeContext(tlsCtx)
	observability.PublisherTLS(tlsCtx, "visitor", secured.ConnectionState(), err)
	tlsDone(err)
	if err != nil {
		return err
	}
	if httpVisitor, ok := s.Visitor.(PublicHTTPVisitor); ok {
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
		return httpVisitor.Frontend.Forward(ctx, secured, ServiceHTTPTarget{Address: s.Target, Transport: transport})
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
		return s.forwardKubernetes(ctx, client, secured.ConnectionState(), ServiceHTTPTarget{Address: s.Target, Transport: transport, native: native, lifetime: ctx, track: trackTarget, enter: enterNativeWork}, decision, wrapHandler)
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
		target := ServiceHTTPTarget{Address: s.Target, Transport: transport, native: native, lifetime: ctx, track: trackTarget, enter: enterNativeWork}
		return httpstream.Serve(live, client, &url.URL{Scheme: scheme, Host: s.Target}, target.dial, func(next http.Handler) http.Handler {
			return wrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// connector admission is the credential, but every HTTP request still
				// rechecks current policy before any target bytes on the shared socket.
				check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				check, authDone := observability.PublisherOperation(check, "visitor_authorization")
				decision, err := s.Visitor.authorize(check, secured.ConnectionState())
				observability.PublisherAuthorization(check, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
				authDone(managedAuthorizationError(decision, err))
				cancel()
				if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
					serviceHTTPDenied(w, serviceHTTPDecisionStatus(err))
					return
				}
				release, ok := s.HTTPRequests.admit(w, r)
				if !ok {
					return
				}
				defer release()
				next.ServeHTTP(w, r)
			}))
		})
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
	if native != nil {
		backend = &nativeServiceConn{conn: backend, ctx: ctx, admission: native}
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

func (s ServiceStream) guardVisitor(ctx context.Context, client net.Conn, target net.Conn, state tls.ConnectionState, decision ServiceVisitorDecision) {
	defer client.Close()
	if target != nil {
		defer target.Close()
	}
	for {
		remaining := time.Until(decision.ValidUntil)
		if remaining <= 0 {
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
		if !decision.ValidUntil.After(time.Now()) {
			return
		}
		check, cancel := context.WithTimeout(ctx, min(5*time.Second, time.Until(decision.ValidUntil)))
		check, authDone := observability.PublisherOperation(check, "visitor_authorization")
		next, err := s.Visitor.authorize(check, state)
		observability.PublisherAuthorization(check, next.Allowed && next.ValidUntil.After(time.Now()), next.Allowed && next.ValidUntil.After(time.Now()), err)
		authDone(managedAuthorizationError(next, err))
		cancel()
		if err == nil {
			if !next.Allowed || !next.ValidUntil.After(time.Now()) {
				return
			}
			decision = next
		}
	}
}

func managedAuthorizationError(decision ServiceVisitorDecision, err error) error {
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
