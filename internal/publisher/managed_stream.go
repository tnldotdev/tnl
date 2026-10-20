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
	"github.com/tnldotdev/tnl/internal/httpstream"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/targettransport"
)

var ErrManagedTLS = errors.New("managed service TLS or visitor authorization failed")

type ManagedVisitorDecision struct {
	Allowed    bool
	ValidUntil time.Time
}

// ManagedStream terminates native client TLS at the publisher. the already
// selected service owns its certificate name; SNI cannot select another target.
// target trust is independent of the public WebPKI identity presented to clients.
type ManagedStream struct {
	Protocol     config.ProtocolName
	Public       bool
	Hostname     string
	HTTPRequests *ManagedHTTPRequestLimits
	Target       string
	TLS          *tls.Config
	TargetTLS    *tls.Config
	Visitor      ManagedVisitorAuthentication
}

func (s ManagedStream) Forward(ctx context.Context, visitor net.Conn) (result error) {
	fields := observability.Fields{Component: "publisher", ServiceProtocol: string(s.Protocol), AccessPath: "direct", Exposure: "private"}
	if s.Public {
		fields.Exposure = "public"
	}
	if _, ok := s.Visitor.(ConnectorVisitor); ok {
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
	if transport.Validate() != nil || nameErr != nil || canonical != s.Hostname || s.Target == "" || s.TLS == nil || s.TLS.GetConfigForClient != nil || s.Visitor == nil || !s.Visitor.valid() {
		return ErrManagedTLS
	}
	if _, ok := s.Visitor.(PublicHTTPVisitor); ok && s.Protocol != config.ProtocolHTTP {
		return ErrManagedTLS
	}
	setup, cancelSetup := context.WithTimeout(ctx, 10*time.Second)
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
	stop := context.AfterFunc(setup, func() {
		socketsMu.Lock()
		defer socketsMu.Unlock()
		_ = visitor.Close()
		if targetSocket != nil {
			_ = targetSocket.Close()
		}
	})
	defer stop()
	trackTarget := func(conn net.Conn) {
		socketsMu.Lock()
		defer socketsMu.Unlock()
		targetSocket = conn
		if setup.Err() != nil {
			_ = conn.Close()
		}
	}
	promote := func() error {
		stopped := stop()
		if setup.Err() != nil {
			return context.Cause(setup)
		}
		if !stopped {
			return context.Canceled
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
		backend, err = observability.DialTarget(setup, "tcp", s.Target)
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
			return nil, ErrManagedTLS
		}
		return nil, nil
	}
	secured := tls.Server(visitor, frontTLS)
	tlsCtx, tlsDone := observability.PublisherOperation(setup, "visitor_tls")
	err = secured.HandshakeContext(tlsCtx)
	observability.PublisherTLS(tlsCtx, "visitor", secured.ConnectionState(), err)
	tlsDone(err)
	if err != nil {
		return err
	}
	if httpVisitor, ok := s.Visitor.(PublicHTTPVisitor); ok {
		if s.Protocol != config.ProtocolHTTP {
			return ErrManagedTLS
		}
		if err := promote(); err != nil {
			return err
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		admissionDone(nil)
		return httpVisitor.Frontend.Forward(ctx, secured, ManagedHTTPTarget{Address: s.Target, Transport: transport})
	}
	authCtx, authDone := observability.PublisherOperation(setup, "visitor_authorization")
	decision, err := s.Visitor.authorize(authCtx, secured.ConnectionState())
	observability.PublisherAuthorization(authCtx, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
	authDone(managedAuthorizationError(decision, err))
	if err != nil {
		return errors.Join(ErrManagedTLS, err)
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return managedAuthorizationError(decision, nil)
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
		go func() { defer close(done); s.guardVisitor(live, secured, nil, decision) }()
		defer func() { cancel(); <-done }()
		scheme := "http"
		if s.TargetTLS != nil {
			scheme = "https"
		}
		return httpstream.Serve(live, secured, &url.URL{Scheme: scheme, Host: s.Target}, func(ctx context.Context) (net.Conn, error) {
			setup, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := observability.DialTarget(setup, "tcp", s.Target)
			if err != nil {
				return nil, err
			}
			backend, err := transport.Secure(setup, conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return backend, nil
		}, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// connector admission is the credential, but every HTTP request still
				// rechecks current policy before any target bytes on the shared socket.
				check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				check, authDone := observability.PublisherOperation(check, "visitor_authorization")
				decision, err := s.Visitor.authorize(check, secured.ConnectionState())
				observability.PublisherAuthorization(check, decision.Allowed && decision.ValidUntil.After(time.Now()), decision.Allowed && decision.ValidUntil.After(time.Now()), err)
				authDone(managedAuthorizationError(decision, err))
				cancel()
				if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
					managedHTTPDenied(w, managedHTTPDecisionStatus(err))
					return
				}
				release, ok := s.HTTPRequests.admit(w, r)
				if !ok {
					return
				}
				defer release()
				next.ServeHTTP(w, r)
			})
		})
	}
	if backend == nil {
		backend, err = observability.DialTarget(setup, "tcp", s.Target)
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
		backend, err = connectMySQLTarget(authCtx, secured, backend, greeting, s.TargetTLS)
		authDone(err)
	} else {
		backend, err = transport.Secure(setup, backend)
	}
	if err != nil {
		return err
	}
	if s.Protocol == config.ProtocolPostgres {
		_, authDone := observability.PublisherOperation(setup, "native_auth")
		err = forwardPostgresAuthentication(secured, backend)
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
		s.guardVisitor(live, secured, backend, decision)
	}()
	defer func() { cancel(); <-guardDone }()
	observed, streamDone := observability.PublisherStream(live, backend)
	_, err = streamcopy.Copy(secured, observed)
	streamDone(err)
	return err
}

func (s ManagedStream) guardVisitor(ctx context.Context, client *tls.Conn, target net.Conn, decision ManagedVisitorDecision) {
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
		next, err := s.Visitor.authorize(check, client.ConnectionState())
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

func managedAuthorizationError(decision ManagedVisitorDecision, err error) error {
	if err != nil {
		return err
	}
	if !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return failure.Wrap("authorize service visitor", failure.ConnectAccessRequired, ErrManagedTLS)
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
		return ErrManagedTLS
	}
	_, err := client.Write([]byte{'S'})
	return err
}
