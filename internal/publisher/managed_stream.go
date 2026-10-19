package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
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
	Hostname     string
	HTTPRequests *ManagedHTTPRequestLimits
	Target       string
	TLS          *tls.Config
	TargetTLS    *tls.Config
	Visitor      ManagedVisitorAuthentication
}

func (s ManagedStream) Forward(ctx context.Context, visitor net.Conn) (result error) {
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
	deadline, _ := setup.Deadline()
	if err := visitor.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(setup, func() { _ = visitor.Close() })
	defer stop()
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
		if err := acceptPostgresTLS(visitor); err != nil {
			return err
		}
	case config.ProtocolMySQL:
		backend, err = observability.DialTarget(setup, "tcp", s.Target)
		if err != nil {
			return err
		}
		if err = backend.SetDeadline(deadline); err != nil {
			return err
		}
		greeting, err = acceptMySQLTLS(visitor, backend, s.TargetTLS != nil)
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
	tlsDone(err)
	if err != nil {
		return err
	}
	if httpVisitor, ok := s.Visitor.(PublicHTTPVisitor); ok {
		if s.Protocol != config.ProtocolHTTP {
			return ErrManagedTLS
		}
		if !stop() && setup.Err() != nil {
			return context.Cause(setup)
		}
		if err := visitor.SetDeadline(time.Time{}); err != nil {
			return err
		}
		admissionDone(nil)
		return httpVisitor.Frontend.Forward(ctx, secured, ManagedHTTPTarget{Address: s.Target, Transport: transport})
	}
	decision, err := s.Visitor.authorize(setup, secured.ConnectionState())
	observability.AuthorizationDecision(ctx, "managed_visitor", err == nil && decision.Allowed && decision.ValidUntil.After(time.Now()))
	if err != nil || !decision.Allowed || !decision.ValidUntil.After(time.Now()) {
		return errors.Join(ErrManagedTLS, err)
	}
	if s.Protocol == config.ProtocolHTTP {
		admissionDone(nil)
		if !stop() && setup.Err() != nil {
			return context.Cause(setup)
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
				decision, err := s.Visitor.authorize(check, secured.ConnectionState())
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
		if err = backend.SetDeadline(deadline); err != nil {
			return err
		}
	}
	if s.Protocol == config.ProtocolMySQL {
		backend, err = connectMySQLTarget(setup, secured, backend, greeting, s.TargetTLS)
	} else {
		backend, err = transport.Secure(setup, backend)
	}
	if err != nil {
		return err
	}
	if s.Protocol == config.ProtocolPostgres {
		if err = forwardPostgresAuthentication(secured, backend); err != nil {
			return err
		}
	}
	if !stop() && setup.Err() != nil {
		return context.Cause(setup)
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
	_, err = streamcopy.Copy(secured, backend)
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
		next, err := s.Visitor.authorize(check, client.ConnectionState())
		cancel()
		if err == nil {
			if !next.Allowed || !next.ValidUntil.After(time.Now()) {
				return
			}
			decision = next
		}
	}
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
