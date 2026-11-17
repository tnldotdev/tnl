package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the admitted-session double tests only this adapter's request transport.
// stream/session tests retain the real authority, WSS and inner QUIC owner.
type httpSession struct {
	ctx         context.Context
	certificate tls.Certificate
	opened      atomic.Int32
}

// only the admitted peer stream is replaced; requests use Connection.Fetch and
// native Go TLS and HTTP, including net/http's actual retry behavior.
type replaySession struct {
	ctx         context.Context
	certificate tls.Certificate
	opened      atomic.Int32
	effects     atomic.Int32
}

func (s *replaySession) Context() context.Context { return s.ctx }
func (*replaySession) Close() error               { return nil }
func (s *replaySession) Forward(ctx context.Context, local net.Conn) error {
	s.opened.Add(1)
	defer local.Close()
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = local.Close() })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	secured := tls.Server(local, &tls.Config{Certificates: []tls.Certificate{s.certificate}})
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	reader := bufio.NewReader(secured)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return nil
		}
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			return err
		}
		if err := request.Body.Close(); err != nil {
			return err
		}
		if request.URL.Path == "/effect" && s.effects.Add(1) == 1 {
			// the application received the complete request and performed its
			// work; disconnect before sending any response byte.
			return nil
		}
		response := &http.Response{
			StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{}, ContentLength: 2,
			Body: io.NopCloser(strings.NewReader("ok")),
		}
		if err := response.Write(secured); err != nil {
			return err
		}
	}
}

func TestSessionFetchDoesNotReplayReceivedGET(t *testing.T) {
	certificate, roots := sessionCertificate(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	engine := &replaySession{ctx: ctx, certificate: certificate}
	connection := newConnection(ctx, cancel, engine, controlv1.ServiceSummary{
		Id: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: "http", TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 443},
	}, &tls.Config{RootCAs: roots})
	defer connection.Close()
	fetch := func(path string) error {
		request, err := http.NewRequestWithContext(ctx, "GET", "https://service.example.test"+path, nil)
		if err != nil {
			return err
		}
		response, err := connection.Fetch(request)
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		return errors.Join(readErr, response.Body.Close())
	}
	// fully consume one response to exercise the reused-connection retry rule.
	if err := fetch("/warmup"); err != nil {
		t.Fatal(err)
	}
	err := fetch("/effect")
	t.Logf("effects=%d admitted_streams=%d fetch_error=%v", engine.effects.Load(), engine.opened.Load(), err)
	if !errors.Is(err, io.EOF) || engine.effects.Load() != 1 || engine.opened.Load() != 2 {
		t.Fatalf("received request was replayed or its disconnect hidden: effects=%d streams=%d error=%v", engine.effects.Load(), engine.opened.Load(), err)
	}
}

func (s *httpSession) Context() context.Context { return s.ctx }
func (s *httpSession) Close() error             { return nil }
func (s *httpSession) Forward(ctx context.Context, local net.Conn) error {
	s.opened.Add(1)
	defer local.Close()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(stopped); _ = local.Close() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	secure := tls.Server(local, &tls.Config{Certificates: []tls.Certificate{s.certificate}})
	if err := secure.HandshakeContext(ctx); err != nil {
		return err
	}
	reader := bufio.NewReader(secure)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(request.Body)
		if err != nil {
			return err
		}
		_ = request.Body.Close()
		response := &http.Response{
			StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1,
			Header:        http.Header{"X-Request-Path": []string{request.URL.Path}},
			Body:          io.NopCloser(strings.NewReader("response:" + string(data))),
			ContentLength: int64(len("response:") + len(data)),
		}
		if err := response.Write(secure); err != nil {
			return err
		}
	}
}

func TestSessionFetchUsesOwnedVerifiedTransportAndRetainedBinding(t *testing.T) {
	certificate, roots := sessionCertificate(t)
	ctx, cancel := context.WithCancel(t.Context())
	engine := &httpSession{ctx: ctx, certificate: certificate}
	connection := newConnection(ctx, cancel, engine, controlv1.ServiceSummary{
		Id: "svc_aaaaaaaaaaaaaaaaaaaaaa", Protocol: "http", TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 443},
	}, &tls.Config{RootCAs: roots})
	defer connection.Close()
	for range 2 {
		request, err := http.NewRequestWithContext(t.Context(), "POST", "https://service.example.test/test", strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := connection.Fetch(request)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if string(data) != "response:payload" || response.Header.Get("X-Request-Path") != "/test" {
			t.Fatal("request did not traverse owned Go transport")
		}
	}
	if engine.opened.Load() != 2 {
		t.Fatal("requests did not use separate streams on the retained binding", engine.opened.Load())
	}
	opened := engine.opened.Load()
	for _, address := range []string{"http://service.example.test/", "https://another.example.test/", "https://user:password@service.example.test/"} {
		request, err := http.NewRequestWithContext(t.Context(), "GET", address, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Fetch(request); err == nil {
			t.Fatal("accepted another service origin", address)
		}
	}
	if engine.opened.Load() != opened {
		t.Fatal("invalid Fetch origin opened a stream")
	}
}
