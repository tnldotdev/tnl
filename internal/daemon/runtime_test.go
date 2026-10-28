package daemon

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRoute53CredentialReadiness(t *testing.T) {
	if err := (&daemon{}).checkRoute53Credentials(t.Context()); err != nil {
		t.Fatalf("control without Route 53 needs no credentials: %v", err)
	}
	failure := errors.New("STS unavailable")
	d := &daemon{route53Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		if failure != nil {
			return aws.Credentials{}, failure
		}
		return aws.Credentials{AccessKeyID: "temporary"}, nil
	})}
	if err := d.checkRoute53Credentials(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("unavailable Route 53 credentials = %v", err)
	}
	failure = nil
	if err := d.checkRoute53Credentials(t.Context()); err != nil {
		t.Fatalf("recovered Route 53 credentials = %v", err)
	}
}

func TestDaemonSupervisesAndJoinsComponents(t *testing.T) {
	d := &daemon{componentDone: make(chan error, 1)}
	failure := errors.New("worker failed")
	d.start("first worker", func() error { return failure })
	if err := <-d.componentDone; !errors.Is(err, failure) || err.Error() != "first worker: worker failed" {
		t.Fatalf("first component error = %v", err)
	}

	// a component can finish after Serve has selected its result. no later
	// completion may block shutdown, regardless of the number of workers.
	release := make(chan struct{})
	d.background(func() { <-release })
	for range 64 {
		d.start("later worker", func() error { return nil })
	}
	joined := make(chan struct{})
	go func() { d.components.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("background drain was not joined")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("component shutdown blocked on a result")
	}
}

func TestDaemonComponentFailureKeepsClassificationCauseAndSafeReport(t *testing.T) {
	for _, specific := range []bool{false, true} {
		t.Run(map[bool]string{false: "unclassified", true: "specific"}[specific], func(t *testing.T) {
			cause := &pgconn.PgError{Code: "40001", Message: "private-test-secret"}
			var original error = cause
			want, retry := failure.ServerComponentFailed, failure.NoRetry
			if specific {
				want, retry = failure.DatabaseUnavailable, failure.RetryLater
				original = failure.Wrap("renew database authority", want, cause)
			}
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(previous)
			d := &daemon{ctx: t.Context(), componentDone: make(chan error, 1)}
			calls := 0
			d.start("run ingress control", func() error { calls++; return original })
			err := <-d.componentDone
			d.components.Wait()
			reportComponentFailure(t.Context(), err)
			reason, definition, ok := failure.Describe(err)
			if !ok || reason != want || definition.Class != failure.Unavailable || definition.Retry != retry {
				t.Fatal("component exit lost its classification or retry policy", reason, definition)
			}
			typed, ok := failure.Of(err)
			if !ok || typed.Operation() != "run ingress control" || errors.Unwrap(err) != original || !errors.Is(err, cause) || calls != 1 {
				t.Fatal("component exit lost its cause, operation, or no-restart boundary", err, calls)
			}
			for _, safe := range []string{output.String(), failure.SafeMessage(err, failure.ServerStartupFailed)} {
				if strings.Contains(safe, "private-test-secret") {
					t.Fatal("component reporting exposed a provider cause")
				}
			}
			if !strings.Contains(output.String(), "run ingress control reason="+string(want)) || !strings.Contains(output.String(), "sqlstate=40001") {
				t.Fatal("component report omitted its operation, reason, or approved SQLSTATE", output.String())
			}
		})
	}
}

func TestDaemonComponentCancellationDoesNotReportFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	d := &daemon{ctx: ctx, componentDone: make(chan error, 1)}
	d.start("stop ingress control", func() error { return context.Canceled })
	err := <-d.componentDone
	d.components.Wait()
	reportComponentFailure(ctx, err)
	if !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatal("canceled component lost its cause or emitted an operational failure", err, output.String())
	}
}

func TestConnectionListenerTransfersOwnership(t *testing.T) {
	listener := newConnectionListener(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	enqueued := make(chan bool, 1)
	go func() { enqueued <- listener.Enqueue(server) }()
	accepted, err := listener.Accept()
	if err != nil || accepted != server || !<-enqueued {
		t.Fatalf("accepted connection = %v, %v", accepted, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after close = %v", err)
	}
	if listener.Enqueue(client) {
		t.Fatal("closed listener accepted a connection")
	}
}

func TestControlHTTPServerBoundsRequestAndResponseIO(t *testing.T) {
	server := controlHTTPServer(http.NotFoundHandler(), nil)
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 30*time.Second ||
		server.WriteTimeout != 3*time.Minute || server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("HTTP server limits = %#v", server)
	}
}
