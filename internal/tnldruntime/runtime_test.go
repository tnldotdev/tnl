package tnldruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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

	// A component can finish after Serve has selected its result. No later
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
