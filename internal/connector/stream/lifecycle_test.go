package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type assignmentConflictControl struct {
	*connectorFixture
	conflict atomic.Bool
	attempts atomic.Int32
	retried  chan struct{}
	once     sync.Once
}

func (c *assignmentConflictControl) ConnectorAssignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (Assignment, error) {
	if slot == 0 && c.conflict.Load() {
		if c.attempts.Add(1) >= 2 {
			c.once.Do(func() { close(c.retried) })
		}
		return Assignment{}, clientcontrol.ErrStatusConflict
	}
	return c.connectorFixture.ConnectorAssignment(ctx, service, subject, slot)
}

func TestConnectorAssignmentConflictKeepsHealthyOtherPath(t *testing.T) {
	var control *assignmentConflictControl
	f := newConfiguredConnectorFixture(t, "tls-tcp", "", func(f *connectorFixture, config *Config) {
		control = &assignmentConflictControl{connectorFixture: f, retried: make(chan struct{})}
		config.Control = control
	})
	healthy := f.local(t) // the first visitor uses slot one.
	if _, err := healthy.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(healthy, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	control.conflict.Store(true)
	f.mu.Lock()
	lost := append([]muxsession.Session{}, f.sessions[0]...)
	siblings := len(f.sessions[1])
	f.mu.Unlock()
	for _, path := range lost {
		_ = path.Close()
	}
	select {
	case <-control.retried:
	case <-f.finished:
		t.Fatal("recoverable assignment 409 canceled the healthy path", f.serveErr)
	case <-time.After(2 * time.Second):
		t.Fatal("assignment conflict was not retried")
	}
	if _, err := healthy.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(healthy, make([]byte, 5)); err != nil {
		t.Fatal("healthy stream stopped", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sessions[1]) != siblings || f.opened.Load() != 1 {
		t.Fatal("healthy stream was restarted or replayed")
	}
}

func TestAssignmentCleanupSharesCallerCancellation(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), "test-access")
	if err != nil {
		t.Fatal(err)
	}
	c := &controlAdapter{client: client, owned: map[string]bool{"cns_aaaaaaaaaaaaaaaaaaaaaa": true, "cns_bbbbbbbbbbbbbbbbbbbbbb": true}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.CloseContext(ctx) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("release did not reach HTTP", err)
	case <-time.After(time.Second):
		t.Fatal("release did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || len(c.owned) != 2 {
			t.Fatal("failed releases lost their ownership or cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("release cleanup replaced its caller's canceled budget")
	}
}

func TestMetadataReloadClassificationAndSafeFormatting(t *testing.T) {
	reload := &MetadataReloadError{ServiceID: "private-context-must-not-be-rendered", ApprovedRevision: 1, SelectedRevision: 2}
	wrapped := errors.Join(fmt.Errorf("connector stopped: %w", reload), io.ErrClosedPipe)
	if !IsMetadataReload(wrapped) || IsMetadataReload(io.ErrClosedPipe) || IsMetadataReload(nil) {
		t.Fatal("reload classification lost the lifecycle boundary")
	}
	var absent *MetadataReloadError
	if IsMetadataReload(absent) {
		t.Fatal("typed nil is not a reload signal")
	}
	var selected *MetadataReloadError
	if !errors.As(wrapped, &selected) || selected != reload {
		t.Fatal("reload metadata was not retained for its caller")
	}
	for _, value := range []any{reload, *reload} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if text := fmt.Sprintf(format, value); text != metadataReloadMessage {
				t.Fatalf("reload formatting included private context: %q", text)
			}
		}
	}
}
