//go:build darwin || linux

package connector

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestForegroundClientStopsDescendantsThatIgnoreTerminate(t *testing.T) {
	err := withClientReady(t, `(trap '' TERM; echo ready; exec sleep 60) & wait`, func(context.Context) error {
		return errors.New("connector stopped")
	})
	var exit *ClientExit
	if err == nil || err.Error() != "connector stopped" || errors.As(err, &exit) {
		t.Fatalf("connector error = %v", err)
	}
}

func TestForegroundClientPreservesNonzeroStatusOnCancellation(t *testing.T) {
	err := withClientReady(t, `trap 'exit 23' TERM; echo ready; while :; do :; done`, func(ctx context.Context) error {
		return context.Canceled
	})
	var exit *ClientExit
	if !errors.As(err, &exit) || exit.Code != 23 || !errors.Is(err, context.Canceled) {
		t.Fatalf("want client exit 23 joined with connector cancellation, got %v", err)
	}
}

func withClientReady(t *testing.T, script string, finish func(context.Context) error) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := r.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(r)
	err = foregroundClient(t.Context(), "", []string{"sh", "-c", script}, nil, w, io.Discard, func(ctx context.Context, ready func(Profile) error) error {
		if err := ready(Profile{}); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Errorf("waiting for client: %q, %v", line, err)
		}
		return finish(ctx)
	})
	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	// the child inherits the real file; EOF proves that none of its processes
	// kept it open after the connector returned.
	if _, readErr := reader.ReadByte(); readErr != io.EOF {
		t.Fatalf("client still owns its output after cancellation: %v", readErr)
	}
	return err
}
