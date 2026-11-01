package stream

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestConnectorAssignmentConflictKeepsHealthyOtherPath(t *testing.T) {
	f := newConnectorFixture(t, "tls-tcp")
	healthy := f.local(t)
	if _, err := healthy.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(healthy, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	f.activationConflict[0].Store(true)
	f.mu.Lock()
	lost := append([]muxsession.Session{}, f.sessions[0]...)
	siblings := len(f.sessions[1])
	f.mu.Unlock()
	for _, path := range lost {
		_ = path.Close()
	}
	if _, err := healthy.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(healthy, make([]byte, 5)); err != nil {
		t.Fatal("healthy stream stopped", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sessions[0]) != 1 || len(f.sessions[1]) != siblings || f.opened.Load() != 1 || f.rejected[0].Load() != 0 {
		t.Fatal("healthy stream was restarted or replayed")
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
