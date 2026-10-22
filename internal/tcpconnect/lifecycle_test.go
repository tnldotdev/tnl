package tcpconnect

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestMetadataReloadClassificationAndSafeFormatting(t *testing.T) {
	reload := &MetadataReloadError{PrivateServiceID: "private-context-must-not-be-rendered", ApprovedRevision: 1, SelectedRevision: 2}
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
