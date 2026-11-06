package connector

import (
	"errors"
	"testing"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

func TestConnectionSDKPreparationFailureRetainsOwnerReference(t *testing.T) {
	f := newSDKFixture(t, true)
	peer, err := f.prepare(t.Context(), "other", "db")
	if err != nil {
		t.Fatal(err)
	}
	f.prepareError = connectorruntime.ErrUnavailable
	_, err = f.prepare(t.Context(), "first", "db")
	var selected interface{ SDKOwnerHandle() string }
	if !errors.Is(err, connectorruntime.ErrUnavailable) || !errors.As(err, &selected) || selected.SDKOwnerHandle() == "" {
		t.Fatal("initial service failure lost its cause or owner cleanup reference", err)
	}
	file := selected.SDKOwnerHandle()
	if file == peer.Owner.ConnectionHandle || f.owners[file].closed {
		t.Fatal("preparation failure stopped or substituted its reusable owner")
	}
	if err := f.operations.stop(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	if !f.owners[file].closed || f.owners[peer.Owner.ConnectionHandle].closed || f.stopped != 1 {
		t.Fatal("failure cleanup did not join only the selected owner")
	}
	f.prepareError = nil
	if _, err := f.prepare(t.Context(), "other", "db"); err != nil {
		t.Fatal("failure cleanup stopped the peer", err)
	}
}
