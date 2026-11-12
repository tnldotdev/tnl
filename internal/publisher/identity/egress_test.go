package identity

import (
	"errors"
	"testing"

	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
)

type runtimeEndpointControl struct{ processidentity.Control }

func TestRemoteRuntimeRequiresCapabilityAndExactEndpoint(t *testing.T) {
	native, _ := privateScopeFixture(t)
	if _, err := native.RemoteRuntime(native.ControlURL()); !errors.Is(err, ErrScope) {
		t.Fatal("deployed owner inferred runtime capabilities", err)
	}
	native.Runtime = runtimeEndpointControl{}
	if _, err := native.RemoteRuntime("https://other.example"); !errors.Is(err, ErrScope) {
		t.Fatal("deployed owner accepted a different control endpoint", err)
	}
	if _, err := native.RemoteRuntime(native.ControlURL()); err != nil {
		t.Fatal("explicit runtime capability and endpoint rejected", err)
	}
}
