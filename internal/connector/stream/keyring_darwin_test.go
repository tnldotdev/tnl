package stream

import (
	"os"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func TestMain(m *testing.M) {
	clientstate.UseMemoryKeychainForTesting()
	os.Exit(m.Run())
}
