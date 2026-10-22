package daemon

import (
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func saveRuntimeOIDCSession(t *testing.T, state *clientstate.Database, origin, databaseURL, domain string) {
	t.Helper()
	d, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	session, err := controltest.Session(t.Context(), d, domain, time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := controltest.SaveSession(t.Context(), state, origin, session); err != nil {
		t.Fatal(err)
	}
}
