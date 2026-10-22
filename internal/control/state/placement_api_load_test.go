package controlstate_test

import (
	"net/http"
	"testing"

	controlapi "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestLoadPlacementWithHostnameLookup(t *testing.T) {
	controlstate.RunPlacementLoad(t, func(database *controlstate.Database, metrics *observability.Metrics) http.Handler {
		handler, err := controlapi.NewHandler(controlapi.Config{Metrics: metrics}, database, database, nil)
		if err != nil {
			t.Fatal(err)
		}
		return handler
	})
}
