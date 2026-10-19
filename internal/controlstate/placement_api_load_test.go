package controlstate_test

import (
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
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
