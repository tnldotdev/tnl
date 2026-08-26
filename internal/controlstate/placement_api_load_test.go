package controlstate_test

import (
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestLoadPlacementWithHostnameLookup(t *testing.T) {
	controlstate.RunPlacementLoad(t, func(database *controlstate.Database, loginToken credentials.LoginToken) http.Handler {
		return controlapi.NewHandler(controlapi.Config{LoginToken: string(loginToken)}, database, database, nil)
	})
}
