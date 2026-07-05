package controlstate

import "testing"

func TestIntegrationRouteSessionCreationAndReadiness(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "route_session")
	testRouteSessionCreation(t, database)
}
