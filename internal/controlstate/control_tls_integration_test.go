package controlstate

import "testing"

func TestIntegrationControlTLSState(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "control_tls")
	testControlTLSState(t, database)
}
