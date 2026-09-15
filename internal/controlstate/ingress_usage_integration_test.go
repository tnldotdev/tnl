package controlstate

import "testing"

func TestIntegrationIngressUsage(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "ingress_usage")
	testIngressUsage(t, database)
}
