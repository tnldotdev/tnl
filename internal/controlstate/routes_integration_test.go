package controlstate

import "testing"

func TestIntegrationRouteManagement(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "route_management")
	testRouteManagement(t, database)
}

func TestIntegrationDNSRouteWork(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "dns_route_work")
	testDNSRouteWork(t, database)
}

func TestIntegrationHostedPolicyRevocation(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "hosted_policy_revocation")
	testHostedPolicyRevocation(t, database)
}
