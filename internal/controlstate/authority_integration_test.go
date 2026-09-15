package controlstate

import "testing"

func TestIntegrationAuthorityMutations(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "authority_mutations")
	testAuthorityMutations(t, database)
}

func TestIntegrationDNSAuthorities(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "dns_authorities")
	testDNSAuthorities(t, database)
}
