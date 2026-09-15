package controlstate

import "testing"

func TestIntegrationRelayCertificateOrderWork(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "relay_certificate_order_work")
	testRelayCertificateOrderWork(t, database)
}
