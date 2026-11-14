package connector

import (
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPreparedConnectorIgnoresIngressReservationButKeepsTrust(t *testing.T) {
	service := controlv1.Service{Id: "svc_0123456789ABCDEFGHIJKL", Protocol: controlv1.Postgres, TrustRevision: 4,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example.test"}}
	prepared := &servicePreparation{service: service}
	for _, port := range []int{0, 25443, 0, 35443} {
		service.Endpoint = &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: port, Public: port != 0}
		if !prepared.matches(service) {
			t.Fatal("ingress reservation retired a prepared connector", port)
		}
	}
	service.TrustRevision++
	if prepared.matches(service) {
		t.Fatal("target trust revision did not invalidate the connector")
	}
	service.TrustRevision--
	service.Endpoint = &controlv1.ServiceEndpoint{Hostname: "another.example.test"}
	if prepared.matches(service) {
		t.Fatal("TLS hostname change did not invalidate the connector")
	}
}
