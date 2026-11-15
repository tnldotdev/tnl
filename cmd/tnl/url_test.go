package main

import (
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServicePublicAddressesUseOnlyTheirAllocatedEndpoint(t *testing.T) {
	for _, test := range []struct {
		protocol controlv1.ServiceProtocol
		endpoint *controlv1.ServiceEndpoint
		want     string
	}{
		{controlv1.ServiceProtocolHTTP, &controlv1.ServiceEndpoint{Hostname: "app.example.test", Port: 443, Public: true}, "https://app.example.test"},
		{controlv1.Postgres, &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 15432, Public: true}, "db.example.test:15432"},
		{controlv1.Postgres, &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 0}, ""},
		{controlv1.ServiceProtocolHTTP, &controlv1.ServiceEndpoint{Hostname: "app.example.test", Port: 443}, ""},
		{controlv1.ServiceProtocolHTTP, nil, ""},
	} {
		address, err := servicePublicAddress(test.protocol, test.endpoint)
		if (err != nil) != (test.want == "") || address != test.want {
			t.Fatalf("protocol=%s endpoint=%+v address=%q err=%v", test.protocol, test.endpoint, address, err)
		}
	}
}
