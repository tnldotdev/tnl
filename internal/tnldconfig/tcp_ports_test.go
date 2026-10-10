package tnldconfig

import (
	"reflect"
	"testing"
)

func TestConfiguredTCPPorts(t *testing.T) {
	config := Config{IngressIPv4Addresses: []string{"192.0.2.10"}, TCPPorts: "3306,5432,15432-15434"}
	ports, err := config.ConfiguredTCPPorts()
	if err != nil || !reflect.DeepEqual(ports, []int32{3306, 5432, 15432, 15433, 15434}) {
		t.Fatalf("configured ports = %v, %v", ports, err)
	}
	for _, value := range []string{"1", "443", "65536", "15432-15430", "5432,5432", "5432,5431-5433", " 5432", "5432,"} {
		config.TCPPorts = value
		if _, err := config.ConfiguredTCPPorts(); err == nil {
			t.Errorf("accepted invalid TCP port inventory %q", value)
		}
	}
	config.TCPPorts = "5432"
	config.IngressIPv4Addresses = nil
	if _, err := config.ConfiguredTCPPorts(); err == nil {
		t.Fatal("enabled public TCP without an ingress address")
	}
}
