package connector

import (
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestConnectListenRejectsNonLoopbackAndInvalidPorts(t *testing.T) {
	for _, value := range []string{"0.0.0.0:5432", "192.0.2.1:5432", "localhost:5432", "[::]:5432", "127.0.0.1:0", "65536", "bad"} {
		if _, err := connectListen(value); err == nil {
			t.Fatalf("unsafe listener %q accepted", value)
		}
	}
	for input, want := range map[string]string{"15432": "127.0.0.1:15432", "[::1]:13306": "[::1]:13306"} {
		if got, err := connectListen(input); err != nil || got != want {
			t.Fatalf("listener %q = %q, %v", input, got, err)
		}
	}
}

func TestConnectSelectionRequiresExactIdentityInventoryAndTeam(t *testing.T) {
	services := []controlv1.PrivateService{{Id: "first", Name: "orders", TeamId: "one"}, {Id: "second", Name: "orders", TeamId: "two"}}
	if _, err := SelectService(services, "orders", ""); err == nil {
		t.Fatal("ambiguous name accepted")
	}
	for _, selection := range [][2]string{{"orders", "two"}, {"second", ""}} {
		got, err := SelectService(services, selection[0], selection[1])
		if err != nil || got.Id != "second" {
			t.Fatalf("selection = %+v, %v", got, err)
		}
	}
	if _, err := SelectService(services, "second", "one"); err == nil {
		t.Fatal("exact ID bypassed team selection")
	}
	if _, err := SelectService(services, "absent", ""); err == nil {
		t.Fatal("unavailable service accepted")
	}
}
