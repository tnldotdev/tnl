package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestManagedInventoryRejectsInvalidBeforeDatabaseIO(t *testing.T) {
	database := new(Database)
	for _, ranges := range [][]tcpport.Range{nil, {}, {{First: 1023, Last: 1024}}, {{First: 20000, Last: 20256}}, {{First: 20000, Last: 20001}, {First: 20001, Last: 20002}}} {
		if err := database.ConfigureIngressServicePorts(t.Context(), "ingress-a", ranges); !errors.Is(err, tcpport.ErrInventory) {
			t.Fatal("invalid control inventory", ranges, err)
		}
	}
}
