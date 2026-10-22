package tnldconfig

import (
	"errors"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/tcpport"
)

func TestServicePortInventoryDefaultsAndEmpty(t *testing.T) {
	configuration := Config{}
	inventory, err := configuration.ServicePortInventory()
	if err != nil || !slices.Equal(inventory.Ranges(), []tcpport.Range{{First: 20000, Last: 20015}}) || configuration.ServicePortRanges != nil {
		t.Fatal("omission must retain the default without mutation", inventory, err)
	}
	for _, values := range [][]string{{}, {""}, {"20000-20256"}, {"20000", "20000"}} {
		if _, err := (Config{ServicePortRanges: values}).ServicePortInventory(); !errors.Is(err, tcpport.ErrInventory) {
			t.Fatalf("accepted %v: %v", values, err)
		}
	}
	if _, err := (Config{ServicePortRanges: []string{"20000-20255"}}).ServicePortInventory(); err != nil {
		t.Fatal(err)
	}
}
