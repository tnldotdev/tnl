package tcpport

import (
	"errors"
	"slices"
	"strconv"
	"testing"
)

func TestPortInventory(t *testing.T) {
	got, err := ParseInventory([]string{"65535", "20000-20100", "1024"})
	if err != nil || !slices.Equal(got.Ranges(), []Range{{1024, 1024}, {20000, 20100}, {65535, 65535}}) {
		t.Fatal(got, err)
	}
	for _, values := range [][]string{nil, {""}, {"443"}, {"65536"}, {"20001-20000"}, {"20000-20010", "20010"}, {"20000", "20000"}, {"020000"}, {"20000-"}, {"20000-20001-20002"}, {" 20000"}} {
		if _, err = ParseInventory(values); !errors.Is(err, ErrInventory) {
			t.Errorf("accepted %q: %v", values, err)
		}
	}
}

func TestInventoryLimitsAndCopyIsolation(t *testing.T) {
	ranges := make([]Range, 256)
	declarations := make([]string, len(ranges))
	for i := range ranges {
		port := 20000 + i
		ranges[i] = Range{port, port}
		declarations[i] = strconv.Itoa(port)
	}
	if _, err := ParseInventory(declarations[:128]); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInventory(declarations[:129]); !errors.Is(err, ErrInventory) {
		t.Fatal("textual limit", err)
	}
	inventory, err := NewInventory(ranges)
	if err != nil || len(inventory.Ports()) != 256 {
		t.Fatal("in-memory singletons", inventory, err)
	}
	if _, err := NewInventory(append(ranges, Range{30000, 30000})); !errors.Is(err, ErrInventory) {
		t.Fatal("257 singletons", err)
	}
	if _, err := ParseInventory([]string{"20000-20255"}); err != nil {
		t.Fatal("256 ports", err)
	}
	if _, err := ParseInventory([]string{"20000-20256"}); !errors.Is(err, ErrInventory) {
		t.Fatal("257 ports", err)
	}
	for _, invalid := range [][]Range{nil, {}, {{1023, 1024}}, {{65535, 65536}}, {{20001, 20000}}, {{20000, 20001}, {20001, 20002}}, {{20000, 20256}}} {
		if _, err := NewInventory(invalid); !errors.Is(err, ErrInventory) {
			t.Errorf("accepted %v: %v", invalid, err)
		}
	}
	ranges[0] = Range{30000, 30000}
	copy := inventory
	copy.Ranges()[0] = Range{30000, 30000}
	copy.Ports()[0] = 30000
	if !inventory.Contains(20000) || inventory.Contains(30000) || inventory.Contains(19999) || !copy.Contains(20255) || copy.Contains(20256) {
		t.Fatal("inventory changed through input or copy-outs")
	}
	var empty Inventory
	if empty.Contains(20000) || len(empty.Ports()) != 0 || len(empty.Ranges()) != 0 {
		t.Fatal("zero inventory has ports")
	}
}
