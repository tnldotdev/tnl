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
	for _, values := range [][]string{{""}, {"443"}, {"65536"}, {"20001-20000"}, {"20000-20010", "20010"}, {"20000", "20000"}, {"020000"}, {"20000-"}, {"20000-20001-20002"}, {" 20000"}} {
		if _, err = ParseInventory(values); !errors.Is(err, ErrInventory) {
			t.Errorf("accepted %q: %v", values, err)
		}
	}
}

func TestFullInventory(t *testing.T) {
	inventory, err := ParseInventory([]string{"1024-65535"})
	ports := inventory.Ports()
	if err != nil || len(ports) != 64512 || ports[0] != 1024 || ports[len(ports)-1] != 65535 {
		t.Fatalf("full range: %d ports, %v", len(ports), err)
	}
	declarations := make([]string, len(ports))
	for i, port := range ports {
		declarations[len(ports)-1-i] = strconv.Itoa(port)
	}
	inventory, err = ParseInventory(declarations)
	if err != nil || !slices.Equal(inventory.Ranges(), []Range{{1024, 65535}}) || !slices.Equal(inventory.Ports(), ports) || !inventory.Contains(65535) || inventory.Contains(1023) {
		t.Fatalf("full singleton inventory: %v", err)
	}
}

func TestInventoryMergesAdjacencyWithoutFillingGaps(t *testing.T) {
	inventory, err := NewInventory([]Range{{20003, 20004}, {65535, 65535}, {20000, 20000}, {1024, 1024}, {20001, 20001}})
	want := []Range{{1024, 1024}, {20000, 20001}, {20003, 20004}, {65535, 65535}}
	if err != nil || !slices.Equal(inventory.Ranges(), want) {
		t.Fatal(inventory, err)
	}
	for _, port := range []int{1024, 20000, 20001, 20003, 20004, 65535} {
		if !inventory.Contains(port) {
			t.Fatal("lost declared port", port)
		}
	}
	for _, port := range []int{443, 1023, 1025, 19999, 20002, 20005, 65536} {
		if inventory.Contains(port) {
			t.Fatal("admitted undeclared port", port)
		}
	}
	again, err := NewInventory(inventory.Ranges())
	if err != nil || !slices.Equal(again.Ranges(), want) {
		t.Fatal("canonicalization changed inventory", again, err)
	}
}

func TestInventoryCopyIsolation(t *testing.T) {
	ranges := make([]Range, 257)
	for i := range ranges {
		port := 20000 + i
		ranges[i] = Range{port, port}
	}
	inventory, err := NewInventory(ranges)
	if err != nil || len(inventory.Ports()) != 257 {
		t.Fatal("in-memory singletons", inventory, err)
	}
	for _, invalid := range [][]Range{{{1023, 1024}}, {{65535, 65536}}, {{20001, 20000}}, {{20000, 20001}, {20001, 20002}}} {
		if _, err := NewInventory(invalid); !errors.Is(err, ErrInventory) {
			t.Errorf("accepted %v: %v", invalid, err)
		}
	}
	ranges[0] = Range{30000, 30000}
	copy := inventory
	copy.Ranges()[0] = Range{30000, 30000}
	copy.Ports()[0] = 30000
	if !inventory.Contains(20000) || inventory.Contains(30000) || inventory.Contains(19999) || !copy.Contains(20256) || copy.Contains(20257) {
		t.Fatal("inventory changed through input or copy-outs")
	}
	var empty Inventory
	if empty.Contains(20000) || len(empty.Ports()) != 0 || len(empty.Ranges()) != 0 {
		t.Fatal("zero inventory has ports")
	}
}

func TestEmptyInventoryHasNoAllocatedPorts(t *testing.T) {
	for _, values := range [][]string{nil, {}} {
		inventory, err := ParseInventory(values)
		if err != nil || len(inventory.Ranges()) != 0 || len(inventory.Ports()) != 0 || inventory.Contains(443) || inventory.Contains(20000) {
			t.Fatal("empty textual inventory gained ports", inventory, err)
		}
	}
	for _, ranges := range [][]Range{nil, {}} {
		inventory, err := NewInventory(ranges)
		if err != nil || len(inventory.Ranges()) != 0 || len(inventory.Ports()) != 0 || inventory.Contains(443) || inventory.Contains(20000) {
			t.Fatal("empty in-memory inventory gained ports", inventory, err)
		}
	}
}
