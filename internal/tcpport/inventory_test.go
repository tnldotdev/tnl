package tcpport

import (
	"errors"
	"slices"
	"testing"
)

func TestPortInventory(t *testing.T) {
	got, err := ParseInventory([]string{"65535", "20000-20100", "1024"})
	if err != nil || !slices.Equal(got, []Range{{1024, 1024}, {20000, 20100}, {65535, 65535}}) {
		t.Fatal(got, err)
	}
	for _, values := range [][]string{nil, {""}, {"443"}, {"65536"}, {"20001-20000"}, {"20000-20010", "20010"}, {"20000", "20000"}, {"020000"}, {"20000-"}, {"20000-20001-20002"}, {" 20000"}} {
		if _, err = ParseInventory(values); !errors.Is(err, ErrInventory) {
			t.Errorf("accepted %q: %v", values, err)
		}
	}
}
