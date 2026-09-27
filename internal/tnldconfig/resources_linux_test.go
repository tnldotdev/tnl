package tnldconfig

import "testing"

func TestCPUSetCount(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int
	}{
		{"0", 1}, {"0-3,6,8-9", 7}, {"", 0}, {"a", 0}, {"3-1", 0},
	} {
		if got := cpuSetCount(test.value); got != test.want {
			t.Errorf("cpuSetCount(%q) = %d; want %d", test.value, got, test.want)
		}
	}
}
