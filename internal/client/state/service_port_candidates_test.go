package state

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestServicePortCandidatePreferenceOrder(t *testing.T) {
	patterns := []int{11111, 22222, 33333, 44444, 55555, 12321, 23432, 34543, 45654, 56765, 10001, 20002, 30003, 40004, 50005, 60006}
	for _, test := range []struct {
		protocol string
		first    []int
	}{
		{"http", []int{8443, 9443, 10443, 11443, 12443, 14443, 18443, 19443}},
		{"postgres", []int{15432, 25432, 35432, 45432, 55432, 5433, 5434, 5435, 5436, 5437, 5438, 5439}},
		{"mysql", []int{13306, 23306, 33306, 43306, 53306, 63306, 3307, 3308, 3309, 3310, 3311, 3312, 3313}},
		{"kubernetes", []int{16443, 26443, 36443, 46443, 56443, 6444, 6445, 6446, 6447, 6448, 6449}},
		{"tcp", nil},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			prefix := append(slices.Clone(test.first), patterns...)
			for _, offset := range []uint32{0, 4444, 10002, 13333, 24444, 35555, 39999} {
				var seed [32]byte
				binary.BigEndian.PutUint32(seed[:4], offset)
				ports := privatePortCandidates(test.protocol, seed)
				if len(ports) != 128 || !slices.Equal(ports[:len(prefix)], prefix) {
					t.Fatal("protocol alternatives, neighbors, or patterned ports lost their order", ports)
				}
				seen := make(map[int]bool, len(ports))
				for _, port := range ports {
					if seen[port] || port < 1024 || port > 65535 || port == 3306 || port == 5432 || port == 6443 {
						t.Fatal("duplicate, privileged, invalid, or canonical candidate", port)
					}
					seen[port] = true
				}
				for _, port := range ports[len(prefix):] {
					if port < 20000 || port >= 60000 {
						t.Fatal("fallback escaped its high-port range", port)
					}
				}
				if !slices.Equal(ports, privatePortCandidates(test.protocol, seed)) {
					t.Fatal("candidate ordering is not deterministic")
				}
			}
		})
	}
	for _, protocol := range []string{"", "https", "ssh", "HTTP", "unknown"} {
		if ports := privatePortCandidates(protocol, [32]byte{}); ports != nil {
			t.Fatal("unknown protocol selected a port", protocol)
		}
	}
}

func TestServicePortCandidateFallbackIsSeededAndDeduplicated(t *testing.T) {
	var seed [32]byte
	// the first hashed candidate is already in the patterned tier.
	binary.BigEndian.PutUint32(seed[:4], 24444)
	first := privatePortCandidates("postgres", seed)
	second := privatePortCandidates("postgres", [32]byte{})
	const friendlyCount = 12 + 16
	if first[friendlyCount] != 52363 || second[friendlyCount] != 20000 {
		t.Fatal("fallback lost its service seed or repeated a friendly candidate", first[friendlyCount], second[friendlyCount])
	}
	if !slices.Equal(first[:friendlyCount], second[:friendlyCount]) {
		t.Fatal("service seed changed the ordered friendly preferences")
	}
}
