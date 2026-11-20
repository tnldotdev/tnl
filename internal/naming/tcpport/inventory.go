package tcpport

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

var ErrInventory = errors.New("service port inventory must contain non-overlapping ports from 1024 to 65535")

const (
	FirstServicePort = 1024
	LastServicePort  = 65535
)

// Range is an inclusive interval in one ingress pool's configured inventory.
type Range struct {
	First, Last int
}

func (r Range) Valid() bool {
	return r.First >= FirstServicePort && r.First <= r.Last && r.Last <= LastServicePort
}

// Inventory is a validated, immutable set of service ports. its zero value has
// no ports, for callers that do not serve managed TCP services.
type Inventory struct {
	ranges []Range
}

func (i Inventory) Contains(port int) bool {
	_, found := slices.BinarySearchFunc(i.ranges, port, func(r Range, port int) int {
		if r.Last < port {
			return -1
		}
		if r.First > port {
			return 1
		}
		return 0
	})
	return found
}

func ParseInventory(values []string) (Inventory, error) {
	ranges := make([]Range, 0, len(values))
	for _, value := range values {
		first, last, found := strings.Cut(value, "-")
		if !found {
			last = first
		}
		start, firstErr := strconv.Atoi(first)
		end, lastErr := strconv.Atoi(last)
		r := Range{First: start, Last: end}
		if firstErr != nil || lastErr != nil || !r.Valid() || strconv.Itoa(start) != first || strconv.Itoa(end) != last {
			return Inventory{}, ErrInventory
		}
		ranges = append(ranges, r)
	}
	return NewInventory(ranges)
}

// NewInventory copies, validates, sorts, and merges adjacent ranges. empty inventories serve
// shared HTTPS without allocated non-HTTP ports.
func NewInventory(ranges []Range) (Inventory, error) {
	ranges = slices.Clone(ranges)
	for _, r := range ranges {
		if !r.Valid() {
			return Inventory{}, ErrInventory
		}
	}
	slices.SortFunc(ranges, func(a, b Range) int { return a.First - b.First })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].First <= ranges[i-1].Last {
			return Inventory{}, ErrInventory
		}
	}
	merged := ranges[:0]
	for _, r := range ranges {
		if len(merged) > 0 && merged[len(merged)-1].Last+1 == r.First {
			merged[len(merged)-1].Last = r.Last
		} else {
			merged = append(merged, r)
		}
	}
	return Inventory{ranges: merged}, nil
}

// Ranges returns a copy in ascending port order.
func (i Inventory) Ranges() []Range { return slices.Clone(i.ranges) }

// Ports returns a copy in ascending port order.
func (i Inventory) Ports() []int {
	count := 0
	for _, interval := range i.ranges {
		count += interval.Last - interval.First + 1
	}
	ports := make([]int, 0, count)
	for _, interval := range i.ranges {
		for port := interval.First; port <= interval.Last; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
