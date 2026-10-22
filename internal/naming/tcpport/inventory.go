package tcpport

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

var ErrInventory = errors.New("service port inventory must contain at most 256 non-overlapping ports from 1024 to 65535")

const MaxInventoryPorts = 256
const MaxInventoryDeclarations = 128

// Range is an inclusive interval in one ingress pool's configured inventory.
type Range struct {
	First, Last int
}

func (r Range) Valid() bool { return r.First >= 1024 && r.First <= r.Last && r.Last <= 65535 }

// Inventory is a validated, immutable set of service ports. its zero value has
// no ports, for callers that do not serve managed TCP services.
type Inventory struct {
	ranges []Range
}

func (i Inventory) Contains(port int) bool {
	for _, r := range i.ranges {
		if port >= r.First && port <= r.Last {
			return true
		}
	}
	return false
}

func ParseInventory(values []string) (Inventory, error) {
	if len(values) == 0 || len(values) > MaxInventoryDeclarations {
		return Inventory{}, ErrInventory
	}
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

// NewInventory copies and validates in-memory ranges. the declaration limit
// belongs to the textual format; in-memory inventories may have 256 singletons.
func NewInventory(ranges []Range) (Inventory, error) {
	if len(ranges) == 0 || len(ranges) > MaxInventoryPorts {
		return Inventory{}, ErrInventory
	}
	ranges = slices.Clone(ranges)
	count := 0
	for _, r := range ranges {
		if !r.Valid() {
			return Inventory{}, ErrInventory
		}
		count += r.Last - r.First + 1
		if count > MaxInventoryPorts {
			return Inventory{}, ErrInventory
		}
	}
	slices.SortFunc(ranges, func(a, b Range) int { return a.First - b.First })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].First <= ranges[i-1].Last {
			return Inventory{}, ErrInventory
		}
	}
	return Inventory{ranges: ranges}, nil
}

// Ranges returns a copy in ascending port order.
func (i Inventory) Ranges() []Range { return slices.Clone(i.ranges) }

// Ports returns a copy in ascending port order.
func (i Inventory) Ports() []int {
	ports := make([]int, 0)
	for _, interval := range i.ranges {
		for port := interval.First; port <= interval.Last; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
