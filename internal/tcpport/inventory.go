package tcpport

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

var ErrInventory = errors.New("service port inventory must contain at most 256 non-overlapping ports from 1024 to 65535")

// Range is an inclusive interval in one ingress pool's configured inventory.
type Range struct {
	First, Last int
}

func (r Range) Valid() bool { return r.First >= 1024 && r.First <= r.Last && r.Last <= 65535 }

func Contains(ranges []Range, port int) bool {
	for _, r := range ranges {
		if port >= r.First && port <= r.Last {
			return true
		}
	}
	return false
}

func ParseInventory(values []string) ([]Range, error) {
	if len(values) == 0 || len(values) > 128 {
		return nil, ErrInventory
	}
	ranges := make([]Range, 0, len(values))
	count := 0
	for _, value := range values {
		first, last, found := strings.Cut(value, "-")
		if !found {
			last = first
		}
		start, firstErr := strconv.Atoi(first)
		end, lastErr := strconv.Atoi(last)
		r := Range{First: start, Last: end}
		if firstErr != nil || lastErr != nil || !r.Valid() || strconv.Itoa(start) != first || strconv.Itoa(end) != last {
			return nil, ErrInventory
		}
		ranges = append(ranges, r)
		count += r.Last - r.First + 1
		if count > 256 {
			return nil, ErrInventory
		}
	}
	slices.SortFunc(ranges, func(a, b Range) int { return a.First - b.First })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].First <= ranges[i-1].Last {
			return nil, ErrInventory
		}
	}
	return ranges, nil
}

func Ports(ranges []Range) []int {
	ports := make([]int, 0)
	for _, interval := range ranges {
		for port := interval.First; port <= interval.Last; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
