//go:build linux

package tailtransport

import (
	"fmt"
	"os"
)

func currentRSS() int64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return -1
	}
	var totalPages, residentPages int64
	if _, err := fmt.Sscan(string(data), &totalPages, &residentPages); err != nil {
		return -1
	}
	return residentPages * int64(os.Getpagesize())
}
