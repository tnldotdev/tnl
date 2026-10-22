package tnldconfig

import "golang.org/x/sys/unix"

func hostMemoryBytes() int64 {
	value, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return int64(value)
}

func constrainProcessResources(*resourceBudget) {}
