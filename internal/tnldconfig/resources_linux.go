package tnldconfig

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func hostMemoryBytes() int64 {
	var info syscall.Sysinfo_t
	if syscall.Sysinfo(&info) != nil {
		return 0
	}
	return int64(info.Totalram) * int64(info.Unit)
}

func constrainProcessResources(resources *resourceBudget) {
	// the cgroup filesystem is namespaced inside containers on Linux. prefer
	// v2, then v1 where supported. missing or unlimited values keep OS limits.
	for _, name := range []string{"/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"} {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if name == "/sys/fs/cgroup/cpu.max" {
			fields := strings.Fields(value)
			if len(fields) == 2 {
				if quota, err := strconv.ParseFloat(fields[0], 64); err == nil && quota > 0 {
					if period, err := strconv.ParseFloat(fields[1], 64); err == nil && period > 0 {
						resources.CPUs = min(resources.CPUs, quota/period)
						break
					}
				}
			}
		} else if quota, err := strconv.ParseFloat(value, 64); err == nil && quota > 0 {
			if periodBytes, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us"); err == nil {
				if period, err := strconv.ParseFloat(strings.TrimSpace(string(periodBytes)), 64); err == nil && period > 0 {
					resources.CPUs = min(resources.CPUs, quota/period)
				}
			}
		}
	}
	for _, name := range []string{"/sys/fs/cgroup/cpuset.cpus.effective", "/sys/fs/cgroup/cpuset/cpuset.cpus"} {
		if data, err := os.ReadFile(name); err == nil {
			if count := cpuSetCount(strings.TrimSpace(string(data))); count > 0 {
				resources.CPUs = min(resources.CPUs, float64(count))
				break
			}
		}
	}
	for _, name := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		if data, err := os.ReadFile(name); err == nil {
			if limit, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && limit > 0 {
				resources.MemoryBytes = min(resources.MemoryBytes, limit)
				break
			}
		}
	}
}

func cpuSetCount(value string) int {
	if value == "" {
		return 0
	}
	count := 0
	for _, part := range strings.Split(value, ",") {
		ends := strings.Split(part, "-")
		start, err := strconv.Atoi(ends[0])
		if err != nil || start < 0 {
			return 0
		}
		end := start
		if len(ends) == 2 {
			end, err = strconv.Atoi(ends[1])
			if err != nil || end < start {
				return 0
			}
		} else if len(ends) != 1 {
			return 0
		}
		count += end - start + 1
	}
	return count
}
