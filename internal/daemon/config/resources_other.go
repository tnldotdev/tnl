//go:build !linux && !darwin

package config

func hostMemoryBytes() int64 { return 0 }

func constrainProcessResources(*resourceBudget) {}
