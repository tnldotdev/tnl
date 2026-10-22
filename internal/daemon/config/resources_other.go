//go:build !linux && !darwin

package tnldconfig

func hostMemoryBytes() int64 { return 0 }

func constrainProcessResources(*resourceBudget) {}
