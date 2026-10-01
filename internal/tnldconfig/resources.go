package tnldconfig

import (
	"math"
	"runtime"
)

const mebibyte int64 = 1 << 20

// resourceBudget is the process allocation, not the number of Go scheduler
// threads. in particular, GOMAXPROCS may exceed a container's CPU quota.
type resourceBudget struct {
	CPUs        float64
	MemoryBytes int64
}

func processResources() resourceBudget {
	resources := resourceBudget{CPUs: float64(runtime.NumCPU()), MemoryBytes: hostMemoryBytes()}
	if resources.MemoryBytes <= 0 {
		resources.MemoryBytes = 512 * mebibyte
	}
	constrainProcessResources(&resources)
	return resources
}

func (c *Config) resolveCapacities(resources resourceBudget) {
	// reserve 35% of available memory and another 64 MiB for the runtime,
	// certificates, buffers, and transient work. the remaining memory is split
	// between simultaneous admitted classes, rather than independently
	// granting every class the entire process budget.
	usable := max(int64(16*mebibyte), int64(float64(resources.MemoryBytes)*0.65)-64*mebibyte)
	cpu := max(0.001, resources.CPUs)
	bound := func(cpuLimit float64, memoryShare float64, bytesEach int64) int64 {
		return max(1, min(int64(math.Floor(cpu*cpuLimit)), int64(float64(usable)*memoryShare)/bytesEach))
	}
	ingressShare, relayShare, controlShare := 1.0, 1.0, 1.0
	if c.Role == RoleStandalone {
		ingressShare, relayShare, controlShare = 0.45, 0.45, 0.10
	}
	if c.ClientHelloConnectionLimit == -1 {
		c.ClientHelloConnectionLimit = int(bound(512, ingressShare*0.08, 32*1024))
	}
	if c.ChallengeConnectionLimit == -1 {
		c.ChallengeConnectionLimit = int(bound(512, ingressShare*0.08, 64*1024))
	}
	if c.VisitorConnectionLimit == -1 {
		c.VisitorConnectionLimit = bound(8192, ingressShare*0.75, 96*1024)
	}
	if c.PublisherConnectionLimit == -1 {
		c.PublisherConnectionLimit = bound(4096, relayShare*0.45, 96*1024)
	}
	if c.RelayStreamCapacity == -1 {
		c.RelayStreamCapacity = bound(4096, relayShare*0.45, 128*1024)
	}
	if c.StandaloneControlConnectionLimit == -1 {
		c.StandaloneControlConnectionLimit = int(bound(512, controlShare*0.8, 64*1024))
	}
	if c.StandaloneRelayConnectionLimit == -1 {
		c.StandaloneRelayConnectionLimit = int(min(c.PublisherConnectionLimit, bound(4096, relayShare*0.45, 96*1024)))
	}
	if c.QUICMaxIncomingStreams == -1 {
		c.QUICMaxIncomingStreams = min(4096, c.RelayStreamCapacity)
	}
}
