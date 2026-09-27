package tnldconfig

import "testing"

func TestAutomaticCapacitiesShareMemory(t *testing.T) {
	for _, role := range []Role{RoleIngress, RoleRelay, RoleStandalone} {
		for _, cpu := range []float64{1, 2} {
			var previous Config
			for _, memoryMiB := range []int64{512, 1024, 2048} {
				cfg := Config{
					Role: role, ClientHelloConnectionLimit: -1, ChallengeConnectionLimit: -1,
					VisitorConnectionLimit: -1, PublisherConnectionLimit: -1, RelayStreamCapacity: -1,
					StandaloneControlConnectionLimit: -1, StandaloneRelayConnectionLimit: -1,
					QUICMaxIncomingStreams: -1,
				}
				cfg.resolveCapacities(resourceBudget{CPUs: cpu, MemoryBytes: memoryMiB * mebibyte})
				if cfg.ClientHelloConnectionLimit <= 0 || cfg.ChallengeConnectionLimit <= 0 || cfg.VisitorConnectionLimit <= 0 ||
					cfg.PublisherConnectionLimit <= 0 || cfg.RelayStreamCapacity <= 0 || cfg.StandaloneControlConnectionLimit <= 0 ||
					cfg.StandaloneRelayConnectionLimit <= 0 || cfg.QUICMaxIncomingStreams <= 0 {
					t.Fatalf("%s %.1f CPU %d MiB: invalid limits: %+v", role, cpu, memoryMiB, cfg)
				}
				if cfg.PublisherConnectionLimit < previous.PublisherConnectionLimit || cfg.RelayStreamCapacity < previous.RelayStreamCapacity ||
					cfg.VisitorConnectionLimit < previous.VisitorConnectionLimit {
					t.Fatalf("%s %.1f CPU: more memory reduced capacities: %+v -> %+v", role, cpu, previous, cfg)
				}
				usable := max(int64(16*mebibyte), int64(float64(memoryMiB*mebibyte)*0.65)-64*mebibyte)
				relayBudget := usable
				if role == RoleStandalone {
					relayBudget = int64(float64(usable) * 0.45)
					combined := cfg.VisitorConnectionLimit*96*1024 + int64(cfg.ClientHelloConnectionLimit)*32*1024 +
						int64(cfg.ChallengeConnectionLimit)*64*1024 + cfg.PublisherConnectionLimit*96*1024 +
						cfg.RelayStreamCapacity*128*1024 + int64(cfg.StandaloneControlConnectionLimit)*64*1024
					if combined > usable {
						t.Fatalf("%s %.1f CPU %d MiB: simultaneous standalone limits exceed memory budget", role, cpu, memoryMiB)
					}
				}
				if cfg.PublisherConnectionLimit*96*1024+cfg.RelayStreamCapacity*128*1024 > relayBudget {
					t.Fatalf("%s %.1f CPU %d MiB: simultaneous relay limits exceed memory budget", role, cpu, memoryMiB)
				}
				if cfg.QUICMaxIncomingStreams > cfg.RelayStreamCapacity || int64(cfg.StandaloneRelayConnectionLimit) > cfg.PublisherConnectionLimit {
					t.Fatalf("%s %.1f CPU %d MiB: derived handoff/transport exceeds relay capacity", role, cpu, memoryMiB)
				}
				previous = cfg
			}
		}
	}
}

func TestExplicitCapacitiesSurviveResolution(t *testing.T) {
	cfg := Config{
		Role: RoleRelay, ClientHelloConnectionLimit: 9, ChallengeConnectionLimit: 8,
		VisitorConnectionLimit: 7, PublisherConnectionLimit: 6, RelayStreamCapacity: 5,
		StandaloneControlConnectionLimit: 4, StandaloneRelayConnectionLimit: 3,
		QUICMaxIncomingStreams: 2,
	}
	cfg.resolveCapacities(resourceBudget{CPUs: 1, MemoryBytes: 512 * mebibyte})
	if cfg.ClientHelloConnectionLimit != 9 || cfg.ChallengeConnectionLimit != 8 || cfg.VisitorConnectionLimit != 7 ||
		cfg.PublisherConnectionLimit != 6 || cfg.RelayStreamCapacity != 5 || cfg.StandaloneControlConnectionLimit != 4 ||
		cfg.StandaloneRelayConnectionLimit != 3 || cfg.QUICMaxIncomingStreams != 2 {
		t.Fatalf("explicit overrides changed: %+v", cfg)
	}
}

func TestCPULimitedDefaults(t *testing.T) {
	limits := func(cpu float64) Config {
		cfg := Config{Role: RoleIngress, ClientHelloConnectionLimit: -1, ChallengeConnectionLimit: -1,
			VisitorConnectionLimit: -1, PublisherConnectionLimit: -1, RelayStreamCapacity: -1,
			StandaloneControlConnectionLimit: -1, StandaloneRelayConnectionLimit: -1, QUICMaxIncomingStreams: -1}
		cfg.resolveCapacities(resourceBudget{CPUs: cpu, MemoryBytes: 8 << 30})
		return cfg
	}
	small, one, two := limits(0.1), limits(1), limits(2)
	if small.VisitorConnectionLimit > one.VisitorConnectionLimit/10 || small.PublisherConnectionLimit > one.PublisherConnectionLimit/10 {
		t.Fatalf("sub-quarter CPU quota was inflated: 0.1=%+v one=%+v", small, one)
	}
	if two.VisitorConnectionLimit != 2*one.VisitorConnectionLimit || two.PublisherConnectionLimit != 2*one.PublisherConnectionLimit {
		t.Fatalf("capacity must scale with CPU where memory is not the ceiling: one=%+v two=%+v", one, two)
	}
}
