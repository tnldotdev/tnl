package trafficlimits

import (
	"errors"
	"time"
)

// IngressConfig contains process-local encrypted traffic settings.
type IngressConfig struct {
	Default, Ceiling               Limits
	SourceConnections              int
	SourceRate, SourceBurst        int
	ProcessRate, ProcessBurst      int
	ProcessUpload, ProcessDownload int64
}

type PendingConfig struct {
	Connections, PublicURLConnections, SourceConnections   int
	PublicURLRate, PublicURLBurst, SourceRate, SourceBurst int
	Timeout                                                time.Duration
	UploadBytes, DownloadBytes                             int64
}

func (c IngressConfig) Resolve() (IngressConfig, error) {
	if c.Default == (Limits{}) {
		c.Default = Default()
	}
	if c.Ceiling == (Limits{}) {
		c.Ceiling = Ceiling()
	}
	for _, p := range []struct {
		value    *int
		fallback int
	}{
		{&c.SourceConnections, 64}, {&c.SourceRate, 30}, {&c.SourceBurst, 60},
		{&c.ProcessRate, 200}, {&c.ProcessBurst, 400},
	} {
		if *p.value == 0 {
			*p.value = p.fallback
		}
	}
	if c.ProcessUpload == 0 {
		c.ProcessUpload = 256 << 20
	}
	if c.ProcessDownload == 0 {
		c.ProcessDownload = 256 << 20
	}
	if !c.Default.Within(c.Ceiling) || c.SourceConnections < 1 || c.SourceRate < 1 || c.SourceBurst < 1 || c.ProcessRate < 1 || c.ProcessBurst < 1 ||
		c.SourceConnections > 1<<20 || c.SourceRate > 1<<31 || c.SourceBurst > 1<<31 || c.ProcessRate > 1<<31 || c.ProcessBurst > 1<<31 ||
		c.ProcessUpload < 64<<10 || c.ProcessDownload < 64<<10 || c.ProcessUpload > 1<<40 || c.ProcessDownload > 1<<40 {
		return c, errors.New("invalid traffic defaults, ceilings, or process budgets")
	}
	c.Default.RatePer = c.Default.Period()
	c.Ceiling.RatePer = c.Ceiling.Period()
	return c, nil
}

func (c PendingConfig) Resolve() (PendingConfig, error) {
	for _, p := range []struct {
		value    *int
		fallback int
	}{
		// ordinary restricted visitors now use pending capacity until the
		// publisher can inspect their credential. leave room for browser assets
		// while keeping independent per-source and per-URL ceilings.
		{&c.Connections, 256}, {&c.PublicURLConnections, 64}, {&c.SourceConnections, 16},
		{&c.PublicURLRate, 60}, {&c.PublicURLBurst, 120}, {&c.SourceRate, 30}, {&c.SourceBurst, 60},
	} {
		if *p.value == 0 {
			*p.value = p.fallback
		}
		if *p.value < 1 || *p.value > 1<<20 {
			return c, errors.New("pending capacities and attempt rates must be positive")
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.UploadBytes == 0 {
		c.UploadBytes = 64 << 10
	}
	if c.DownloadBytes == 0 {
		c.DownloadBytes = 128 << 10
	}
	if c.Timeout < time.Millisecond || c.Timeout > time.Minute || c.UploadBytes < 1 || c.DownloadBytes < 1 ||
		c.UploadBytes > 1<<20 || c.DownloadBytes > 1<<20 || c.PublicURLConnections > c.Connections || c.SourceConnections > c.Connections {
		return c, errors.New("invalid pending authorization bounds")
	}
	return c, nil
}
