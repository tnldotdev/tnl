package ingress

import (
	"errors"
	"net"
	"testing"
	"time"
)

func publicServiceWaitAuthorized(t *testing.T, p *PublicServices) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		active := p.active
		p.mu.Unlock()
		if active == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("public service visitor was not promoted")
}

func TestPublicServiceLiveVisitorClosesOnExplicitDenial(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	p.config.RecheckInterval, p.config.RecheckTimeout, p.config.HardAuthorizationTTL = 20*time.Millisecond, 10*time.Millisecond, 150*time.Millisecond
	stream, stop := publicServiceActiveStream(t, p, f)
	publicServiceWaitAuthorized(t, p)
	c.mu.Lock()
	c.deny = true
	c.mu.Unlock()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked visitor kept an active stream")
	}
	stop()
	if c.recheckActive.Load() != 0 {
		t.Fatal("recheck survived denial")
	}
	select {
	case <-f.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived denial")
	}
}

func TestPublicServiceLiveVisitorOutageHonorsLastSuccessfulDeadline(t *testing.T) {
	for _, grant := range []bool{false, true} {
		name := "hard ttl"
		if grant {
			name = "earlier grant"
		}
		t.Run(name, func(t *testing.T) {
			p, c, f, _ := publicServiceTestSetup(t)
			p.config.RecheckInterval, p.config.RecheckTimeout = 20*time.Millisecond, 10*time.Millisecond
			p.config.HardAuthorizationTTL = 125 * time.Millisecond
			bound := 300 * time.Millisecond
			if grant {
				p.config.HardAuthorizationTTL = 250 * time.Millisecond
				c.recheckValidUntil = time.Now().Add(135 * time.Millisecond)
				bound = 190 * time.Millisecond
			}
			stream, stop := publicServiceActiveStream(t, p, f)
			publicServiceWaitAuthorized(t, p)
			c.mu.Lock()
			c.recheckErr = errors.New("control unavailable after last check")
			c.mu.Unlock()
			started := time.Now()
			_ = stream.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := stream.Read(make([]byte, 1)); err == nil {
				t.Fatal("outage left visitor open")
			}
			if elapsed := time.Since(started); elapsed > bound || !grant && elapsed < 35*time.Millisecond {
				t.Fatalf("outage deadline = %v", elapsed)
			}
			stop()
			c.mu.Lock()
			checks := c.rechecks
			c.mu.Unlock()
			if checks < 2 || c.recheckActive.Load() != 0 {
				t.Fatalf("recheck retries/join: checks=%d active=%d", checks, c.recheckActive.Load())
			}
			select {
			case <-f.relayDone:
			case <-time.After(time.Second):
				t.Fatal("relay copy survived deadline")
			}
		})
	}
}

func TestPublicServiceLiveVisitorOutageHonorsInitialClaimDeadline(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.initialValidUntil = time.Now().Add(175 * time.Millisecond)
	c.recheckErr = errors.New("control unavailable immediately after admission")
	stream, stop := publicServiceActiveStream(t, p, f)
	started := time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("initial expiry did not end visitor")
	}
	if elapsed := time.Since(started); elapsed > 230*time.Millisecond {
		t.Fatalf("ignored initial deadline for %v", elapsed)
	}
	stop()
	c.mu.Lock()
	checks := c.rechecks
	c.mu.Unlock()
	if checks < 2 || c.recheckActive.Load() != 0 {
		t.Fatalf("initial outage scheduling/join: checks=%d active=%d", checks, c.recheckActive.Load())
	}
	select {
	case <-f.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived initial expiry")
	}
}

func TestPublicServiceLiveVisitorDefaultsRefreshShortInitialLease(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.initialValidUntil = time.Now().Add(250 * time.Millisecond)
	c.recheckStarted = make(chan struct{}, 1)
	stream, _ := publicServiceActiveStream(t, p, f)
	select {
	case <-c.recheckStarted:
	case <-time.After(time.Second):
		t.Fatal("default scheduling missed initial lease")
	}
	_ = stream.SetReadDeadline(c.initialValidUntil.Add(100 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected bytes")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("successful check did not preserve same stream: %v", err)
	}
}

func TestPublicServiceLiveVisitorCloseJoinsBlockedRecheckAndCopy(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	p.config.RecheckInterval, p.config.RecheckTimeout, p.config.HardAuthorizationTTL = 120*time.Millisecond, 100*time.Millisecond, 350*time.Millisecond
	_, stop := publicServiceActiveStream(t, p, f)
	publicServiceWaitAuthorized(t, p)
	c.mu.Lock()
	c.recheckStarted, c.recheckGate = make(chan struct{}, 1), make(chan struct{})
	started := c.recheckStarted
	c.mu.Unlock()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked check never started")
	}
	_ = p.Close()
	stop()
	if c.recheckActive.Load() != 0 || p.Load() != 0 || p.pending != 0 || p.active != 0 {
		t.Fatal("close did not join policy and release capacity")
	}
	select {
	case <-f.relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay copy survived close")
	}
}
