package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// compose may start a component before docker dns has registered its sibling.
// bound discovery separately from server startup; never retry a whole workload.
func separatedLookupIPv4(ctx context.Context, hostname string, lookup func(context.Context, string, string) ([]net.IP, error)) (result []net.IP, retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("resolve separated runtime host %q: %w", hostname, retErr)
		}
	}()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	delay := 100 * time.Millisecond
	for {
		call, done := context.WithTimeout(startup, 2*time.Second)
		addresses, err := lookup(call, "ip4", hostname)
		if err == nil {
			err = call.Err()
		}
		done()
		if startup.Err() != nil {
			return nil, errors.Join(context.Cause(startup), err)
		}
		if err == nil {
			for _, address := range addresses {
				if address.To4() != nil {
					result = append(result, address)
				}
			}
			if len(result) > 0 {
				return result, nil
			}
			err = errors.New("no IPv4 address is registered yet")
		} else {
			var dns *net.DNSError
			if !errors.Is(err, context.DeadlineExceeded) &&
				(!errors.As(err, &dns) || !dns.IsNotFound && !dns.IsTemporary && !dns.IsTimeout) {
				return nil, err
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-startup.Done():
			timer.Stop()
			return nil, errors.Join(context.Cause(startup), err)
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
}

func TestSeparatedDNSRetriesContainerRegistrationBeforeIPv4Readiness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		started := time.Now()
		addresses, err := separatedLookupIPv4(t.Context(), "ingress", func(ctx context.Context, network, host string) ([]net.IP, error) {
			calls++
			if network != "ip4" || host != "ingress" {
				t.Error("lookup changed the selected fixture hostname or address family")
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
				t.Error("lookup has no bounded request deadline")
			}
			switch calls {
			case 1:
				return nil, &net.DNSError{IsTemporary: true, Name: host, Err: "server misbehaving"}
			case 2:
				return nil, &net.DNSError{IsNotFound: true, Name: host, Err: "not registered"}
			case 3:
				return nil, &net.DNSError{IsTimeout: true, Name: host, Err: "timeout"}
			case 4:
				return []net.IP{net.ParseIP("::1")}, nil
			default:
				return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")}, nil
			}
		})
		if err != nil || calls != 5 || len(addresses) != 2 || !addresses[0].Equal(net.ParseIP("192.0.2.10")) || !addresses[1].Equal(net.ParseIP("192.0.2.11")) || time.Since(started) != 1500*time.Millisecond {
			t.Fatal("fixture DNS did not wait for the exact IPv4 result", calls, addresses, err)
		}
	})
}

func TestSeparatedDNSOutageHasFixedBudgetAndPreservesCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cause := &net.DNSError{IsTemporary: true, Name: "ingress", Err: "server misbehaving"}
		started, calls := time.Now(), 0
		_, err := separatedLookupIPv4(t.Context(), "ingress", func(context.Context, string, string) ([]net.IP, error) {
			calls++
			return nil, cause
		})
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) || time.Since(started) != 10*time.Second || calls > 20 {
			t.Fatal("fixture DNS escaped its budget or lost the lookup failure", calls, err)
		}
	})
}

func TestSeparatedDNSCancellationInterruptsBlockedLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started, calls := time.Now(), 0
		_, err := separatedLookupIPv4(ctx, "ingress", func(ctx context.Context, _, _ string) ([]net.IP, error) {
			calls++
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if !errors.Is(err, context.Canceled) || calls != 1 || time.Since(started) != 0 {
			t.Fatal("canceled fixture lookup retried or blocked", calls, err)
		}
	})
}

func TestSeparatedDNSPermanentFailureDoesNotRetry(t *testing.T) {
	cause := &net.DNSError{Name: "ingress", Err: "invalid resolver configuration"}
	calls := 0
	_, err := separatedLookupIPv4(t.Context(), "ingress", func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return nil, cause
	})
	if !errors.Is(err, cause) || calls != 1 {
		t.Fatal("permanent fixture DNS failure retried or lost its cause", calls, err)
	}
}
