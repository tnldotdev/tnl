package dnsready

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const (
	stateUnknown int32 = iota
	stateUnavailable
	stateReady
)

var checkInterval = 30 * time.Second

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupCNAME(context.Context, string) (string, error)
}

type ingressSet struct {
	addresses []net.IPAddr
}

// Checker verifies that static route wildcard DNS reaches the control ingress.
type Checker struct {
	controlHost    string
	hostnameSuffix string
	resolver       resolver
	state          atomic.Int32
	ingress        atomic.Pointer[ingressSet]
}

func New(controlHost, hostnameSuffix string) *Checker {
	return NewWithResolver(controlHost, hostnameSuffix, net.DefaultResolver)
}

func NewWithResolver(controlHost, hostnameSuffix string, resolver *net.Resolver) *Checker {
	return &Checker{controlHost: controlHost, hostnameSuffix: hostnameSuffix, resolver: resolver}
}

// Ready reports the most recently observed readiness state.
func (c *Checker) Ready() bool { return c.state.Load() == stateReady }

// Check resolves representative base and maximum-depth descendant names against
// the control ingress.
func (c *Checker) Check(ctx context.Context) error {
	var material [8]byte
	if _, err := rand.Read(material[:]); err != nil {
		return fmt.Errorf("generate DNS probe name: %w", err)
	}
	base := "tnl-dns-" + hex.EncodeToString(material[:]) + "." + c.hostnameSuffix
	control, err := c.resolver.LookupIPAddr(ctx, c.controlHost)
	if err != nil {
		return fmt.Errorf("resolve control hostname %s: %w", c.controlHost, err)
	}
	c.ingress.Store(&ingressSet{addresses: append([]net.IPAddr(nil), control...)})
	deep := base
	for index := 8; index > 0; index-- {
		deep = fmt.Sprintf("d%d.%s", index, deep)
	}
	for _, hostname := range []string{base, deep} {
		if err := c.checkHostnameAgainst(ctx, hostname, control); err != nil {
			return err
		}
	}
	return nil
}

// CheckHostname requires one route hostname address to overlap control ingress.
func (c *Checker) CheckHostname(ctx context.Context, hostname string) error {
	control, err := c.resolver.LookupIPAddr(ctx, c.controlHost)
	if err != nil {
		return fmt.Errorf("resolve control hostname %s: %w", c.controlHost, err)
	}
	return c.checkHostnameAgainst(ctx, hostname, control)
}

func (c *Checker) checkHostnameAgainst(ctx context.Context, hostname string, control []net.IPAddr) error {
	route, err := c.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return fmt.Errorf("resolve route hostname %s: %w", hostname, err)
	}
	if !overlap(control, route) {
		return fmt.Errorf("route hostname %s does not resolve to control ingress", hostname)
	}
	return nil
}

// IngressAddresses returns the currently ready control ingress addresses.
func (c *Checker) IngressAddresses() []string {
	current := c.ingress.Load()
	if current == nil {
		return nil
	}
	unique := make(map[string]struct{}, len(current.addresses))
	for _, address := range current.addresses {
		if address.IP != nil {
			unique[address.IP.String()] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}

// CheckDomain verifies exact and wildcard claim-specific CNAME proof and the
// resulting route address. Apex proof uses _tnl because an apex cannot be a CNAME.
func (c *Checker) CheckDomain(ctx context.Context, domain, target string, apex bool) error {
	proof := domain
	if apex {
		proof = "_tnl." + domain
	}
	if err := c.checkCNAME(ctx, proof, target); err != nil {
		return err
	}
	var material [8]byte
	if _, err := rand.Read(material[:]); err != nil {
		return fmt.Errorf("generate wildcard DNS probe: %w", err)
	}
	child := "tnl-proof-" + hex.EncodeToString(material[:]) + "." + domain
	if err := c.checkCNAME(ctx, child, target); err != nil {
		return err
	}
	if err := c.CheckHostname(ctx, domain); err != nil {
		return err
	}
	return c.CheckHostname(ctx, child)
}

func (c *Checker) checkCNAME(ctx context.Context, hostname, target string) error {
	actual, err := c.resolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return fmt.Errorf("resolve CNAME %s: %w", hostname, err)
	}
	actual = strings.ToLower(strings.TrimSuffix(actual, "."))
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	if actual != target || actual == strings.ToLower(strings.TrimSuffix(hostname, ".")) {
		return fmt.Errorf("CNAME %s does not target %s", hostname, target)
	}
	return nil
}

// Monitor checks immediately and then periodically, reporting only state transitions.
func (c *Checker) Monitor(ctx context.Context, logf func(string, ...any)) {
	check := func() {
		err := c.Check(ctx)
		next := int32(stateReady)
		if err != nil {
			next = stateUnavailable
		}
		previous := c.state.Swap(next)
		if previous == next {
			return
		}
		if err == nil {
			logf("Public DNS ready")
			for _, address := range c.IngressAddresses() {
				family := "IPv6"
				if net.ParseIP(address).To4() != nil {
					family = "IPv4"
				}
				logf("%s ingress: %s", family, address)
			}
		} else {
			logf("Public DNS not ready: %v", err)
		}
	}
	check()
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func overlap(left, right []net.IPAddr) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	for _, a := range left {
		for _, b := range right {
			if a.IP.Equal(b.IP) {
				return true
			}
		}
	}
	return false
}
