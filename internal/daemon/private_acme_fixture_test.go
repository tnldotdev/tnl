package tnldruntime

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/control/certificates"
	dnscontroller "github.com/tnldotdev/tnl/internal/control/dns"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

// only the DNS provider is local. Pebble performs DNS-01 validation against
// records written by the real DNS and ACME workers, including cleanup receipts.
type privateFixtureDNS struct {
	mu      sync.Mutex
	address string
	txt     map[string][]string
	ip      map[string][]string
}

func newPrivateFixtureDNS(t *testing.T) *privateFixtureDNS {
	t.Helper()
	listener, packet := privateFixtureDNSListeners(t)
	f := &privateFixtureDNS{address: packet.LocalAddr().String(), txt: map[string][]string{}, ip: map[string][]string{}}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(r)
		answer.Authoritative = true
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeTXT:
				for _, value := range f.txt[dns.Fqdn(q.Name)] {
					answer.Answer = append(answer.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{value}})
				}
			case dns.TypeA:
				addresses := f.ip[dns.Fqdn(q.Name)]
				if len(addresses) == 0 {
					_, parent, _ := strings.Cut(q.Name, ".")
					addresses = f.ip["*."+parent]
				}
				for _, value := range addresses {
					answer.Answer = append(answer.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(value)})
				}
			}
		}
		_ = w.WriteMsg(answer)
	})
	for _, server := range []*dns.Server{{PacketConn: packet, Handler: handler}, {Listener: listener, Handler: handler}} {
		startOwnedDNSServer(t, server)
	}
	return f
}

// TCP and UDP have independent port allocations. keep both reservations until
// their servers take ownership, retrying only a collision with the other protocol.
func privateFixtureDNSListeners(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	for range 32 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		packet, err := net.ListenPacket("udp", listener.Addr().String())
		if err == nil {
			return listener, packet
		}
		_ = listener.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	t.Fatal("reserve one DNS port for TCP and UDP")
	return nil, nil
}
func (f *privateFixtureDNS) ReconcileChallenge(_ context.Context, r dnscontroller.ChallengeRecord) (dnscontroller.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[dns.Fqdn(r.RecordName)] = slices.Clone(r.DesiredOwnedValues)
	return dnscontroller.Zone{ID: r.ZoneID, Nameservers: []string{f.address}, ChangeID: "fixture-change"}, nil
}
func (f *privateFixtureDNS) RefreshChallenge(ctx context.Context, r dnscontroller.ChallengeRecord) (dnscontroller.Zone, error) {
	return f.ReconcileChallenge(ctx, r)
}
func (f *privateFixtureDNS) ChangeReady(context.Context, string) (bool, error) { return true, nil }
func (f *privateFixtureDNS) VerifyChallenge(ctx context.Context, name, expected string, _ []string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	answer, _, err := (&dns.Client{}).ExchangeContext(ctx, m, f.address)
	if err != nil {
		return false, err
	}
	for _, record := range answer.Answer {
		if txt, ok := record.(*dns.TXT); ok && slices.Contains(txt.Txt, expected) {
			return true, nil
		}
	}
	return false, nil
}
func (f *privateFixtureDNS) PublishAddress(_ context.Context, r dnscontroller.AddressRecord) (dnscontroller.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ip[dns.Fqdn(r.CanonicalHostname)] = slices.Clone(r.IngressIPv4Addresses)
	if r.WildcardHostname != "" {
		f.ip[dns.Fqdn(r.WildcardHostname)] = slices.Clone(r.IngressIPv4Addresses)
	}
	return dnscontroller.Zone{ID: r.ZoneID, Nameservers: []string{f.address}, ChangeID: "fixture-address"}, nil
}
func (f *privateFixtureDNS) RemoveAddress(_ context.Context, r dnscontroller.AddressRecord) (dnscontroller.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ip, dns.Fqdn(r.CanonicalHostname))
	delete(f.ip, dns.Fqdn(r.WildcardHostname))
	return dnscontroller.Zone{ID: r.ZoneID, Nameservers: []string{f.address}, ChangeID: "fixture-remove"}, nil
}
func (f *privateFixtureDNS) EnsureCustomZone(context.Context, controlstate.DNSAuthorityWork) (dnscontroller.Zone, error) {
	return dnscontroller.Zone{}, errors.New("fixture supports its managed domain only")
}
func (f *privateFixtureDNS) ReleaseCustomZone(context.Context, controlstate.DNSAuthorityWork) error {
	return errors.New("unexpected custom domain release")
}
func (f *privateFixtureDNS) Verify(context.Context, string, []string) (bool, error) {
	return false, errors.New("unexpected custom domain verification")
}
func (f *privateFixtureDNS) VerifyPublicURL(ctx context.Context, name string, ipv4, ipv6, _ []string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	answer, _, err := (&dns.Client{}).ExchangeContext(ctx, m, f.address)
	if err != nil {
		return false, err
	}
	var addresses []string
	for _, record := range answer.Answer {
		if address, ok := record.(*dns.A); ok {
			addresses = append(addresses, address.A.String())
		}
	}
	slices.Sort(addresses)
	expected := slices.Clone(ipv4)
	slices.Sort(expected)
	return len(ipv6) == 0 && slices.Equal(addresses, expected), nil
}

func privateFixtureACME(t *testing.T, d *controlstate.Database, cfg *tnldconfig.Config) (integrationPebble, *privateFixtureDNS) {
	t.Helper()
	provider := newPrivateFixtureDNS(t)
	pebble := startIntegrationPebble(t, 0, provider.address)
	cfg.Route53ManagedZoneID = "fixture-zone"
	cfg.IngressIPv4Addresses = []string{"127.0.0.1"}
	cfg.ACMEDirectoryURL = pebble.directoryURL
	account, err := d.EnsureACMEAccount(t.Context(), cfg.ACMEDirectoryURL, "operator@example.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = certificates.ReconcileACMEAccount(t.Context(), d, pebble.httpClient, account, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	return pebble, provider
}

func startPrivateFixtureWorkers(t *testing.T, ctx context.Context, process *daemon, d *controlstate.Database, cfg tnldconfig.Config, pebble integrationPebble, provider *privateFixtureDNS) {
	t.Helper()
	dnsConfig := dnscontroller.Config{WorkerID: "private-fixture-dns", ManagedDomain: cfg.ManagedDomain, ManagedZoneID: cfg.Route53ManagedZoneID, IngressIPv4Addresses: cfg.IngressIPv4Addresses, PollInterval: 20 * time.Millisecond}
	manager, err := dnscontroller.NewChallengeManager(d, provider, provider, dnsConfig)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := certificates.NewPublicURLWorker(d, certificates.PublicURLConfig{WorkerID: "private-fixture-acme", Profile: "tlsserver", HTTPClient: pebble.httpClient, DNSChallenges: manager, PollInterval: 20 * time.Millisecond, IdleInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := dnscontroller.New(d, provider, provider, dnsConfig)
	if err != nil {
		t.Fatal(err)
	}
	process.start("private fixture certificate worker", func() error { return worker.Run(ctx) })
	process.start("private fixture DNS worker", func() error { return addresses.Run(ctx) })
}
