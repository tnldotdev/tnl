package ingress

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestPublicURLRequiresExactOriginalDestinationPort(t *testing.T) {
	for _, port := range []uint16{25443, 25444, 443} {
		t.Run(net.JoinHostPort("route.example", strconv.Itoa(int(port))), func(t *testing.T) {
			backend := newTLSBackend(t)
			configuration := publicURLConfig(backend)
			lookup := configuration.Lookup
			configuration.Lookup = func(host string) ([]PublicURL, LookupReason) {
				runs, reason := lookup(host)
				for index := range runs {
					runs[index].Port = 25443
				}
				return runs, reason
			}
			configuration.RequireProxyHeader = true
			configuration.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
			configuration.ServicePortRanges = []tcpport.Range{{First: 25443, Last: 25444}}
			configuration.HasPublicURLPort = func(value int) bool { return value == 25443 || value == 25444 }
			_, address := startIngress(t, configuration)
			connection, err := net.DialTimeout("tcp", address, fixtureTimeout)
			if err != nil {
				t.Fatal(err)
			}
			ownIngressConn(t, connection)
			destination := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port)
			header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.8:40000"), Destination: destination})
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAll(connection, header); err != nil {
				t.Fatal(err)
			}
			client := tls.Client(connection, &tls.Config{ServerName: "route.example", MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}) // local self-signed fixture.
			if port != 25443 {
				if err := client.Handshake(); err == nil || backend.opens.Load() != 0 {
					t.Fatal("hostname lookup authorized another destination port", err, backend.opens.Load())
				}
				return
			}
			exchangePing(t, client)
			result := ingressAwait(t, backend.result)
			if result.err != nil || result.header.Destination != destination || backend.opens.Load() != 1 {
				t.Fatal("high-port visitor lost exact destination metadata", result, backend.opens.Load())
			}
		})
	}
}

func TestRoutingTablePortIndexTracksRunsAndRejectsInvalidPagesAtomically(t *testing.T) {
	now := time.Now().UTC()
	event := func(revision, run int64, port int) ingressv1.IngressRoutingTableEvent {
		entry := forwardingTestEntry(now, "relay.example:443")
		entry.Port, entry.PublishRunNumber = port, run
		entry.CanonicalHostname, entry.PolicyRevision = "route.example", 1
		entry.PublishRunId, entry.IpPolicy = "run-"+strconv.FormatInt(run, 10), ingressv1.AllowAll
		return ingressv1.IngressRoutingTableEvent{RoutingTableRevision: revision, Kind: ingressv1.PublicUrlUpsert,
			PublicUrlId: entry.PublicUrlId, PublishRunNumber: run, CanonicalHostname: entry.CanonicalHostname,
			EntryRevision: revision, Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now}
	}
	var table RoutingTable
	first, second := event(1, 1, 25443), event(2, 2, 25443)
	if err := table.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2, Entries: []ingressv1.IngressRoutingTableEvent{first, second}}); err != nil {
		t.Fatal(err)
	}
	if !table.HasPublicURLPort(25443) || table.HasPublicURLPort(0) || table.HasPublicURLPort(443) {
		t.Fatal("snapshot did not index exact public URL ports")
	}
	tombstone := event(3, 1, 25443)
	tombstone.Kind, tombstone.PublicUrlExpiresAt = ingressv1.PublicUrlTombstone, nil
	tombstone.Entry.PublisherConnections = nil
	if err := table.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{tombstone}}); err != nil {
		t.Fatal(err)
	}
	if !table.HasPublicURLPort(25443) {
		t.Fatal("one run's tombstone removed its sibling's port")
	}
	changed, invalid := event(4, 2, 25444), event(5, 3, 0)
	if err := table.ApplyPage(3, ingressv1.IngressRoutingTablePage{ThroughRevision: 5, NextRevision: 5, Events: []ingressv1.IngressRoutingTableEvent{changed, invalid}}); err == nil {
		t.Fatal("unreserved port was accepted")
	}
	if !table.HasPublicURLPort(25443) || table.HasPublicURLPort(25444) {
		t.Fatal("invalid page partially changed the port index")
	}
	if err := table.ApplyPage(3, ingressv1.IngressRoutingTablePage{ThroughRevision: 4, NextRevision: 4, Events: []ingressv1.IngressRoutingTableEvent{changed}}); err != nil {
		t.Fatal(err)
	}
	if table.HasPublicURLPort(25443) || !table.HasPublicURLPort(25444) {
		t.Fatal("replacement retained an old port or lost the new one")
	}
}
