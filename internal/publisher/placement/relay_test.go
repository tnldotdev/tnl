package placement

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherRanksTwoVerifiedRelayServicesPerRegion(t *testing.T) {
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := issuer.TLS.Certificates[0]
	trust := x509.NewCertPool()
	trust.AddCert(issuer.Certificate())
	issuer.Close()
	var candidates controlv1.RelayCandidates
	var slow net.Listener
	for _, site := range []struct {
		code  string
		delay time.Duration
	}{{"sjc", 0}, {"ord", 80 * time.Millisecond}} {
		for slot := 1; slot <= 2; slot++ {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			var workers sync.WaitGroup
			workers.Go(func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer connection.Close()
						time.Sleep(site.delay)
						_, _, _ = muxsession.AcceptTLSYamuxOrProbe(ctx, connection,
							&tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
					})
				}
			})
			t.Cleanup(func() { cancel(); _ = listener.Close(); workers.Wait() })
			candidates.Candidates = append(candidates.Candidates, controlv1.RelayProbeCandidate{
				Region: site.code, RelayServiceId: "relay-" + site.code + "-" + strconv.Itoa(slot),
				RelayAddress: listener.Addr().String(), TlsServerName: "127.0.0.1",
			})
			if site.code == "ord" && slot == 2 {
				slow = listener
			}
		}
	}
	selected := Rank(context.Background(), candidates, &tls.Config{RootCAs: trust})
	if len(selected) != 2 || selected[0] != "sjc" || selected[1] != "ord" {
		t.Fatalf("verified publisher relay paths: %v", selected)
	}
	if selected = Rank(context.Background(), candidates, &tls.Config{InsecureSkipVerify: true}); len(selected) != 0 {
		t.Fatalf("unverified relay TLS influenced placement: %v", selected)
	}
	_ = slow.Close()
	selected = Rank(context.Background(), candidates, &tls.Config{RootCAs: trust})
	if len(selected) != 1 || selected[0] != "sjc" {
		t.Fatalf("one working relay service did not exclude its region: %v", selected)
	}
}
