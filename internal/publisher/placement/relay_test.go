package placement

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestCandidatePairsIgnoreUnknownAndIncompleteRegions(t *testing.T) {
	var input controlv1.RelayCandidates
	for _, code := range []string{"ord", "sjc", "zzz"} {
		for slot := range 2 {
			input.Candidates = append(input.Candidates, controlv1.RelayProbeCandidate{Region: code, RelayServiceId: code + strconv.Itoa(slot), RelayAddress: "relay.example:" + strconv.Itoa(443+len(input.Candidates)), TlsServerName: "relay.example"})
		}
	}
	for _, location := range region.All()[:17] {
		code := string(location.Code)
		if code != "ord" && code != "sjc" {
			input.Candidates = append(input.Candidates, controlv1.RelayProbeCandidate{Region: code, RelayServiceId: code, RelayAddress: "relay.example:" + strconv.Itoa(443+len(input.Candidates)), TlsServerName: "relay.example"})
		}
	}
	pairs := candidatePairs(input)
	if len(pairs) != 2 || pairs[0].code != "ord" || pairs[1].code != "sjc" {
		t.Fatal("usable pairs hidden by unsupported inventory", pairs)
	}
	input.Candidates[1].RelayServiceId = input.Candidates[0].RelayServiceId
	if got := candidatePairs(input); len(got) != 0 {
		t.Fatal("duplicate relay service qualified a pair", got)
	}
	input.Candidates[1].RelayServiceId = "distinct-service"
	input.Candidates[1].RelayAddress = input.Candidates[0].RelayAddress
	if got := candidatePairs(input); len(got) != 0 {
		t.Fatal("duplicate relay endpoint qualified a pair", got)
	}
	input.Candidates[1].RelayAddress = "relay.example:invalid"
	if got := candidatePairs(input); len(got) != 0 {
		t.Fatal("invalid relay endpoint qualified a pair", got)
	}
}

func TestCanceledMeasurementCannotPopulateSharedRanking(t *testing.T) {
	started := make(chan struct{})
	var calls int
	c := chooser{measure: func(ctx context.Context, _ controlv1.RelayCandidates) []region.Code {
		calls++
		if calls == 1 {
			close(started)
			<-ctx.Done()
			return []region.Code{"ord"}
		}
		return []region.Code{"sjc", "ord"}
	}}
	input := controlv1.RelayCandidates{Candidates: []controlv1.RelayProbeCandidate{{Region: "ord"}}}
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan []region.Code, 1)
	go func() { first <- c.choose(ctx, input, nil) }()
	<-started
	second := make(chan []region.Code, 1)
	go func() { second <- c.choose(t.Context(), input, nil) }()
	cancel()
	if got := <-first; len(got) != 0 {
		t.Fatal("canceled initiator retained a ranking", got)
	}
	if got := <-second; !slices.Equal(got, []region.Code{"sjc", "ord"}) {
		t.Fatal("live waiter inherited canceled partial result", got)
	}
	got := c.choose(t.Context(), input, nil)
	got[0] = "ord"
	if got := c.choose(t.Context(), input, nil); got[0] != "sjc" || calls != 2 {
		t.Fatal("cached ranking was mutable or repeated", got, calls)
	}
}

func TestRankingDoesNotReuseDifferentRelayTransportTrust(t *testing.T) {
	var calls int
	c := chooser{measure: func(_ context.Context, _ controlv1.RelayCandidates) []region.Code {
		calls++
		return []region.Code{"sjc", "ord"}
	}}
	input := controlv1.RelayCandidates{Candidates: []controlv1.RelayProbeCandidate{{Region: "sjc"}}}
	first, second := &tls.Config{}, &tls.Config{}
	for _, trust := range []*tls.Config{first, second, first} {
		if got := c.choose(t.Context(), input, trust); !slices.Equal(got, []region.Code{"sjc", "ord"}) {
			t.Fatal("measured ranking changed", got)
		}
	}
	if calls != 2 {
		t.Fatal("cached ranking crossed distinct transport trust", calls)
	}
}

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
