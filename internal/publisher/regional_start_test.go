package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type measuredRunControl struct {
	PublicURLControlClient
	candidates controlv1.RelayCandidates
	preferred  []string
	created    bool
}

type measuredCertificateControl struct {
	*certificateTestControl
	candidates controlv1.RelayCandidates
	preferred  []string
}

func (c *measuredCertificateControl) RelayCandidates(context.Context, string) (controlv1.RelayCandidates, error) {
	return c.candidates, nil
}

func (c *measuredCertificateControl) CreatePublishRunInRegions(ctx context.Context, id, key string, preferred []string) (controlv1.PublishRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	return c.certificateTestControl.CreatePublishRun(ctx, id, key)
}

func TestPublicPublisherReachesReadyWithMeasuredTwoRegionStart(t *testing.T) {
	control := newCertificateTestControl(t, "app.member.example", namespaceCertificateTestPlan())
	control.store = certificateTestStore(t, filepath.Join(t.TempDir(), "state"))
	config := startCertificateTLSYamuxHarness(t, control)
	relay := publicURLTestCertificate(t, "relay.example")
	tcp := config.TCPConnector.(muxsession.TLSYamuxConnector)
	tcp.TLSConfig = tcp.TLSConfig.Clone()
	tcp.TLSConfig.RootCAs = tcp.TLSConfig.RootCAs.Clone()
	tcp.TLSConfig.RootCAs.AddCert(relay.Leaf)
	config.TCPConnector = tcp
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	var listeners []net.Listener
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	})
	measured := &measuredCertificateControl{certificateTestControl: control}
	for _, assigned := range control.setup.PublisherConnections {
		measured.candidates.Candidates = append(measured.candidates.Candidates, controlv1.RelayProbeCandidate{
			Region: "sjc", RelayServiceId: assigned.RelayServiceId, RelayAddress: assigned.RelayAddress, TlsServerName: assigned.TlsServerName,
		})
	}
	for slot := range 2 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		workers.Go(func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					defer connection.Close()
					stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
					defer stop()
					time.Sleep(75 * time.Millisecond)
					_, _, _ = muxsession.AcceptTLSYamuxOrProbe(ctx, connection, &tls.Config{Certificates: []tls.Certificate{relay}}, muxsession.TLSYamuxConfig{})
				})
			}
		})
		measured.candidates.Candidates = append(measured.candidates.Candidates, controlv1.RelayProbeCandidate{
			Region: "ord", RelayServiceId: "relay-ord-" + strconv.Itoa(slot), RelayAddress: listener.Addr().String(), TlsServerName: "relay.example",
		})
	}
	config.Control = measured
	reachedReady := errors.New("public publisher reached ready")
	control.ready = func() error { return reachedReady }
	if err := runCertificateSessionTest(t, config); !errors.Is(err, reachedReady) || !slices.Equal(measured.preferred, []string{"sjc", "ord"}) || len(control.closedSessions) != 1 {
		t.Fatal("automatic two-region ranking failed before public publisher readiness", measured.preferred, err)
	}
}

func (c *measuredRunControl) RelayCandidates(context.Context, string) (controlv1.RelayCandidates, error) {
	return c.candidates, nil
}

func (c *measuredRunControl) CreatePublishRunInRegions(_ context.Context, id, _ string, preferred []string) (controlv1.PublishRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	c.created = true
	return controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{Id: id}}, nil
}

func TestPublicRunCreationUsesVerifiedMeasuredRelayPairs(t *testing.T) {
	certificate := publicURLTestCertificate(t, "relay.example")
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	var listeners []net.Listener
	t.Cleanup(func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		workers.Wait()
	})
	control := &measuredRunControl{}
	for _, site := range []struct {
		code  string
		delay time.Duration
	}{{"sjc", 0}, {"ord", 75 * time.Millisecond}} {
		for slot := range 2 {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listeners = append(listeners, listener)
			workers.Go(func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer connection.Close()
						stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
						defer stop()
						time.Sleep(site.delay)
						_, _, _ = muxsession.AcceptTLSYamuxOrProbe(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
					})
				}
			})
			control.candidates.Candidates = append(control.candidates.Candidates, controlv1.RelayProbeCandidate{
				Region: site.code, RelayServiceId: "relay-" + site.code + "-" + strconv.Itoa(slot),
				RelayAddress: listener.Addr().String(), TlsServerName: "relay.example",
			})
		}
	}
	url := controlv1.PublicURL{Id: "url_aaaaaaaaaaaaaaaaaaaaaa"}
	setup, err := createPublishRun(ctx, Config{Control: control, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}}}, url)
	if err != nil || setup.PublicUrl.Id != url.Id || !control.created || !slices.Equal(control.preferred, []string{"sjc", "ord"}) {
		t.Fatal("verified two-region placement did not reach regional run creation", setup, control.preferred, err)
	}
}
