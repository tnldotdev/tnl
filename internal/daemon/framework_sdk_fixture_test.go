package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherlocal "github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/zalando/go-keyring"
)

type frameworkNativeSetup struct {
	controlURL              string
	state                   *clientstate.Store
	controlHTTP, publicHTTP *http.Client
	publicDomain            string
	publicRootPEM           []byte
	relayTLS                *tls.Config
	quic, tcp               muxsession.Connector
}

type frameworkNativeOwner struct {
	endpoint string
	routable <-chan string
	stop     func()
}

// share the real native app owner with connector and public framework proofs.
// only infrastructure addressing/trust and a readiness observer are attached.
func startFrameworkNativeOwner(t *testing.T, directory string, services config.Services, setup frameworkNativeSetup) frameworkNativeOwner {
	t.Helper()
	if runtime.GOOS == "darwin" {
		keyring.MockInit()
	}
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	profile, err := state.Server(t.Context(), setup.controlURL)
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := setup.state.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatal("fixture lost its control session", err)
	}
	if err := profile.SaveControlSession(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_ACCESS_TOKEN", "")
	t.Setenv("TNL_SERVER", "")
	original := http.DefaultTransport
	transport := setup.controlHTTP.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	controlDial := transport.DialContext
	controlOrigin, err := url.Parse(setup.controlURL)
	if err != nil {
		t.Fatal(err)
	}
	var publicDial func(context.Context, string, string) (net.Conn, error)
	if setup.publicHTTP != nil {
		publicDial = setup.publicHTTP.Transport.(*http.Transport).DialContext
		transport.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
		if setup.publicDomain == "" || !transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(setup.publicRootPEM) {
			t.Fatal("public framework transport requires its managed domain and visitor CA")
		}
	}
	// target probes clone the standard transport and must still reach the real
	// local listener. redirect only control and managed public socket addresses.
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		hostname, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if hostname == controlOrigin.Hostname() {
			return controlDial(ctx, network, address)
		}
		if publicDial != nil && strings.HasSuffix(hostname, "."+setup.publicDomain) {
			return publicDial(ctx, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = original
		transport.CloseIdleConnections()
	})
	project := clientproject.Project{Root: directory, Config: config.TNL{Server: new(setup.controlURL), Services: services}}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	routable := make(chan string, 1)
	options := publisherlocal.Options{Directory: directory, StateDir: state.Root(), Snapshot: bytes.NewReader(snapshot),
		AttachPublication: func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
			cfg.RelayQUIC, cfg.RelayTCP = setup.quic, setup.tcp
			cfg.TransportTLS, cfg.DrainTime = setup.relayTLS.Clone(), time.Second
			onReady := cfg.Ready
			cfg.Ready = func() error {
				if onReady != nil {
					if err := onReady(); err != nil {
						return err
					}
				}
				select {
				case routable <- cfg.ServiceID:
				default:
				}
				return nil
			}
			return nil
		}}
	ownerCtx, stopOwner := context.WithCancel(t.Context())
	ownerDone := make(chan struct{})
	var ownerErr error
	go func() {
		defer close(ownerDone)
		ownerErr = publisherlocal.Serve(ownerCtx, options)
	}()
	stop := sync.OnceFunc(func() {
		stopOwner()
		if err := waitForDoneWithin(ownerDone, 20*time.Second); err != nil {
			t.Error("native framework owner did not join", err)
		} else if ownerErr != nil {
			t.Error("native framework owner", ownerErr)
		}
	})
	t.Cleanup(stop)
	descriptor, err := publisherprotocol.DescriptorPath(state.Root(), directory)
	if err != nil {
		t.Fatal(err)
	}
	var owner publisherprotocol.Endpoint
	privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-ownerDone:
			return false, errors.Join(errors.New("native framework owner stopped before startup"), ownerErr)
		default:
		}
		value, err := publisherprotocol.ReadEndpoint(descriptor)
		if err != nil {
			return false, nil
		}
		owner = value
		return publisherlocal.Available(ctx, owner), nil
	})
	var endpoint publisherprotocol.Endpoint
	web := "web"
	if err := publisherprotocol.Call(t.Context(), owner, http.MethodPost, "/v1/capabilities",
		publisherprotocol.CapabilityRequest{Scope: "app", Service: &web}, &endpoint); err != nil {
		t.Fatal(err)
	}
	endpointDirectory := t.TempDir()
	if err := os.Chmod(endpointDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(endpointDirectory, "endpoint.json")
	if err := publisherprotocol.WriteEndpoint(mounted, endpoint); err != nil {
		t.Fatal(err)
	}
	return frameworkNativeOwner{endpoint: mounted, routable: routable, stop: stop}
}
