//go:build js && wasm

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// experimental ABI: globalThis.tnlConnectorWasm.prepare(options, host, signal?)
// resolves to {open(): Promise<stream>, close(): Promise<void>}. each stream has
// read(max): Promise<Uint8Array|null>, write(Uint8Array): Promise<void>,
// startTls(): Promise<void>, and close(): Promise<void>. startTls sends postgres
// SSLRequest, requires S and verifies visitor TLS before startup/auth bytes.
// host.dialTCP(address, signal?) resolves to a byte socket with read/write/close.
// closing a socket must settle pending I/O; AbortSignal cancels acquisition.
// ca_pem trusts local control, relay and service certificates; optional separate
// roots override that pool. the unchanged workload.Client owns all exchange,
// validation, signing, renewal and service requests. native provider acquisition
// and identity refresh are outside this fixed-assertion experiment.
type options struct {
	ControlURL        string   `json:"control_url"`
	TeamID            string   `json:"team_id"`
	ProjectKey        string   `json:"project_key"`
	SourceFingerprint string   `json:"source_fingerprint"`
	Workload          string   `json:"workload"`
	Assertion         string   `json:"assertion"`
	ServiceID         string   `json:"service_id"`
	Services          []string `json:"services,omitempty"`
	CAPEM             string   `json:"ca_pem"`
	RelayCAPEM        string   `json:"relay_ca_pem"`
	ServiceCAPEM      string   `json:"service_ca_pem"`
	ReuseBuffers      bool     `json:"bridge_reuse_buffers"`
	CompactPromises   bool     `json:"bridge_compact_promises"`
}

type backend struct {
	cancel    context.CancelCauseFunc
	client    *workload.Client
	transport *http.Transport
	workers   sync.WaitGroup
	once      sync.Once
	closeMu   sync.Mutex
	exchanged bool
	revoked   bool
}

type prepared struct {
	backend         *backend
	session         *connectorstream.Session
	trust           *tls.Config
	hostname        string
	protocol        string
	reuseBuffers    bool
	compactPromises bool
}

func roots(pem string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("connector WASM: ca_pem must contain trusted certificates")
	}
	return pool, nil
}

func prepare(ctx context.Context, o options, dial func(context.Context, string, string) (net.Conn, error)) (_ *prepared, result error) {
	pool, err := roots(o.CAPEM)
	if err != nil {
		return nil, err
	}
	trust := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	trust.VerifyConnection = func(state tls.ConnectionState) error { observeTLS("control", state); return nil }
	transport := &http.Transport{DialContext: dial, TLSClientConfig: trust, ForceAttemptHTTP2: false}
	client, err := workload.New(o.ControlURL, &http.Client{Transport: transport})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	life, cancel := context.WithCancelCause(ctx)
	b := &backend{cancel: cancel, client: client, transport: transport}
	defer func() {
		if result != nil {
			result = errors.Join(result, b.close())
		}
	}()
	setup, stop := context.WithTimeout(life, 30*time.Second)
	defer stop()
	if _, err := client.Exchange(setup, o.TeamID, o.ProjectKey, o.SourceFingerprint, o.Workload, o.Assertion, o.Services); err != nil {
		return nil, err
	}
	b.exchanged = true
	b.workers.Go(func() { cancel(client.Maintain(life)) })
	control, err := connectorstream.NewWorkloadControl(client)
	if err != nil {
		return nil, err
	}
	run, err := control.ResolveService(setup, o.ServiceID)
	if err != nil {
		return nil, err
	}
	relayTrust, serviceTrust := trust.Clone(), trust.Clone()
	relayTrust.VerifyConnection = func(state tls.ConnectionState) error { observeTLS("relay", state); return nil }
	serviceTrust.VerifyConnection = func(state tls.ConnectionState) error { observeTLS("visitor", state); return nil }
	if o.RelayCAPEM != "" {
		relayTrust.RootCAs, err = roots(o.RelayCAPEM)
		if err != nil {
			return nil, err
		}
	}
	if o.ServiceCAPEM != "" {
		serviceTrust.RootCAs, err = roots(o.ServiceCAPEM)
		if err != nil {
			return nil, err
		}
	}
	// byte hosts have no outer UDP socket. the actual inner quic-go connection
	// remains on peer.Endpoint over the two real TLS/yamux relay carriers.
	session, err := connectorstream.Prepare(life, connectorstream.Config{Control: control, ServiceID: o.ServiceID, Protocol: run.Protocol, TrustRevision: run.TrustRevision, Endpoint: run.Endpoint,
		ServiceTLS: serviceTrust, TransportTLS: relayTrust, RelayQUIC: noHostUDP{}, RelayTCP: muxsession.TLSYamuxConnector{TLSConfig: relayTrust, Config: muxsession.TLSYamuxConfig{Dialer: &byteDialer{dial: dial}}}})
	if err != nil {
		return nil, err
	}
	negotiated["inner-quic"] = tls.CipherSuiteName(session.InnerCipherSuite())
	return &prepared{backend: b, session: session, trust: serviceTrust, hostname: run.Endpoint.Hostname, protocol: run.Protocol, reuseBuffers: o.ReuseBuffers, compactPromises: o.CompactPromises}, nil
}

type noHostUDP struct{}

// the pointer preserves transport connector comparability while retaining a
// per-preparation byte host; TLS and yamux remain owned by muxsession.
type byteDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d *byteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func (noHostUDP) Connect(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
	return nil, errors.New("connector WASM: host provides TCP only")
}

func (b *backend) close() error {
	b.once.Do(func() { b.cancel(context.Canceled); b.workers.Wait() })
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	defer b.transport.CloseIdleConnections()
	if !b.exchanged || b.revoked {
		return nil
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	err := b.client.Revoke(ctx)
	if err == nil || errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrNotFound) {
		b.revoked = true
		return nil
	}
	// retain the client after an uncertain reply. a later handle.close retries
	// revocation after the transport workers have already joined.
	return err
}
