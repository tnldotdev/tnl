package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type sourceForwardingControl struct{ *lifecycleControl }

func (c sourceForwardingControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if request.AfterRevision != 0 {
		// updates in these tests enter through the real policy owner below.
		// a background reply must not overwrite that explicitly observed update.
		<-ctx.Done()
		return controlv1.VisitorPolicyUpdate{}, ctx.Err()
	}
	update, err := c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.Anonymous = true
	update.Policy.PublicEndpoint = &controlv1.VisitorPublicEndpoint{Hostname: c.prep.Hostname, Port: 443, EndpointRevision: 1}
	return update, err
}

type sourceForwardingFixture struct {
	prepared     *Prepared
	bound        *Bound
	verification *tls.Config
	header       tunnelv1.ServiceForwardingHeader
	metadata     []byte
	update       visitorlease.Update
	delivered    atomic.Int32
	capacity     atomic.Int32
}

func newSourceForwardingFixture(t *testing.T) *sourceForwardingFixture {
	t.Helper()
	f := &sourceForwardingFixture{}
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port, approved.Endpoint.Public = controlv1.ServiceProtocolHTTP, 443, true
	control.approved = &approved
	cfg.Target = ""
	cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.delivered.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "one delivery" || r.Header.Get("Authorization") != "Bearer application-secret" {
			t.Error("source admission changed application bytes or authentication", string(body), err)
		}
		if r.RemoteAddr != "192.0.2.10:40000" {
			t.Error("source admission lost the accepted socket address", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f.prepared, err = newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	certificate, verification := managedTestCertificate(t, approved.Endpoint.Hostname)
	f.verification = verification
	if err := f.prepared.installManagedCertificate(certificate); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (sourceForwardingControl{control}).ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{
		Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: control.prep.ServiceId},
		RunId:    control.prep.ServiceRunId, RunNumber: control.prep.RunNumber,
	}, control.setup.RunToken)
	if err != nil {
		t.Fatal(err)
	}
	f.update, err = visitorlease.Decode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_, closeRun, err := configureServiceRun(t.Context(), cfg, f.prepared, control.setup, sourceForwardingControl{control}, cfg.State, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeRun(); err != nil {
			t.Error("close source forwarding owner", err)
		}
	})
	f.bound, err = f.prepared.Activate(control.setup)
	if err != nil {
		t.Fatal(err)
	}
	f.header = privateHeader(t, f.prepared.connectionRef(f.bound.connections[0]))
	f.header.PublicService.DestinationPort = 443
	f.metadata = publicSourceMetadata(t, f.prepared, f.header)
	return f
}

func (f *sourceForwardingFixture) opening(t *testing.T, slot int, header tunnelv1.ServiceForwardingHeader, metadata []byte) (net.Conn, <-chan error) {
	t.Helper()
	ref := f.prepared.connectionRef(f.bound.connections[slot])
	header.PublisherConnectionID, header.ConnectionSlot = ref.PublisherConnectionID, ref.ConnectionSlot
	header.ConnectionAssignmentRevision, header.RelayServiceID = ref.ConnectionAssignmentRevision, ref.RelayServiceID
	client, server := net.Pipe()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer server.Close()
		done <- f.bound.serveBody(t.Context(), ref, server, header, nil, func(context.Context) error {
			f.capacity.Add(1)
			return nil
		}, nil)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("source forwarding worker outlived its owner")
		}
	})
	if _, err := client.Write(metadata); err != nil {
		t.Fatal("write signed source metadata", err)
	}
	return client, done
}

func sourceForwardingJoined(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("source forwarding did not join")
		return nil
	}
}

func (f *sourceForwardingFixture) request(t *testing.T, slot int) {
	t.Helper()
	raw, done := f.opening(t, slot, f.header, f.metadata)
	secure := tls.Client(raw, f.verification)
	if err := secure.HandshakeContext(t.Context()); err != nil {
		t.Fatal("verified visitor TLS", err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+f.prepared.managedHostname+"/", strings.NewReader("one delivery"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer application-secret")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Close = true
	if err := request.Write(secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusNoContent || readErr != nil || closeErr != nil {
		t.Fatal("source forwarding changed the response", response.Status, readErr, closeErr)
	}
	_ = raw.Close()
	_ = sourceForwardingJoined(t, done)
}

func TestPublicSourceMetadataOnlyFallbackAndLateByteReplay(t *testing.T) {
	for _, lateByte := range []bool{false, true} {
		t.Run(map[bool]string{false: "closed metadata-only path", true: "late visitor byte"}[lateByte], func(t *testing.T) {
			f := newSourceForwardingFixture(t)
			first, firstDone := f.opening(t, 0, f.header, f.metadata)
			if !lateByte {
				_ = first.Close()
				if err := sourceForwardingJoined(t, firstDone); err == nil {
					t.Fatal("metadata-only path was treated as a complete visitor")
				}
			}
			if f.delivered.Load() != 0 || f.capacity.Load() != 0 {
				t.Fatal("source metadata alone delivered or reserved application work")
			}
			f.request(t, 1)
			if lateByte {
				if _, err := first.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				if err := sourceForwardingJoined(t, firstDone); !errors.Is(err, errSourceProofReplay) {
					t.Fatal("late first byte reused the successful fallback's proof", err)
				}
			}
			replayed, replayDone := f.opening(t, 0, f.header, f.metadata)
			if _, err := replayed.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			if err := sourceForwardingJoined(t, replayDone); !errors.Is(err, errSourceProofReplay) {
				t.Fatal("visitor release cleared the run's source replay evidence", err)
			}
			if f.delivered.Load() != 1 || f.capacity.Load() != 1 {
				t.Fatal("fallback or replay duplicated application delivery or capacity", f.delivered.Load(), f.capacity.Load())
			}
		})
	}
}

func TestPublicSourceMutationDoesNotConsumeValidEvidence(t *testing.T) {
	for _, mutation := range []string{"source address", "source port", "destination", "signature"} {
		t.Run(mutation, func(t *testing.T) {
			f := newSourceForwardingFixture(t)
			metadata, _, err := proxyproto.Decode(bytes.NewReader(f.metadata))
			if err != nil {
				t.Fatal(err)
			}
			header := f.header
			switch mutation {
			case "source address":
				metadata.Source = netip.MustParseAddrPort("198.51.100.7:40000")
				header.SourceIP = metadata.Source.Addr().String()
			case "source port":
				metadata.Source = netip.MustParseAddrPort("192.0.2.10:40001")
			case "destination":
				metadata.Destination = netip.MustParseAddrPort("203.0.113.2:443")
			case "signature":
				proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
				if err != nil {
					t.Fatal(err)
				}
				proof.MAC[0] ^= 1
				wire, err := proof.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				metadata.VisitorSourceProof = string(wire)
			}
			wire, err := proxyproto.Encode(metadata)
			if err != nil {
				t.Fatal(err)
			}
			raw, done := f.opening(t, 0, header, wire)
			if _, err := raw.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			if err := sourceForwardingJoined(t, done); !errors.Is(err, visitortoken.ErrVisitorSource) {
				t.Fatal("mutated accepted-source facts were not rejected", err)
			}
			f.request(t, 1)
			if f.delivered.Load() != 1 || f.capacity.Load() != 1 {
				t.Fatal("invalid evidence spent the valid fallback or reached the application")
			}
		})
	}
}

func TestPublicSourcePolicyChangesFenceAdmittedSocket(t *testing.T) {
	for _, change := range []string{"disabled", "source excluded", "endpoint replaced"} {
		t.Run(change, func(t *testing.T) {
			f := newSourceForwardingFixture(t)
			raw, done := f.opening(t, 0, f.header, f.metadata)
			secure := tls.Client(raw, f.verification)
			if err := secure.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			update := f.update
			update.View.VisitorPolicyRevision++
			now := time.Now()
			update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
			switch change {
			case "disabled":
				update.Enabled = false
			case "source excluded":
				key := [32]byte{1}
				entry, err := ippolicy.Hash(key, netip.MustParsePrefix("203.0.113.0/24"))
				if err != nil {
					t.Fatal(err)
				}
				policy, err := ippolicy.New(key, []ippolicy.Entry{entry})
				if err != nil {
					t.Fatal(err)
				}
				update.IP = &policy
			case "endpoint replaced":
				endpoint := *update.PublicEndpoint
				endpoint.EndpointRevision++
				update.PublicEndpoint = &endpoint
			}
			if err := f.prepared.policy.Apply(f.prepared.policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
			_ = sourceForwardingJoined(t, done)
			if f.delivered.Load() != 0 || f.capacity.Load() != 0 {
				t.Fatal("changed source policy admitted application work")
			}
		})
	}
}
