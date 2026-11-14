package publishingtest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// visit sends no visitor credential. restricted service tests must explicitly
// obtain owner, token, or browser permission and use VisitWithHeaders.
func (f *Fixture) Visit(ctx context.Context, address string) (int, []byte, error) {
	status, _, body, err := f.VisitWithHeaders(ctx, address, nil)
	return status, body, err
}

func (f *Fixture) VisitWithHeaders(ctx context.Context, address string, headers http.Header) (int, http.Header, []byte, error) {
	u, err := url.Parse(address)
	if err != nil {
		return 0, nil, nil, err
	}
	f.mu.Lock()
	var service string
	for id := range f.seenRuns {
		run, found := f.backend.Run(id)
		if found && run.Service.Endpoint.Hostname == u.Hostname() {
			service = run.Service.Id
			break
		}
	}
	f.mu.Unlock()
	session, ref, found := f.backend.Connection(service)
	if !found {
		return 0, nil, nil, errors.New("service publisher connection is not ready")
	}
	run, found := f.backend.Run(ref.ServiceRunID)
	if !found {
		return 0, nil, nil, errors.New("service run has stopped")
	}
	slot := run.Setup.PublisherConnections[ref.ConnectionSlot]
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber, PublisherConnectionID: ref.PublisherConnectionID,
		ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision, VisitorConnectionID: id(f.t, opaqueid.VisitorConnectionPrefix), SourceIP: "127.0.0.1", ExpiresAt: time.Now().Add(10 * time.Second),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "fixture-ingress", IngressRunID: id(f.t, opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 443}},
		ConnectionSlot: ref.ConnectionSlot, RelayServiceID: slot.RelayServiceId, RelayID: "fixture-relay", RelayRunID: id(f.t, opaqueid.RelayRunPrefix),
		RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	stream, err := session.OpenServiceForwardingStream(ctx, header)
	if err != nil {
		return 0, nil, nil, err
	}
	defer stream.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("127.0.0.1:45123"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		return 0, nil, nil, err
	}
	if _, err := stream.Write(metadata); err != nil {
		return 0, nil, nil, err
	}
	connection := tls.Client(stream, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname()})
	defer connection.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header, request.Close = headers.Clone(), true
	if err := request.Write(connection); err != nil {
		return 0, nil, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, response.Header.Clone(), body, err
}
