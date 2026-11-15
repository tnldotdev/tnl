package publishingtest

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"
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
	stream, err := f.backend.OpenHTTPVisitor(ctx, service, netip.MustParseAddrPort("127.0.0.1:45123"), netip.MustParseAddrPort("127.0.0.1:443"))
	if err != nil {
		return 0, nil, nil, err
	}
	defer stream.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
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
