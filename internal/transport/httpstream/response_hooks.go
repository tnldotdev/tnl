package httpstream

import (
	"context"
	"net/http"
	"net/http/httputil"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

// ResponseHooks separates header observation from optional body modification.
// callbacks are shared by a run and may run concurrently.
type ResponseHooks struct {
	ModifyHTML    func(*http.Response) error
	Observe       func(*http.Response) error
	ObserveStatus func(*http.Request, int)
}

type visitorHostKey struct{}

// WithVisitorHost supplies an authority already checked by the HTTP owner.
// connector owners use the admitted service hostname, not a loopback Host header.
func WithVisitorHost(request *http.Request, hostname string) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), visitorHostKey{}, hostname))
}

// Rewrite retains the admitted visitor authority for response observers without
// changing the upstream URL, Host header, dial destination, or target TLS.
func (h ResponseHooks) Rewrite(request *httputil.ProxyRequest) {
	host, ok := request.In.Context().Value(visitorHostKey{}).(string)
	if !ok {
		host = request.In.Host
	}
	request.Out = WithVisitorHost(request.Out, host)
	if h.ModifyHTML != nil && !IsReadinessProbe(request.In) {
		request.Out.Header.Del("Accept-Encoding")
	}
	request.Out.Header.Del(ReadinessProbeHeader)
}

// ModifyResponse runs before upstream headers escape. only HTML modification
// may read the body; readiness still runs header observers.
func (h ResponseHooks) ModifyResponse(response *http.Response) error {
	upstream := response.Request
	if host, ok := upstream.Context().Value(visitorHostKey{}).(string); ok {
		// observers see the visitor authority, but the request sent to the target
		// and its URL retain their selected upstream identity.
		request := upstream.Clone(upstream.Context())
		request.Host = host
		response.Request = request
		defer func() { response.Request = upstream }()
	}
	if h.ObserveStatus != nil && response.StatusCode >= 400 {
		h.ObserveStatus(response.Request, response.StatusCode)
	}
	if h.Observe != nil {
		if err := h.Observe(response); err != nil {
			return err
		}
	}
	if h.ModifyHTML != nil && !IsReadinessProbe(response.Request) {
		if err := h.ModifyHTML(response); err != nil {
			return err
		}
	}
	inspection.ApplicationResponse(response.Request)
	observability.PublisherHTTPResponse(response.Request.Context())
	observability.PublisherHTTPUpgrade(response)
	return nil
}

func (h ResponseHooks) ForwardingFailed(request *http.Request) {
	if h.ObserveStatus != nil {
		h.ObserveStatus(request, 0)
	}
}
