package observability

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/tnldotdev/tnl/internal/failure"
)

// classify known target trust failures at the TLS leg even when net/http calls
// its handshake observer with the raw crypto/tls error. retain the original cause.
func publisherTargetTLSError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := failure.ReasonOf(err); ok {
		return err
	}
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	if errors.As(err, &certificate) || errors.As(err, &record) {
		return failure.Wrap("observe target TLS", failure.TargetTLSRejected, err)
	}
	return err
}

// TargetRequest observes the standard transport's TLS handshake locally. it
// never extracts or injects propagation headers on customer HTTP requests.
func TargetRequest(request *http.Request) *http.Request {
	if FromContext(request.Context()) == nil {
		return request
	}
	var mu sync.Mutex
	tlsCtx := request.Context()
	finish := func(error) {}
	observer := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			mu.Lock()
			defer mu.Unlock()
			tlsCtx, finish = PublisherOperation(request.Context(), "target_tls")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			PublisherTLS(tlsCtx, "target", state, err)
			finish(err)
		},
	}
	return request.WithContext(httptrace.WithClientTrace(request.Context(), observer))
}
