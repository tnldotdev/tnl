package observability

import (
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"sync"
)

// TargetRequest observes the standard transport's TLS handshake locally. it
// never extracts or injects propagation headers on customer HTTP requests.
func TargetRequest(request *http.Request) *http.Request {
	if FromContext(request.Context()) == nil {
		return request
	}
	var mu sync.Mutex
	finish := func(error) {}
	observer := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			mu.Lock()
			defer mu.Unlock()
			_, finish = PublisherOperation(request.Context(), "target_tls")
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			finish(err)
		},
	}
	return request.WithContext(httptrace.WithClientTrace(request.Context(), observer))
}
