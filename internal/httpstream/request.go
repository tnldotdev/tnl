package httpstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"
)

// RequestBodyTimeout bounds upload completion, including a trickling body.
// response streams and upgraded connections have no total lifetime limit here.
const RequestBodyTimeout = 30 * time.Second

type requestBodyKey struct{}

// Requests owns the incoming body before middleware or ReverseProxy clones the
// request. nested forwarding handlers reuse that owner and its original budget.
func Requests(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(requestBodyKey{}).(*requestBody); ok {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		if r.ProtoMajor == 1 {
			// otherwise net/http drains the upload before flushing a response,
			// deadlocking clients that wait for the response before sending more.
			_ = controller.EnableFullDuplex()
		}
		body := &requestBody{ReadCloser: r.Body, source: r, remaining: r.ContentLength}
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			_ = controller.SetReadDeadline(time.Now().Add(timeout))
			body.clearDeadline = func() { _ = controller.SetReadDeadline(time.Time{}) }
		}
		r = r.WithContext(context.WithValue(r.Context(), requestBodyKey{}, body))
		if body.clearDeadline != nil {
			r.Body = body
		}
		next.ServeHTTP(w, r)
	})
}

// ForwardTrailers binds the transport's independent trailer map to the original
// body's EOF. request clones only contain the trailer names until then; sharing
// their maps loses values or races header validation with incoming body reads.
func ForwardTrailers(in, out *http.Request) {
	if body, ok := in.Context().Value(requestBodyKey{}).(*requestBody); ok && out.Body != nil {
		out.Trailer = make(http.Header, len(body.source.Trailer))
		for key := range body.source.Trailer {
			out.Trailer[key] = nil
		}
		body.trailers = out.Trailer
	}
}

type requestBody struct {
	io.ReadCloser
	source        *http.Request
	remaining     int64
	trailers      http.Header
	clearDeadline func()
	once          sync.Once
}

func (b *requestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		// only this read owns completed incoming trailers. publish their values
		// before the transport sees EOF and writes its final chunk.
		if b.trailers != nil {
			for key, values := range b.source.Trailer {
				b.trailers[key] = slices.Clone(values)
			}
		}
	}
	if b.remaining > 0 {
		b.remaining -= int64(n)
	}
	if errors.Is(err, io.EOF) || b.remaining == 0 {
		b.finish()
	}
	return n, err
}

func (b *requestBody) finish() {
	// an incomplete or failed upload keeps its deadline, including net/http's
	// cleanup of an unread HTTP/1 body after an early final response.
	b.once.Do(func() {
		if b.clearDeadline != nil {
			b.clearDeadline()
		}
	})
}
