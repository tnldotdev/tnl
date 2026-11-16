package httpstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
)

type requestBodyKey struct{}

// Requests owns the incoming body before middleware or ReverseProxy clones the
// request. only time awaiting body reads spends the idle timeout; target writes,
// admission, and response streaming do not. nested forwarding reuses this owner.
func Requests(next http.Handler, timeout time.Duration) http.Handler {
	if timeout == 0 {
		timeout = applicationlimits.DefaultRequestBodyIdleTimeout
	}
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
		body := &requestBody{ReadCloser: r.Body, source: r, remaining: r.ContentLength, timeout: timeout}
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			body.controller = controller
			if r.ProtoMajor == 1 {
				// net/http retains the original body for its post-handler drain.
				// arm that cleanup only after the handler stops consuming it.
				defer body.startCleanup()
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), requestBodyKey{}, body))
		if body.controller != nil {
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
	source     *http.Request
	remaining  int64
	trailers   http.Header
	controller *http.ResponseController
	timeout    time.Duration
	mu         sync.Mutex
	deadline   time.Time
	complete   bool
	cleanup    bool
	closeOnce  sync.Once
	closeErr   error
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if !b.complete && b.deadline.IsZero() {
		b.setDeadline(time.Now().Add(b.timeout))
	}
	b.mu.Unlock()
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
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining > 0 {
		b.remaining -= int64(n)
	}
	if errors.Is(err, io.EOF) || b.remaining == 0 {
		b.complete = true
		b.setDeadline(time.Time{})
	} else if n > 0 && !b.cleanup {
		// reads returning bytes have made progress. pause the timer while the
		// consumer forwards those bytes or waits for target capacity.
		b.setDeadline(time.Time{})
	}
	return n, err
}

func (b *requestBody) setDeadline(deadline time.Time) {
	b.deadline = deadline
	if b.controller != nil {
		_ = b.controller.SetReadDeadline(deadline)
	}
}

func (b *requestBody) startCleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanup = true
	if !b.complete && b.deadline.IsZero() {
		b.setDeadline(time.Now().Add(b.timeout))
	}
}

func (b *requestBody) Close() error {
	b.closeOnce.Do(func() {
		b.startCleanup()
		b.closeErr = b.ReadCloser.Close()
		b.mu.Lock()
		b.complete = true
		b.setDeadline(time.Time{})
		b.mu.Unlock()
	})
	return b.closeErr
}
