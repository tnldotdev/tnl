package inspection

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type responseOriginKey struct{}

// BeginHTTP observes one request without retaining headers, query, or body.
// callers defer finish directly so interrupted handlers remain errors and panic
// propagation is unchanged. transport owners retain handler and stream lifetimes.
func BeginHTTP(w http.ResponseWriter, r *http.Request, mode Mode, observe Observer) (http.ResponseWriter, *http.Request, func()) {
	if observe == nil || mode == None || strings.HasPrefix(r.URL.Path, "/__tnl/") {
		return w, r, func() {}
	}
	started := time.Now()
	original := r
	forwarded := &atomic.Bool{}
	r = r.WithContext(context.WithValue(r.Context(), responseOriginKey{}, forwarded))
	writer := &observedResponseWriter{ResponseWriter: w}
	return writer, r, func() {
		interrupted := recover()
		path := original.URL.EscapedPath()
		if len(path) > 512 {
			path = path[:512]
		}
		origin := "tnl"
		if forwarded.Load() {
			origin = "local_service"
		}
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		result := HTTPResult(status)
		if interrupted != nil || writer.err != nil || original.Context().Err() != nil {
			result = ResultError
		}
		observe(Summary{Protocol: HTTP, ReceivedAt: started.UTC(), Method: original.Method,
			Path: path, Status: status, Result: result, Duration: time.Since(started), Origin: origin})
		if interrupted != nil {
			panic(interrupted)
		}
	}
}

// ApplicationResponse marks an accepted target response, not merely a target
// dial or an authorization decision. a failed proxy response remains tnl-authored.
func ApplicationResponse(r *http.Request) {
	if r == nil {
		return
	}
	if forwarded, ok := r.Context().Value(responseOriginKey{}).(*atomic.Bool); ok {
		forwarded.Store(true)
	}
}

// unwrap lets net/http's response controller retain flushing and upgrades.
type observedResponseWriter struct {
	http.ResponseWriter
	status int
	err    error
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status == 0 && (status >= http.StatusOK || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *observedResponseWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		w.err = err
	}
	return err
}
