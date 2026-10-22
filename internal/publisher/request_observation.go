package publisher

import "net/http"

type responseOriginKey struct{}

// Unwrap lets net/http's response controller retain flushing and upgrades.
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
