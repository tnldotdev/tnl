// Package benchworkload contains the publisher and visitor workloads shared by
// local runtime tests and deployed benchmarks. Runners own infrastructure.
package benchworkload

import (
	"io"
	"net/http"
	"time"
)

func Payload(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i)
	}
	return body
}

func Origin(size int) http.Handler {
	body := Payload(size)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TNL-Bench-Host", r.Host)
		if r.URL.Path != "/hold" {
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		controller := http.NewResponseController(w)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := io.WriteString(w, "tick\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
}
