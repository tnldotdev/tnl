// Package benchworkload contains the publisher and visitor workloads shared by
// local runtime tests and staging benchmarks. Runners own setup and cleanup.
package benchworkload

import (
	"io"
	"net/http"
	"strconv"
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
		if r.URL.Path == bandwidthPath {
			serveBandwidth(w, r)
			return
		}
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

func serveBandwidth(w http.ResponseWriter, r *http.Request) {
	direction := r.Header.Get(bandwidthDirectionHeader)
	if direction != BandwidthDownstream && direction != BandwidthUpstream {
		http.Error(w, "invalid bandwidth direction", http.StatusBadRequest)
		return
	}
	rate, rateErr := strconv.ParseInt(r.Header.Get(bandwidthRateHeader), 10, 64)
	durationValue, durationErr := strconv.ParseInt(r.Header.Get(bandwidthDurationHeader), 10, 64)
	duration := time.Duration(durationValue)
	if rateErr != nil || rate < 1 || rate > maxBandwidthStreamRate || durationErr != nil || duration <= 0 || duration > bandwidthSegmentDuration {
		http.Error(w, "invalid bandwidth rate or duration", http.StatusBadRequest)
		return
	}
	expected := bytesForDuration(rate, duration)
	if direction == BandwidthUpstream {
		if r.Method != http.MethodPost || r.ContentLength != expected {
			http.Error(w, "invalid bandwidth upload", http.StatusBadRequest)
			return
		}
		verifier := payloadVerifier{}
		if _, err := io.Copy(&verifier, r.Body); err != nil || verifier.Bytes() != expected {
			http.Error(w, "invalid bandwidth payload", http.StatusBadRequest)
			return
		}
		w.Header().Set(bandwidthBytesHeader, strconv.FormatInt(verifier.Bytes(), 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "invalid bandwidth download", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(expected, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, newPacedPayloadReader(r.Context(), rate, expected))
}
