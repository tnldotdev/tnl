package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
)

func TestServiceHTTPInspectionRecordsTruncatedTargetResponse(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			summaries := make(chan inspection.Summary, 1)
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				connection, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n")
				if err := buffered.Flush(); err != nil {
					t.Error(err)
				}
			}), h2, false, func(frontend *HTTP) {
				frontend.InspectionMode = inspection.SummaryMode
				frontend.ObserveSummary = func(summary inspection.Summary) { summaries <- summary }
			})
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/truncated?private=query", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("visitor did not receive the target headers", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || string(body) != "part" || response.StatusCode != http.StatusOK {
				t.Fatal("truncated target response completed or stalled", string(body), err)
			}
			select {
			case summary := <-summaries:
				if summary.Status != http.StatusOK || summary.Result != inspection.ResultError || summary.Origin != "local_service" || summary.Path != "/truncated" {
					t.Fatal("truncated response was inspected as successful", summary)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("truncated response did not emit a summary")
			}
		})
	}
}

func TestServiceHTTPInspectionSeparatesPolicyAndTargetResponses(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			summaries := make(chan inspection.Summary, 4)
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "application-secret" {
					t.Error("inspection changed application credentials")
				}
				status := http.StatusNoContent
				if r.URL.Path == "/broken" {
					status = http.StatusInternalServerError
				}
				w.WriteHeader(status)
			}), h2, false, func(frontend *HTTP) {
				frontend.InspectionMode = inspection.SummaryMode
				frontend.ObserveSummary = func(summary inspection.Summary) { summaries <- summary }
			})
			for _, test := range []struct {
				path, observedPath, origin string
				credential                 bool
				status                     int
			}{
				{"/private?token=secret-query", "/private", "tnl", false, http.StatusForbidden},
				{"/ok?token=secret-query", "/ok", "local_service", true, http.StatusNoContent},
				{"/broken", "/broken", "local_service", true, http.StatusInternalServerError},
			} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+test.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "application-secret")
				if test.credential {
					request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != test.status {
					t.Fatal("inspection changed the HTTP response", response.Status)
				}
				select {
				case summary := <-summaries:
					if summary.Protocol != inspection.HTTP || summary.Origin != test.origin || summary.Path != test.observedPath ||
						summary.Method != http.MethodGet || summary.Status != test.status || summary.Result != inspection.HTTPResult(test.status) ||
						summary.ReceivedAt.IsZero() || summary.Duration < 0 || summary.Duration > time.Minute {
						t.Fatal("inspection lost request facts or retained query data", summary)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("service HTTP did not emit its request summary")
				}
			}
		})
	}
}
