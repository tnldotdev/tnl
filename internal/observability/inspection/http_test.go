package inspection

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPObservationCapturesOnlySummaryAndResponseOrigin(t *testing.T) {
	for _, mode := range []Mode{"", None, SummaryMode} {
		for _, status := range []int{http.StatusNoContent, http.StatusBadRequest, http.StatusInternalServerError} {
			for _, application := range []bool{false, true} {
				var events []Summary
				request := httptest.NewRequest(http.MethodPost, "/"+strings.Repeat("p", 600)+"?token=secret-query", strings.NewReader("secret-body"))
				request.Header.Set("Authorization", "secret-credential")
				response := httptest.NewRecorder()
				func() {
					w, r, finish := BeginHTTP(response, request, mode, func(event Summary) { events = append(events, event) })
					defer finish()
					if application {
						ApplicationResponse(r)
					}
					w.WriteHeader(http.StatusEarlyHints)
					w.WriteHeader(status)
				}()
				if mode == None {
					if len(events) != 0 {
						t.Fatal("disabled inspection emitted a summary")
					}
					continue
				}
				if len(events) != 1 {
					t.Fatal("request did not emit exactly one summary", len(events))
				}
				event := events[0]
				origin := "tnl"
				if application {
					origin = "local_service"
				}
				if event.Protocol != HTTP || event.Status != status || event.Method != http.MethodPost || event.Origin != origin ||
					event.Result != HTTPResult(status) || event.Path != "/"+strings.Repeat("p", 511) ||
					event.ReceivedAt.IsZero() || event.Duration < 0 || event.Duration > time.Minute {
					t.Fatal("summary retained unsafe data or lost the response facts", event)
				}
			}
		}
	}
}

type inspectionControllerWriter struct {
	http.ResponseWriter
	err error
}

func (w inspectionControllerWriter) FlushError() error { return w.err }
func (w inspectionControllerWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, w.err
}
func (w inspectionControllerWriter) Write([]byte) (int, error) { return 0, w.err }

func TestHTTPObservationPreservesControllerErrorsAndInterruptedHandlers(t *testing.T) {
	for _, boundary := range []string{"flush", "write", "hijack", "cancel", "panic"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/request", nil)
			failure := errors.New("response interrupted")
			var event Summary
			func() {
				defer func() {
					interrupted := recover()
					if boundary == "panic" && interrupted != failure || boundary != "panic" && interrupted != nil {
						t.Fatal("observation changed panic propagation", interrupted)
					}
				}()
				w, _, finish := BeginHTTP(inspectionControllerWriter{ResponseWriter: httptest.NewRecorder(), err: failure}, request, SummaryMode, func(value Summary) { event = value })
				defer finish()
				switch boundary {
				case "flush":
					if err := http.NewResponseController(w).Flush(); !errors.Is(err, failure) {
						t.Fatal("observation hid flush error", err)
					}
				case "write":
					if _, err := io.WriteString(w, "response"); !errors.Is(err, failure) {
						t.Fatal("observation hid write error", err)
					}
				case "hijack":
					if _, _, err := http.NewResponseController(w).Hijack(); !errors.Is(err, failure) {
						t.Fatal("observation hid hijack capability", err)
					}
				case "cancel":
					cancel()
				case "panic":
					panic(failure)
				}
			}()
			if event.Status != http.StatusOK || event.Origin != "tnl" || boundary != "hijack" && event.Result != ResultError {
				t.Fatal("interrupted response had a successful summary", event)
			}
		})
	}
}

func TestHTTPObservationExcludesPreparationAndDisabledCallbacks(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/__tnl/team/handoff/secret", nil)
	response := httptest.NewRecorder()
	w, r, finish := BeginHTTP(response, request, SummaryMode, func(Summary) { t.Error("preparation was inspected") })
	defer finish()
	if w != response || r != request {
		t.Fatal("preparation acquired inspection state")
	}
	w, r, finishDisabled := BeginHTTP(response, request, None, nil)
	defer finishDisabled()
	if w != response || r != request {
		t.Fatal("disabled inspection changed the request")
	}
}
