package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceHTTPPhysicalCapacityDiagnostic(t *testing.T) {
	capacity := &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	for _, test := range []struct {
		name string
		err  error
		code diagnostic.Code
	}{
		{"capacity", capacity, diagnostic.RequestLimitReached},
		{"wrapped-capacity", fmt.Errorf("reserve: %w", capacity), diagnostic.RequestLimitReached},
		{"unavailable", errors.New("capacity exchange unavailable"), ""},
		{"mixed-cleanup", errors.Join(capacity, errors.New("independent cleanup failure")), ""},
		{"mixed-cancellation", errors.Join(capacity, context.Canceled), ""},
	} {
		for _, h2 := range []bool{false, true} {
			for _, inline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/h2=%t/inline=%t", test.name, h2, inline), func(t *testing.T) {
					var attempts, forwarded atomic.Int32
					client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						forwarded.Add(1)
						w.WriteHeader(http.StatusNoContent)
					}), h2, inline, func(frontend *HTTP) {
						var err error
						frontend.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1)})
						if err != nil {
							t.Fatal(err)
						}
						frontend.ReserveCapacity = func(context.Context) error {
							attempts.Add(1)
							return test.err
						}
					})
					for range 2 {
						request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
						response, err := client.Do(request)
						if err != nil {
							t.Fatal(err)
						}
						_, readErr := io.Copy(io.Discard, response.Body)
						closeErr := response.Body.Close()
						if err := errors.Join(readErr, closeErr); err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != http.StatusServiceUnavailable ||
							response.Header.Get("Tnl-Error-Code") != string(test.code) ||
							response.ProtoMajor == 2 != h2 || response.Close == h2 {
							t.Fatal("physical capacity changed its diagnostic or protocol-specific closure",
								response.StatusCode, response.Header.Get("Tnl-Error-Code"), response.ProtoMajor, response.Close)
						}
					}
					if attempts.Load() != 2 || forwarded.Load() != 0 {
						t.Fatal("capacity refusal spent the request budget or reached the target", attempts.Load(), forwarded.Load())
					}
				})
			}
		}
	}
}
