package service

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPInlineApplicationKeepsPolicyAndReservedPaths(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			calls := make(chan struct{}, 8)
			client, _, _, token := serviceHTTPApplicationFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls <- struct{}{}
				if r.Host != "preview.example.test" || r.TLS == nil || r.TLS.ServerName != r.Host || r.RemoteAddr != "192.0.2.1:1" ||
					r.Header.Get(httpaccess.VisitorTokenHeader) != "" || r.Header.Get("Authorization") != "application-secret" {
					t.Error("inline application lost admitted request facts or received visitor credentials")
				}
				_, _ = io.WriteString(w, "inline")
			}), h2, true)
			for _, test := range []struct {
				path       string
				credential bool
				status     int
			}{
				{"/", false, http.StatusForbidden},
				{"/__tnl/unknown", true, http.StatusNotFound},
				{"/callback", true, http.StatusOK},
			} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+test.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if test.credential {
					request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				}
				request.Header.Set("Authorization", "application-secret")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != test.status || test.status == http.StatusOK && string(body) != "inline" {
					t.Fatal("inline HTTP response changed", response.Status, string(body), err)
				}
				if h2 && response.ProtoMajor != 2 {
					t.Fatal("inline handler lost negotiated HTTP/2", response.Proto)
				}
			}
			if len(calls) != 1 {
				t.Fatal("inline application bypassed policy or reserved paths", len(calls))
			}
		})
	}
}

func TestServiceHTTPInlinePreparationDoesNotRequireDummyTarget(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	preparation := control.prep
	approved, err := control.GetPublisherService(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
	cfg.Target = ""
	cfg.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	prepared, err := newManagedPrepared(preparation, approved, cfg)
	if err != nil || prepared.target != "" || prepared.handler == nil {
		t.Fatal("inline service required a target proxy or another listener", err)
	}
	cfg.Target = "localhost:3000"
	if _, err := newManagedPrepared(preparation, approved, cfg); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("inline service silently selected between target modes", err)
	}
	cfg.Target = ""
	approved.Protocol, approved.Endpoint.Port = controlv1.Tcp, 0
	if _, err := newManagedPrepared(preparation, approved, cfg); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("non-HTTP service accepted an HTTP handler", err)
	}
}
