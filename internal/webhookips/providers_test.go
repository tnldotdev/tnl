package webhookips

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/httpjson"
)

func TestResolveProviderWebhookLists(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/stripe":
			_, _ = response.Write([]byte(`{"WEBHOOKS":["192.0.2.7","192.0.2.7/32","2001:db8::1/64"]}`))
		case "/github":
			if request.Header.Get("User-Agent") != "tnl" {
				t.Errorf("GitHub user agent = %q", request.Header.Get("User-Agent"))
			}
			_, _ = response.Write([]byte(`{"hooks":["198.51.100.0/24","192.0.2.7/32"],"actions":["0.0.0.0/0"]}`))
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	catalog := map[string]provider{
		"github": {url: server.URL + "/github", field: "hooks"},
		"stripe": {url: server.URL + "/stripe", field: "WEBHOOKS"},
	}
	sources, err := resolve(t.Context(), server.Client(), catalog, []string{"stripe", "github"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Name != "github" || sources[1].Name != "stripe" ||
		!slices.Equal(sources[0].Prefixes, []string{"192.0.2.7/32", "198.51.100.0/24"}) ||
		!slices.Equal(sources[1].Prefixes, []string{"192.0.2.7/32", "2001:db8::/64"}) {
		t.Fatalf("resolved sources = %#v", sources)
	}
}

func TestResolveProviderFailsWithoutCompleteUsableList(t *testing.T) {
	for _, test := range []struct {
		name, body, want string
		status           int
	}{
		{"empty", `{"hooks":[]}`, "no webhook IPs", http.StatusOK},
		{"missing", `{"web":["192.0.2.1"]}`, "no webhook IPs", http.StatusOK},
		{"null", `{"hooks":null}`, "no webhook IPs", http.StatusOK},
		{"invalid address", `{"hooks":["192.0.2.1","not-an-ip"]}`, "invalid IP prefix", http.StatusOK},
		{"public IPv4", `{"hooks":["0.0.0.0/0"]}`, "allowing every IP", http.StatusOK},
		{"public IPv6", `{"hooks":["::/0"]}`, "allowing every IP", http.StatusOK},
		{"invalid JSON", `{"hooks":[`, "invalid JSON", http.StatusOK},
		{"http error", `{}`, "HTTP 503", http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := resolve(t.Context(), server.Client(), map[string]provider{
				"github": {url: server.URL, field: "hooks"},
			}, []string{"github"})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("resolution error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestResolveProviderBoundsAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"hooks":["192.0.2.1"],"other":"` + strings.Repeat("x", maxProviderResponseBytes) + `"}`))
	}))
	defer server.Close()
	catalog := map[string]provider{"github": {url: server.URL, field: "hooks"}}
	if _, err := resolve(t.Context(), server.Client(), catalog, []string{"github"}); !errors.Is(err, httpjson.ErrTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolve(ctx, server.Client(), catalog, []string{"github"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled resolution error = %v", err)
	}
}
