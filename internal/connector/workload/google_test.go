package workload

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
)

type googleTransport func(*http.Request) (*http.Response, error)

func (f googleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoogleMetadataAcquisition(t *testing.T) {
	for _, test := range []struct {
		name, body, flavor string
		status             int
		valid              bool
	}{
		{"identity", "signed.jwt.token", "Google", 200, true},
		{"missing flavor", "signed.jwt.token", "", 200, false},
		{"redirect", "signed.jwt.token", "Google", 302, false},
		{"denied", "signed.jwt.token", "Google", 403, false},
		{"empty", "", "Google", 200, false},
		{"oversized", strings.Repeat("x", (32<<10)+1), "Google", 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := googleTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != "metadata.google.internal" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" || r.URL.Query().Get("audience") != "https://control.example/a&b=c" || r.URL.Query().Get("format") != "full" || r.Header.Get("Metadata-Flavor") != "Google" || r.Header.Get("Authorization") != "" {
					t.Fatal("metadata request changed")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Metadata-Flavor": {test.flavor}, "Location": {"https://elsewhere.example"}}, Body: io.NopCloser(strings.NewReader(test.body)), Request: r}, nil
			})
			token, err := googleAssertion(t.Context(), "https://control.example/a&b=c", transport)
			if calls != 1 || test.valid && (err != nil || token != test.body) || !test.valid && !errors.Is(err, ErrAssertionUnavailable) {
				t.Fatal("incorrect acquisition result", calls, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := googleAssertion(ctx, "tnl", googleTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }))
	if !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("canceled acquisition succeeded", err)
	}
	source := workloadmanifest.Acquisition{Method: "google-metadata", Audience: "https://control.example"}
	if RefreshSource(t.TempDir(), source, func(string) string { t.Fatal("metadata refresh read environment"); return "" }) == nil {
		t.Fatal("metadata source cannot refresh independently")
	}
	source.TokenEnv = "STATIC_GOOGLE_TOKEN"
	if ValidateRefreshSource(source) == nil {
		t.Fatal("metadata refresh retained an environment credential")
	}
}
