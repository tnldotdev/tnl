package webhookips

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

type memoryCache map[string]CacheEntry

func (c memoryCache) CachedWebhookPolicy(_ context.Context, server, name string) (CacheEntry, error) {
	if entry, found := c[server+"\x00"+name]; found {
		return entry, nil
	}
	return CacheEntry{}, sql.ErrNoRows
}
func (c memoryCache) SaveWebhookPolicy(_ context.Context, server, name string, entry CacheEntry) error {
	c[server+"\x00"+name] = entry
	return nil
}

func TestProviderCatalogRevalidationAndBoundedOutage(t *testing.T) {
	now := time.Now()
	var unavailable bool
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/v1/webhook-providers/stripe/source" || request.Header.Get("User-Agent") != "tnl" {
			t.Errorf("unexpected catalog request: %s", request.URL)
		}
		if unavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Cache-Control", "public, max-age=300")
		response.Header().Set("ETag", `"first"`)
		if request.Header.Get("If-None-Match") == `"first"` {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = response.Write([]byte(`{"source":{"kind":"ip_ranges","ranges":["192.0.2.1/32","198.51.100.0/24"]}}`))
	}))
	defer server.Close()
	cache := memoryCache{}
	read := func(at time.Time) (Source, error) {
		return resolve(t.Context(), server.Client(), cache, server.URL, "stripe", at)
	}
	source, err := read(now)
	if err != nil || !slices.Equal(source.Prefixes, []string{"192.0.2.1/32", "198.51.100.0/24"}) {
		t.Fatalf("source = %+v, %v", source, err)
	}
	if _, err := read(now.Add(4 * time.Minute)); err != nil || requests != 1 {
		t.Fatalf("fresh cached source requested again: %d, %v", requests, err)
	}
	if _, err := read(now.Add(6 * time.Minute)); err != nil || requests != 2 {
		t.Fatalf("304 did not refresh cache: %d, %v", requests, err)
	}
	unavailable = true
	source, err = read(now.Add(12 * time.Minute))
	if err != nil || !source.Stale {
		t.Fatalf("short outage discarded cached source: %+v, %v", source, err)
	}
	if _, err := read(now.Add(25 * time.Hour)); err == nil {
		t.Fatal("expired last-good source was used")
	}
	other := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer other.Close()
	if _, err := resolve(t.Context(), other.Client(), cache, other.URL, "stripe", now.Add(time.Minute)); err == nil {
		t.Fatal("another server reused the cached policy")
	}
}

func TestCatalogRejectsInvalidSourcesWithoutWidening(t *testing.T) {
	for _, body := range []string{
		`{"source":{"kind":"ip_ranges","ranges":[]}}`,
		`{"source":{"kind":"ip_ranges","ranges":["0.0.0.0/0"]}}`,
		`{"source":{"kind":"ip_ranges","ranges":["::/0"]}}`,
		`{"source":{"kind":"ip_ranges","ranges":["not-ip"]}}`,
		`{"source":{"kind":"ip_ranges","ranges":["192.0.2.4/24"]}}`,
		`{"source":{"kind":"*","ranges":["192.0.2.1"]}}`,
		`{"source":{"kind":"other"}}`,
		`{"source":{"kind":"*"},"unexpected":"x"}`,
		`{"source":{"kind":"*"}}{"source":{"kind":"*"}}`,
	} {
		if _, err := parseCatalog([]byte(body), "stripe"); err == nil {
			t.Errorf("accepted invalid catalog source: %s", body)
		}
	}
	if source, err := parseCatalog([]byte(`{"source":{"kind":"*"}}`), "discord"); err != nil || !source.Any || len(source.Prefixes) != 0 {
		t.Fatalf("wildcard source = %+v, %v", source, err)
	}
	if !Valid("custom") || Valid("svix") || len(Names()) != 23 {
		t.Fatal("provider enum changed unexpectedly")
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"source":{"kind":"ip_ranges","ranges":[]}}`))
	}))
	defer server.Close()
	if _, err := resolve(t.Context(), server.Client(), memoryCache{}, server.URL, "stripe", time.Now()); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("invalid network source was admitted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolve(ctx, server.Client(), memoryCache{}, server.URL, "stripe", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled catalog = %v", err)
	}
}
