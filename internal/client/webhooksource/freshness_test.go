package webhooksource

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

func TestProviderCatalogCannotRenewTheUpstreamExpiryWith304(t *testing.T) {
	local := time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	control := local.Add(7 * time.Hour)
	checked := control.Add(-24*time.Hour + 10*time.Minute)
	var elapsed atomic.Int64
	var failed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failed.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=0")
		w.Header().Set("ETag", `"same-source"`)
		w.Header().Set("TNL-Webhook-Policy-Observed-At", control.Add(time.Duration(elapsed.Load())).Format(time.RFC3339Nano))
		w.Header().Set("TNL-Webhook-Policy-Checked-At", checked.Format(time.RFC3339Nano))
		w.Header().Set("TNL-Webhook-Policy-Fresh-Until", checked.Add(15*time.Minute).Format(time.RFC3339Nano))
		w.Header().Set("TNL-Webhook-Policy-Valid-Until", checked.Add(24*time.Hour).Format(time.RFC3339Nano))
		if r.Header.Get("If-None-Match") == `"same-source"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(`{"source":{"kind":"ip_ranges","ranges":["192.0.2.0/24"]}}`))
	}))
	t.Cleanup(server.Close)
	cache := memoryCache{}
	read := func(after time.Duration) (Source, error) {
		elapsed.Store(int64(after))
		return resolve(t.Context(), server.Client(), cache, server.URL, "stripe", local.Add(after))
	}
	first, err := read(0)
	if err != nil || first.Any || !first.Stale {
		t.Error("server's still-valid last-good source was not retained as stale", first, err)
	}
	if source, err := read(9 * time.Minute); err != nil || source.Any || !source.Stale {
		t.Error("304 discarded still-valid source or treated it as newly checked", source, err)
	}
	failed.Store(true)
	if _, err := read(10 * time.Minute); err == nil {
		t.Error("catalog failure admitted an actually expired source after 304")
	}
	failed.Store(false)
	if _, err := read(11 * time.Minute); err == nil {
		t.Error("expired server metadata renewed the source")
	}
}

func TestProviderCatalogSpendsSharedCacheAgeBeforeInstallingAWindow(t *testing.T) {
	control := time.Date(2038, 1, 2, 3, 4, 5, 0, time.UTC)
	local := time.Date(2026, 11, 17, 1, 2, 3, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ippolicy.NewProviderWindow(control, control).WriteHeaders(w.Header())
		w.Header().Set("ETag", `"unchanged"`)
		w.Header().Set("Cache-Control", "public, max-age=900")
		w.Header().Set("Age", "900")
		_, _ = w.Write([]byte(`{"source":{"kind":"ip_ranges","ranges":["192.0.2.0/24"]}}`))
	}))
	t.Cleanup(server.Close)
	source, err := resolve(t.Context(), server.Client(), memoryCache{}, server.URL, "stripe", local)
	if err != nil || !source.Stale || source.Any ||
		source.ValidUntil.After(local.Add(24*time.Hour-15*time.Minute)) {
		t.Fatal("shared cache age restarted the catalog's provider-check window", source, err)
	}
}
