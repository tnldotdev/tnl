package clientstate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/webhookips"
)

func TestWebhookPolicyCacheSurvivesRestartAndRejectsUnboundedData(t *testing.T) {
	const serverA, serverB = "https://control.one.test", "https://control.two.test"
	root := filepath.Join(t.TempDir(), "state")
	state, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	entry := webhookips.CacheEntry{JSON: []byte(`{"source":{"kind":"ip_ranges","ranges":["192.0.2.0/24"]}}`),
		ETag: `"one"`, CheckedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := state.SaveWebhookPolicy(t.Context(), serverA, "stripe", entry); err != nil {
		t.Fatal(err)
	}
	second := entry
	second.ETag = `"two"`
	if err := state.SaveWebhookPolicy(t.Context(), serverB, "stripe", second); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	read, err := state.CachedWebhookPolicy(t.Context(), serverA, "stripe")
	if err != nil || string(read.JSON) != string(entry.JSON) || read.ETag != entry.ETag || !read.CheckedAt.Equal(entry.CheckedAt) {
		t.Fatalf("cached policy = %+v, %v", read, err)
	}
	read, err = state.CachedWebhookPolicy(t.Context(), serverB, "stripe")
	if err != nil || read.ETag != second.ETag {
		t.Fatalf("second server reused another policy: %+v, %v", read, err)
	}
	entry.JSON = make([]byte, 16385)
	if err := state.SaveWebhookPolicy(t.Context(), serverA, "stripe", entry); err == nil {
		t.Fatal("unbounded policy was saved")
	}
	if _, err := state.CachedWebhookPolicy(t.Context(), serverA, "svix"); err == nil {
		t.Fatal("unknown provider read cached policy")
	}
}
