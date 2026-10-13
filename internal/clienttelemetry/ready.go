// package clienttelemetry reports the first ready ad-hoc SDK publication.
package clienttelemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const readyReceiver = "https://tnl.dev/api/telemetry"
const readyTimeout = 500 * time.Millisecond

type readyReporter struct {
	receiver string
	client   *http.Client
}

// ReportAdHocReady queues a bounded event without delaying the publisher's
// first ready response for remote telemetry delivery.
func ReportAdHocReady(ctx context.Context, state *clientstate.Database, serverURL, invocationID string) {
	reporter := readyReporter{receiver: readyReceiver, client: &http.Client{Timeout: readyTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	reporter.queue(ctx, state, serverURL, invocationID)
}

func (r readyReporter) queue(ctx context.Context, state *clientstate.Database, serverURL, invocationID string) bool {
	if state == nil || !opaqueid.Valid(invocationID, opaqueid.InvocationPrefix) {
		return false
	}
	if disabled, _ := strconv.ParseBool(os.Getenv("TNL_NO_TELEMETRY")); disabled {
		return false
	}
	id, err := opaqueid.New(opaqueid.TelemetryEventPrefix)
	if err != nil {
		return false
	}
	kind := "self_hosted"
	if serverURL == clientserver.DefaultURL {
		kind = "hosted"
	}
	encoded, err := json.Marshal(struct {
		EventID      string    `json:"event_id"`
		InvocationID string    `json:"invocation_id"`
		OccurredAt   time.Time `json:"occurred_at"`
		EventVersion int       `json:"event_version"`
		Name         string    `json:"name"`
		Payload      any       `json:"payload"`
	}{id, invocationID, time.Now().UTC(), 1, "tunnel.ready", struct {
		Source      string `json:"source"`
		ServerKind  string `json:"server_kind"`
		PublishMode string `json:"publish_mode"`
		EntryMode   string `json:"entry_mode"`
	}{"publish", kind, "app", "ad_hoc"}})
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(invocationID))
	queueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readyTimeout)
	queued, err := state.QueueReadyTelemetryEvent(queueCtx, hex.EncodeToString(digest[:]), id, encoded)
	cancel()
	if err != nil || !queued {
		return false
	}
	go r.flush(state.Root())
	return true
}

func (r readyReporter) flush(root string) {
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return
	}
	defer state.Close()
	enabled, err := state.TelemetryEnabled(ctx)
	if err != nil || !enabled {
		return
	}
	if err := state.PruneTelemetryOutbox(ctx); err != nil {
		return
	}
	pending, err := state.PendingTelemetryEvents(ctx, 25)
	if err != nil || len(pending) == 0 {
		return
	}
	installationID, err := state.InstallationID(ctx)
	if err != nil {
		return
	}
	events := make([]json.RawMessage, 0, len(pending))
	for _, item := range pending {
		events = append(events, item.JSON)
	}
	body, err := json.Marshal(struct {
		SchemaVersion  int               `json:"schema_version"`
		InstallationID string            `json:"installation_id"`
		Client         any               `json:"client"`
		Events         []json.RawMessage `json:"events"`
	}{1, installationID, struct {
		Version string `json:"version"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		CI      bool   `json:"ci"`
	}{buildinfo.Version, runtime.GOOS, runtime.GOARCH, os.Getenv("CI") != ""}, events})
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.receiver, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "tnl")
	response, err := r.client.Do(request)
	if err != nil {
		return
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNoContent || response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
		_ = state.DeleteTelemetryEvents(ctx, pending)
	}
}
