package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
)

func TestIntegrationLocalPublicURLConfigurationReusesBoundIdentity(t *testing.T) {
	f := newSplitPublishFixture(t, "local-continuity")
	directory := t.TempDir()
	path := filepath.Join(directory, "tnl.json")
	writeConfiguration := func(shared bool) {
		t.Helper()
		limits := map[string]any{"total": 100, "concurrency": 3}
		public := map[string]any{"hostname": f.identity.hostname}
		binding := map[string]any{"public_url": public}
		if shared {
			binding["http"] = map[string]any{"access": "restricted", "limits": limits}
		} else {
			public["access"], public["limits"] = "restricted", map[string]any{"http": limits}
		}
		document, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{
			"server": f.identity.controlOrigin, "feedback": true, "services": map[string]any{"web": map[string]any{}},
			"deployments": map[string]any{"local": map[string]any{"targets": map[string]any{"web": binding}}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, document, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfiguration(false)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "source-bound application")
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	original := http.DefaultTransport
	http.DefaultTransport = sdkControlTransport{origin: f.identity.controlOrigin, selected: f.controlHTTP.Transport, other: original}
	t.Cleanup(func() { http.DefaultTransport = original })
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor := *f.visitor.client
	visitor.Jar = jar
	var first publisher.Event
	var previewID, publisherID string
	var share controlv1.ShareCreation
	var report controlv1.FeedbackThread
	for round := range 2 {
		func() {
			if round == 1 {
				writeConfiguration(true)
			}
			state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(f.owner.directory, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			salt, err := state.WorktreeHashSalt(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, directory, salt)
			if err != nil {
				t.Fatal(err)
			}
			manager, err := publisherapp.New(t.Context(), project.Root, state, publisherapp.ConfiguredServices(project), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			operations := invocation.NewProjectRuntime(project, state, manager, nil)
			configuration, err := operations.PublicConfiguration(t.Context(), publisherapp.Service{Name: "web", Target: target.URL, ServiceProtocol: "http"})
			if err != nil {
				t.Fatal("configure source-bound application", err)
			}
			cfg := configuration.Publisher
			if cfg.Limits.Requests != 100 || cfg.Limits.Concurrency != 3 {
				t.Fatal("moving HTTP settings lost the request budget")
			}
			if cfg.AssignedPublicURL == nil || cfg.AssignedPublicURL.Port < 1024 || cfg.PreviewID == "" || cfg.PublisherIdentityID == "" {
				t.Fatal("configuration omitted saved endpoint or identity facts")
			}
			if round == 0 {
				previewID, publisherID = cfg.PreviewID, cfg.PublisherIdentityID
			} else if cfg.PreviewID != previewID || cfg.PublisherIdentityID != publisherID || cfg.AssignedPublicURL.Id != first.PublicURLID {
				t.Fatal("reopening configuration replaced a saved resource")
			}
			quic, tcp := f.connectors()
			cfg.QUICConnector, cfg.TCPConnector = quic, tcp
			cfg.TransportTLS, cfg.DrainTime, cfg.FallbackDelay = f.roots.Clone(), time.Second, 10*time.Millisecond
			handle := startOwnedIntegrationPublisher(t, f.owner, cfg, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
			defer stopIntegrationPublisher(t, handle)
			ready := f.waitReady(t, handle)
			origin, err := url.Parse(ready.PublicURL)
			if err != nil || origin.Port() == "" || origin.Port() == "443" {
				t.Fatal("application did not retain its allocated port")
			}
			metadata, err := operations.Metadata(t.Context())
			if err != nil || metadata.Services["web"].URL != ready.PublicURL || metadata.Services["web"].Port != cfg.AssignedPublicURL.Port {
				t.Fatal("project metadata lost the saved allocated origin", err)
			}
			if round == 0 {
				first = ready
				share, err = f.identity.routes.CreateShare(t.Context(), previewID, "local-continuity-share", controlv1.CreateShareRequest{
					PublicUrlIds: []string{ready.PublicURLID}, EntryPublicUrlId: ready.PublicURLID, ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatal("create source-bound preview share", err)
				}
			} else if ready.PublicURLID != first.PublicURLID || ready.PublicURL != first.PublicURL || ready.PublishRunNumber <= first.PublishRunNumber {
				t.Fatal("restart changed the allocated origin or reused a publish run")
			}
			preview, err := f.identity.routes.GetPreview(t.Context(), previewID)
			if err != nil || len(preview.PublicUrlIds) != 1 || !slices.Contains(preview.PublicUrlIds, first.PublicURLID) {
				t.Fatal("restart lost preview membership", err)
			}
			retained, err := f.identity.routes.GetShare(t.Context(), share.Share.Id)
			if err != nil || retained.RevokedAt != nil || !slices.Equal(retained.PublicUrlIds, share.Share.PublicUrlIds) {
				t.Fatal("restart changed captured share membership", err)
			}
			waitForIntegrationCondition(t, 5*time.Second, func(ctx context.Context) (bool, error) {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, share.Link, nil)
				if err != nil {
					return false, err
				}
				response, err := visitor.Do(request)
				if err != nil {
					// never return the request error, which contains the share secret.
					var requestErr *url.Error
					if errors.As(err, &requestErr) {
						return false, fmt.Errorf("share request failed: %w", requestErr.Err)
					}
					return false, errors.New("share request failed")
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				return readErr == nil && response.StatusCode == http.StatusOK && string(body) == "source-bound application", readErr
			})
			browser, err := publisherv1.NewClientWithResponses(ready.PublicURL, publisherv1.WithHTTPClient(&visitor), publisherv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
				request.Header.Set("Origin", ready.PublicURL)
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if round == 0 {
				data, err := os.ReadFile(filepath.Join(integrationRepositoryRoot(t), "contracts/fixtures/publisher/v1/report-request.json"))
				if err != nil {
					t.Fatal(err)
				}
				var input publisherv1.BrowserFeedbackReportRequest
				if err := json.Unmarshal(data, &input); err != nil {
					t.Fatal(err)
				}
				created, err := browser.CreateBrowserFeedbackReportWithResponse(t.Context(), &publisherv1.CreateBrowserFeedbackReportParams{IdempotencyKey: "continuity-report"}, input)
				if err != nil || created.JSON200 == nil {
					t.Fatal("reviewer could not create feedback", err)
				}
				report = *created.JSON200
			}
			read, err := browser.GetBrowserFeedbackThreadWithResponse(t.Context(), report.Id)
			if err != nil || read.JSON200 == nil {
				t.Fatal("reviewer lost feedback after configuration reopened", err)
			}
			thread := read.JSON200
			if !reflect.DeepEqual(thread.Report, report.Report) || !reflect.DeepEqual(thread.Scope, report.Scope) ||
				!reflect.DeepEqual(thread.SourceAtReport, report.SourceAtReport) || !reflect.DeepEqual(thread.Evidence, report.Evidence) ||
				thread.Scope.PreviewId != previewID || thread.Scope.PublicUrlId != first.PublicURLID {
				t.Fatal("configuration restart changed immutable feedback")
			}
		}()
	}
	// an unavailable retained binding is not an absent binding. startup must
	// stop before hostname allocation or publisher enrollment can replace it.
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.public_urls SET lifecycle_state='suspended',suspended_at=now() WHERE id=$1`, first.PublicURLID); err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(f.owner.directory, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	salt, err := state.WorktreeHashSalt(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, directory, salt)
	if err != nil {
		t.Fatal(err)
	}
	operations := invocation.NewProjectRuntime(project, state, nil, nil)
	if _, err := operations.PublicConfiguration(t.Context(), publisherapp.Service{Name: "web", Target: target.URL, ServiceProtocol: "http"}); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("unavailable saved binding did not stop startup", err)
	}
	var urls, identities int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM control.public_urls),(SELECT count(*) FROM control.publisher_identities)`).Scan(&urls, &identities); err != nil || urls != 1 || identities != 1 {
		t.Fatal("failed startup allocated a replacement public URL or publisher", urls, identities, err)
	}
}
