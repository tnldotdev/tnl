package control

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherWatchValidatesChangesAgainstSubscriptions(t *testing.T) {
	const run = "srun_1234567890123456789012"
	const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	var revision int64 = 4
	scope := controlv1.PublisherWatchRun{
		ServiceId: "svc_1234567890123456789012", ServiceRunId: run,
		RunNumber: 2, RunToken: token, ConnectorRevision: &revision,
	}
	for _, tc := range []struct {
		name, response string
		want           []controlv1.PublisherWatchChange
		valid          bool
	}{
		{"quiet", `{"changes":[]}`, []controlv1.PublisherWatchChange{}, true},
		{"changed", `{"changes":[{"service_run_id":"` + run + `","connector_revision":"5"}]}`, []controlv1.PublisherWatchChange{{ServiceRunId: run, ConnectorRevision: 5}}, true},
		{"unavailable", `{"changes":[{"service_run_id":"` + run + `","connector_revision":"-1"}]}`, []controlv1.PublisherWatchChange{{ServiceRunId: run, ConnectorRevision: -1}}, true},
		{"null", `{"changes":null}`, nil, false},
		{"unknown scope", `{"changes":[{"service_run_id":"srun_0000000000000000000000","connector_revision":"5"}]}`, nil, false},
		{"not changed", `{"changes":[{"service_run_id":"` + run + `","connector_revision":"4"}]}`, nil, false},
		{"invalid version", `{"changes":[{"service_run_id":"` + run + `","connector_revision":"-2"}]}`, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				defer request.Body.Close()
				if request.Method != http.MethodPost || request.URL.Path != "/v1/publisher/watch" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" {
					t.Error("watch should put exact run credentials only in the request body")
				}
				var body controlv1.PublisherWatchRequest
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil || len(body.Runs) != 1 || body.Runs[0].RunToken != token ||
					body.Runs[0].ConnectorRevision == nil || *body.Runs[0].ConnectorRevision != revision {
					t.Error("watch did not send the requested scope and bookmark")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
			})}, "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.WatchPublisherRuns(t.Context(), []controlv1.PublisherWatchRun{scope})
			if tc.valid != (err == nil) || !slices.Equal(got, tc.want) {
				t.Fatalf("watch changes = %v, %v; want %v", got, err, tc.want)
			}
			if *scope.ConnectorRevision != revision {
				t.Fatal("watch acknowledged a notice")
			}
		})
	}
}
