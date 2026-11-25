package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLIOutputPreference(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	dir := t.TempDir()
	for _, tt := range []struct {
		preference, explicit, agent string
		machine                     bool
	}{
		{"", "", "", false},
		{"", "", "custom-agent@2", false},
		{"machine", "", "custom-agent@2", true},
		{"machine", "human", "", false},
		{"human", "json", "", true},
	} {
		t.Run(tt.preference+"/"+tt.explicit+"/"+tt.agent, func(t *testing.T) {
			args := []string{"ping", server.URL}
			if tt.explicit != "" {
				args = append(args, "--output", tt.explicit)
			}
			got := runBuiltCLI(t, dir, []string{"TNL_OUTPUT=" + tt.preference, "AI_AGENT=" + tt.agent}, args...)
			if got.exit != 0 || got.stderr != "" {
				t.Fatalf("ping did not produce a clean result: %+v", got)
			}
			if tt.machine {
				var response struct {
					Status int `json:"http_status"`
				}
				if json.Unmarshal([]byte(got.stdout), &response) != nil || response.Status != http.StatusNoContent {
					t.Fatalf("want a single JSON result, got %q", got.stdout)
				}
			} else if got.stdout != "HTTP 204 No Content  "+server.URL+"\n" {
				t.Fatalf("want human result, got %q", got.stdout)
			}
			if strings.Contains(got.stdout, "\x1b") {
				t.Fatalf("escaped output: %q", got.stdout)
			}
		})
	}
}
