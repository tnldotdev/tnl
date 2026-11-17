package httpprotection

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

func TestViteEnvironmentModuleExclusion(t *testing.T) {
	// CRS 930130 deliberately restricts /@fs/. retain the real Linux CI
	// module path so this proof does not depend on the test host's checkout.
	const path = "/@fs/home/runner/work/tnl/tnl/node_modules/.pnpm/vite@8.3.4_@types+node@22.20.5_esbuild@0.28.2_jiti@2.7.0_tsx@4.23.1_yaml@2.9.1/node_modules/vite/dist/client/env.mjs"
	defaults := inspector(t, policy.Settings{})
	excluded := inspector(t, policy.Settings{Exclusions: []policy.Exclusion{{RuleID: 930130, Path: path}}})
	for _, test := range []struct {
		name   string
		p      *Inspector
		path   string
		status int
		rule   int
	}{
		{"default_linux", defaults, path, http.StatusForbidden, 930130},
		{"default_macos", defaults, strings.Replace(path, "/home/runner/work/tnl/tnl/", "/Users/developer/tnl/", 1), http.StatusForbidden, 930130},
		{"exact_module", excluded, path, 0, 0},
		{"exact_module_query", excluded, path + "?v=123", 0, 0},
		{"module_suffix", excluded, path + ".bak", http.StatusForbidden, 930130},
		{"neighboring_file", excluded, strings.TrimSuffix(path, "env.mjs") + ".env", http.StatusForbidden, 930130},
		{"other_fs_path", excluded, "/@fs/home/runner/work/tnl/tnl/.env", http.StatusForbidden, 930130},
		{"other_vite_prefix", excluded, "/@id/vite", http.StatusForbidden, 930130},
		{"restricted_file", excluded, "/.env", http.StatusForbidden, 930130},
		{"module_sqli", excluded, path + "?q=" + url.QueryEscape("' OR 1=1 --"), http.StatusForbidden, 942100},
		{"module_xss", excluded, path + "?q=" + url.QueryEscape("<script>alert(1)</script>"), http.StatusForbidden, 941100},
	} {
		t.Run(test.name, func(t *testing.T) {
			// match the public HMR fixture's Go HTTP visitor headers.
			r := httptest.NewRequest(http.MethodGet, "https://app.example"+test.path, nil)
			r.Header.Set("User-Agent", "Go-http-client/1.1")
			r.Header.Set("Accept-Encoding", "gzip")
			r.Header.Set("Connection", "close")
			_, cleanup, result := test.p.Inspect(r)
			defer cleanup()
			if result.Status != test.status || test.rule != 0 && !slices.Contains(result.RuleIDs, test.rule) {
				t.Fatalf("status=%d want=%d rules=%v want rule=%d", result.Status, test.status, result.RuleIDs, test.rule)
			}
		})
	}
}
