package authority

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestEnvironmentPermissionScopePresence(t *testing.T) {
	for _, test := range []struct {
		name  string
		scope authorityv1.EnvironmentPermissionScope
		valid bool
	}{
		{"exact", machineEnvironmentScope("env_one"), true},
		{"fixed collection", authorityv1.EnvironmentPermissionScope{CollectionId: new("col_one"), IncludeFutureEnvironments: new(false)}, true},
		{"future collection", authorityv1.EnvironmentPermissionScope{CollectionId: new("col_one"), IncludeFutureEnvironments: new(true)}, true},
		{"missing", authorityv1.EnvironmentPermissionScope{}, false},
		{"missing future choice", authorityv1.EnvironmentPermissionScope{CollectionId: new("col_one")}, false},
		{"future without collection", authorityv1.EnvironmentPermissionScope{IncludeFutureEnvironments: new(false)}, false},
		{"explicit empty collection", authorityv1.EnvironmentPermissionScope{CollectionId: new(""), EnvironmentIds: new([]string{"env_one"})}, false},
		{"mixed scope", authorityv1.EnvironmentPermissionScope{CollectionId: new("col_one"), IncludeFutureEnvironments: new(true), EnvironmentIds: new([]string{})}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := environmentPermissionScopeFromAPI(test.scope)
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
			if test.valid && test.scope.IncludeFutureEnvironments != nil && (r.IncludeFutureEnvironments == nil || *r.IncludeFutureEnvironments != *test.scope.IncludeFutureEnvironments) {
				t.Fatal("explicit future choice lost")
			}
		})
	}
}

func TestEnvironmentPermissionJSONRejectsMissingNullAndUnknownFields(t *testing.T) {
	valid := `{"project_key":"equipment","scope":{"environment_ids":["env_one"]},"services":["api"],"max_duration_seconds":0,"expires_at":"2026-12-01T00:00:00Z"}`
	for _, body := range []string{
		`null`, `[]`, `{}`, strings.Replace(valid, `"max_duration_seconds":0,`, "", 1),
		strings.Replace(valid, `"max_duration_seconds":0`, `"max_duration_seconds":null`, 1),
		strings.Replace(valid, `["env_one"]`, `null`, 1),
		strings.Replace(valid, `"scope":{`, `"scope":{"unknown":true,`, 1),
		valid + ` {}`, strings.Replace(valid, `"services":["api"]`, `"services":[null]`, 1),
	} {
		t.Run(body, func(t *testing.T) {
			var request authorityv1.EnvironmentVisitorPermissionRequest
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			if err := decodeEnvironmentVisitorJSON(httptest.NewRecorder(), r, &request, "project_key", "scope", "services", "max_duration_seconds", "expires_at"); err == nil {
				t.Fatal("invalid permission request accepted")
			}
		})
	}
	var request authorityv1.EnvironmentVisitorPermissionRequest
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(valid))
	if err := decodeEnvironmentVisitorJSON(httptest.NewRecorder(), r, &request, "project_key", "scope", "services", "max_duration_seconds", "expires_at"); err != nil || request.MaxDurationSeconds != 0 {
		t.Fatal("explicit zero deadline rejected", err)
	}
}
