package workload

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRefreshSourcesExcludeStaticAndRequestCredentials(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name        string
		hints       Acquisition
		environment map[string]string
		want        *Acquisition
	}{
		{"projected file", Acquisition{Method: "token-file", TokenFile: "current.jwt"}, nil, &Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "current.jwt")}},
		{"Vercel rotating file", Acquisition{Method: "vercel-oidc"}, map[string]string{"VERCEL_OIDC_TOKEN_FILE": "vercel.jwt", "VERCEL_OIDC_TOKEN": "private-static-token"}, &Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "vercel.jwt")}},
		{"Vercel static token", Acquisition{Method: "vercel-oidc"}, map[string]string{"VERCEL_OIDC_TOKEN": "private-static-token"}, nil},
		{"GitHub request bearer", Acquisition{Method: "github-actions", Audience: "https://control.example"}, map[string]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "private-request-bearer"}, nil},
		{"static env", Acquisition{Method: "token-env", TokenEnv: "JWT"}, map[string]string{"JWT": "private-static-token"}, nil},
		{"request callback", Acquisition{Method: "callback"}, nil, nil},
		{"Fly local API", Acquisition{Method: "fly-machine-api", Audience: "https://control.example"}, nil, &Acquisition{Method: "fly-machine-api", Audience: "https://control.example"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := RefreshSource(directory, test.hints, func(name string) string { return test.environment[name] })
			if !reflect.DeepEqual(source, test.want) {
				t.Fatal("unexpected native refresh source")
			}
		})
	}
	for _, source := range []Acquisition{
		{Method: "token-file", TokenFile: "relative.jwt"},
		{Method: "token-file", TokenFile: "/run/current\n.jwt"},
		{Method: "token-file", TokenFile: "/" + strings.Repeat("x", 4096)},
		{Method: "token-file", TokenFile: "/run/current.jwt", TokenEnv: "JWT"},
		{Method: "fly-machine-api", Audience: "https://control.example", TokenFile: "/run/current.jwt"},
		{Method: "fly-machine-api"},
	} {
		if ValidateRefreshSource(source) == nil {
			t.Fatal("invalid refresh source accepted")
		}
	}
}
