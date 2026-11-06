package acquisition

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
)

func TestRefreshSourcesExcludeStaticAndRequestCredentials(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name        string
		hints       workloadmanifest.Acquisition
		environment map[string]string
		want        *workloadmanifest.Acquisition
	}{
		{"projected file", workloadmanifest.Acquisition{Method: "token-file", TokenFile: "current.jwt"}, nil, &workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "current.jwt")}},
		{"Vercel rotating file", workloadmanifest.Acquisition{Method: "vercel-oidc"}, map[string]string{"VERCEL_OIDC_TOKEN_FILE": "vercel.jwt", "VERCEL_OIDC_TOKEN": "private-static-token"}, &workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "vercel.jwt")}},
		{"Vercel static token", workloadmanifest.Acquisition{Method: "vercel-oidc"}, map[string]string{"VERCEL_OIDC_TOKEN": "private-static-token"}, nil},
		{"GitHub request bearer", workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example"}, map[string]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "private-request-bearer"}, nil},
		{"static env", workloadmanifest.Acquisition{Method: "token-env", TokenEnv: "JWT"}, map[string]string{"JWT": "private-static-token"}, nil},
		{"request callback", workloadmanifest.Acquisition{Method: "callback"}, nil, nil},
		{"Fly local API", workloadmanifest.Acquisition{Method: "fly-machine-api", Audience: "https://control.example"}, nil, &workloadmanifest.Acquisition{Method: "fly-machine-api", Audience: "https://control.example"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := RefreshSource(directory, test.hints, func(name string) string { return test.environment[name] })
			if !reflect.DeepEqual(source, test.want) {
				t.Fatal("unexpected native refresh source")
			}
		})
	}
	for _, source := range []workloadmanifest.Acquisition{
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
