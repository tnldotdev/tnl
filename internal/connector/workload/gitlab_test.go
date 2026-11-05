package workload

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestGitLabJobTokenIsCurrentNativeInputNotBackgroundCredential(t *testing.T) {
	hints := workloadmanifest.Acquisition{Method: "token-env", TokenEnv: config.GitLabTokenEnv, Audience: "https://control.example"}
	value := "first.signed.token"
	getenv := func(name string) string {
		if name != config.GitLabTokenEnv {
			t.Fatal("job source read an unrelated credential", name)
		}
		return value
	}
	for _, current := range []string{"first.signed.token", "second.signed.token"} {
		value = current
		if token, err := Acquire(t.Context(), hints, nil, getenv); err != nil || token != current {
			t.Fatal("native acquisition did not read current job input", err)
		}
	}
	if source := RefreshSource(t.TempDir(), hints, getenv); source != nil {
		t.Fatal("static job token became an independent background credential")
	}
	value = ""
	if _, err := Acquire(t.Context(), hints, nil, getenv); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("missing selected job token did not fail closed", err)
	}
}
