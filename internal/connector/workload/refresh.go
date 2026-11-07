package workload

import (
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
)

// refreshSource selects only independently readable native sources. static
// environment tokens and request callbacks cannot mint a later identity proof.
func RefreshSource(directory string, hints workloadmanifest.Acquisition, getenv func(string) string) *workloadmanifest.Acquisition {
	source := hints
	if source.Method == "vercel-oidc" {
		source.Method, source.TokenFile = "token-file", getenv("VERCEL_OIDC_TOKEN_FILE")
	}
	if source.Method == "token-file" && source.TokenFile != "" && !filepath.IsAbs(source.TokenFile) {
		source.TokenFile = filepath.Join(directory, source.TokenFile)
	}
	if ValidateRefreshSource(source) != nil {
		return nil
	}
	return &source
}

func ValidateRefreshSource(source workloadmanifest.Acquisition) error {
	if source.TokenEnv != "" {
		return ErrAssertionSource
	}
	switch source.Method {
	case "token-file":
		if !filepath.IsAbs(source.TokenFile) || len(source.TokenFile) > 4096 || strings.ContainsAny(source.TokenFile, "\x00\r\n") {
			return ErrAssertionSource
		}
	case "fly-machine-api":
		if source.TokenFile != "" || !config.ExactWorkloadValue(source.Audience) {
			return ErrAssertionSource
		}
	default:
		return ErrAssertionSource
	}
	return nil
}
