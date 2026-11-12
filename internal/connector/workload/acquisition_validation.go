package workload

import (
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// validateAcquisition accepts one explicit native source, not provider discovery
// or fallback. hints never grant visitor access or assert a verified provider.
func ValidateAcquisition(source Acquisition) error {
	switch source.Method {
	case "token-file":
		if !filepath.IsAbs(source.TokenFile) || len(source.TokenFile) > 4096 || strings.ContainsAny(source.TokenFile, "\x00\r\n") || source.TokenEnv != "" || source.Audience != "" { return ErrAssertionSource }
	case "token-env":
		if config.ValidateWorkloadTokenEnv(source.TokenEnv) != nil || source.TokenFile != "" || source.Audience != "" { return ErrAssertionSource }
	case "github-actions", "fly-machine-api", "google-metadata":
		if !config.ExactWorkloadValue(source.Audience) || source.TokenFile != "" || source.TokenEnv != "" { return ErrAssertionSource }
	case "vercel-oidc":
		if source.Audience != "" || source.TokenFile != "" || source.TokenEnv != "" { return ErrAssertionSource }
	default:
		return ErrAssertionSource
	}
	return nil
}
