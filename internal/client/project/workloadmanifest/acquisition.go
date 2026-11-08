package workloadmanifest

import "github.com/tnldotdev/tnl/internal/config"

// acquisition hints are shared by generated manifests and config-based startup.
// callers resolve relative files and read the current environment.
func AcquisitionFor(p config.Workload, server string) (Acquisition, error) {
	a := Acquisition{}
	switch p.Provider() {
	case "github":
		a.Method, a.Audience = "github-actions", server
	case "vercel":
		a.Method = "vercel-oidc"
	case "fly":
		a.Method, a.Audience = "fly-machine-api", server
	case "google":
		a.Method, a.Audience = "google-metadata", p.TokenAudience(server)
	case "oidc":
		a.Method, a.Audience = "callback", p.TokenAudience(server)
	default:
		return Acquisition{}, ErrInvalid
	}
	if p.Token != nil {
		if (p.Token.File == nil) == (p.Token.Env == nil) {
			return Acquisition{}, ErrInvalid
		}
		if p.Token.File != nil {
			a = Acquisition{Method: "token-file", Audience: a.Audience, TokenFile: *p.Token.File}
		}
		if p.Token.Env != nil {
			a = Acquisition{Method: "token-env", Audience: a.Audience, TokenEnv: *p.Token.Env}
		}
	}
	return a, nil
}
