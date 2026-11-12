package workload

// acquisition contains only private source hints. it is not a deployment
// manifest, visitor permission, environment selector or identity policy.
type Acquisition struct {
	Method    string `json:"method"`
	Audience  string `json:"audience,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	TokenEnv  string `json:"token_env,omitempty"`
}
