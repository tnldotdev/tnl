package localproxy

import (
	"strings"
)

// Mount forwards one complete path prefix to another local service.
type Mount struct {
	Prefix      string
	Target      string
	StripPrefix bool
	// resolveTarget returns the currently registered app target at admission.
	// an empty value rejects new requests while the mounted app is stopped.
	ResolveTarget func() string
	Options       TargetOptions
}

func matchesMountPath(escapedPath, prefix string) bool {
	return escapedPath == prefix || strings.HasPrefix(escapedPath, prefix+"/")
}
