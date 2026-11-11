package proxy

import (
	"context"
	"strings"
)

// Mount forwards one complete path prefix to another local service.
type Mount struct {
	Prefix      string
	Target      string
	StripPrefix bool
	// resolveTarget captures the address and identity at request admission.
	// existing streams finish against their captured target.
	ResolveTarget func(context.Context) (address, identity string, err error)
	Options       TargetOptions
}

func matchesMountPath(escapedPath, prefix string) bool {
	return escapedPath == prefix || strings.HasPrefix(escapedPath, prefix+"/")
}
