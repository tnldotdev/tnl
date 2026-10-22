package service

import (
	"context"
	"crypto/tls"
)

// TargetResolver captures one verified target for a new connection. the
// implementation owns freshness and publication-scoped resource/trust pinning;
// an error fences new visitors but cannot replay or reconnect admitted streams.
type TargetResolver interface {
	ResolveTarget(context.Context) (string, *tls.Config, error)
}
