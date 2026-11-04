package publisher

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// normalizeHTTPMode keeps handler-backed publication separate from target forwarding.
func normalizeHTTPMode(target string, handler http.Handler, resolve func(context.Context) (string, string, error), mounts []publisherproxy.Mount, options publisherproxy.TargetOptions, tlsName string, purpose controlv1.PublicURLPurpose) (string, error) {
	if handler != nil {
		if target != "" || resolve != nil || len(mounts) != 0 || options.RootCAs != nil || options.ServerName != "" || tlsName != "" {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("handler-backed public URL cannot configure a target, resolver, mounts, or target TLS"))
		}
		return "", nil
	}
	if purpose == controlv1.Oauth || purpose == controlv1.Webhooks {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("integration URL requires a publisher handler"))
	}
	return targetsyntax.NormalizeTarget(target)
}
