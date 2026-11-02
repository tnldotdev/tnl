package daemon

import (
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// the generated client also reports the ingress-owned service audit queue.
type ingressRuntimeClient struct {
	*ingress.HTTPControlClient
	generated ingressv1.ClientWithResponsesInterface
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
