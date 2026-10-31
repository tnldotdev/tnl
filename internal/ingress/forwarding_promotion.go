package ingress

import (
	"context"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// SetPromotionHandler supplies the server's current policy and capacity check.
func (f *Forwarder) SetPromotionHandler(handle func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult) {
	f.mu.Lock()
	f.promote = handle
	f.mu.Unlock()
}
