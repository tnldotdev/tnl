package public

import (
	"net/http"
	"net/netip"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func publisherRequestSource(r *http.Request) string {
	ip, err := guestRequestAddress(r)
	if err != nil || ip.IsUnspecified() {
		return ""
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}

// capture peer facts at the serving boundary, including run-token policy and
// certificate requests. this grants no authority; an absent peer remains invalid.
func publisherRequestSourceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, _ := guestRequestAddress(r)
		if source.IsUnspecified() {
			source = netip.Addr{}
		}
		ctx := controlstate.WithPublisherRequestSource(r.Context(), source)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
