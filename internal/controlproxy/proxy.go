// package controlproxy admits HTTP requests from an explicitly trusted HTTPS
// terminator. the external origin is configuration, never forwarded input.
package controlproxy

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/serviceapi"
)

type Config struct {
	Origin         string
	TrustedPeers   []string
	ClientIPHeader string
}

func (c Config) Validate() error {
	_, err := c.Handler(http.NotFoundHandler())
	return err
}

func (c Config) Handler(next http.Handler) (http.Handler, error) {
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("control proxy requires a canonical external HTTPS origin")
	}
	if c.ClientIPHeader != "X-Forwarded-For" && c.ClientIPHeader != "Fly-Client-IP" {
		return nil, errors.New("control proxy client IP header must be X-Forwarded-For or Fly-Client-IP")
	}
	if len(c.TrustedPeers) == 0 {
		return nil, errors.New("control proxy requires trusted peer CIDRs")
	}
	peers := make([]netip.Prefix, len(c.TrustedPeers))
	for i, value := range c.TrustedPeers {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, errors.New("control proxy peer must be a canonical, bounded CIDR")
		}
		peers[i] = prefix
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		trusted := false
		if err == nil {
			for _, prefix := range peers {
				trusted = trusted || prefix.Contains(peer.Addr().Unmap())
			}
		}
		if !trusted {
			serviceapi.WriteProblem(w, http.StatusForbidden, "forbidden", "control backend requires a trusted HTTPS proxy")
			return
		}
		// require one overwritten source value, not an ambiguous proxy chain.
		values := r.Header.Values(c.ClientIPHeader)
		var source netip.Addr
		if len(values) == 1 {
			source, _ = netip.ParseAddr(values[0])
		}
		proto := r.Header.Values("X-Forwarded-Proto")
		if !source.IsValid() || source.Zone() != "" || len(proto) != 1 || proto[0] != "https" || r.Host != origin.Host {
			serviceapi.WriteProblem(w, http.StatusBadRequest, "invalid_request", "control proxy metadata is invalid")
			return
		}
		request := r.Clone(r.Context())
		request.RemoteAddr = net.JoinHostPort(source.Unmap().String(), "0")
		request.URL.Scheme, request.URL.Host = origin.Scheme, origin.Host
		for name := range request.Header {
			lower := strings.ToLower(name)
			if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "fly-") {
				request.Header.Del(name)
			}
		}
		next.ServeHTTP(w, request)
	}), nil
}
