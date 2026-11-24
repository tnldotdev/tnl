// package controlproxy admits HTTP requests from an explicitly trusted HTTPS
// terminator. the external origin is configuration, never forwarded input.
package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
)

type Config struct {
	Origin       string
	TrustedPeers []string
	Provider     Provider
}

type Provider string

const (
	SingleXFF Provider = "single-xff"
	Fly       Provider = "fly"
	AWSALB    Provider = "aws-alb"
)

var errProxyProvider = errors.New("select single-xff, fly, or aws-alb for the trusted HTTPS proxy")

type addressPolicy struct {
	header  string
	appends bool
}

var providers = map[Provider]addressPolicy{
	SingleXFF: {header: "X-Forwarded-For"},
	Fly:       {header: "Fly-Client-IP"},
	AWSALB:    {header: "X-Forwarded-For", appends: true},
}

func (p addressPolicy) clientIP(headers http.Header) netip.Addr {
	values := headers.Values(p.header)
	if len(values) != 1 {
		return netip.Addr{}
	}
	value := values[0]
	if p.appends {
		// the ALB appends the socket IP after any client-supplied addresses.
		value = strings.Trim(value[strings.LastIndexByte(value, ',')+1:], " \t")
	}
	ip, _ := netip.ParseAddr(value)
	return ip
}

func (c Config) Validate() error {
	_, err := c.Handler(http.NotFoundHandler())
	return err
}

func (c Config) Handler(next http.Handler) (http.Handler, error) {
	canonical, canonicalErr := naming.CanonicalControlURL(c.Origin)
	if canonicalErr == nil && canonical == c.Origin && naming.IsLoopbackHTTP(c.Origin) {
		origin, _ := url.Parse(c.Origin)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != origin.Host {
				serverhttp.WriteProblem(w, http.StatusBadRequest, "invalid_request", "local control host is invalid", "")
				return
			}
			request := r.Clone(r.Context())
			request.URL.Scheme, request.URL.Host = origin.Scheme, origin.Host
			stripForwardingHeaders(request.Header)
			next.ServeHTTP(w, request)
		}), nil
	}
	origin, err := url.Parse(c.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("control proxy requires a canonical external HTTPS origin")
	}
	policy, ok := providers[c.Provider]
	if !ok {
		return nil, failure.Wrap("select control proxy provider", failure.ServerConfigInvalid, errProxyProvider)
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
			serverhttp.WriteProblem(w, http.StatusForbidden, "forbidden", "control backend requires a trusted HTTPS proxy", "")
			return
		}
		source := policy.clientIP(r.Header)
		proto := r.Header.Values("X-Forwarded-Proto")
		if !source.IsValid() || source.Zone() != "" || len(proto) != 1 || proto[0] != "https" || r.Host != origin.Host {
			serverhttp.WriteProblem(w, http.StatusBadRequest, "invalid_request", "control proxy metadata is invalid", "")
			return
		}
		request := r.Clone(r.Context())
		request.RemoteAddr = net.JoinHostPort(source.Unmap().String(), "0")
		request.URL.Scheme, request.URL.Host = origin.Scheme, origin.Host
		stripForwardingHeaders(request.Header)
		next.ServeHTTP(w, request)
	}), nil
}

func stripForwardingHeaders(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "fly-") {
			delete(header, name)
		}
	}
}
