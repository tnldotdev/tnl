package invocation

import (
	"context"
	"errors"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
)

func AccessIPPrefixes(ctx context.Context, control clientIPLookup, values []string) ([]string, error) {
	input := make([]string, 0, len(values))
	for _, value := range values {
		if value == "current" {
			current, err := control.ClientIP(ctx)
			if err != nil {
				return nil, err
			}
			address, err := netip.ParseAddr(current.Ip)
			if err != nil || address.Zone() != "" {
				return nil, errors.New("control returned an invalid current IP")
			}
			address = address.Unmap()
			value = netip.PrefixFrom(address, address.BitLen()).String()
		}
		input = append(input, value)
	}
	result, err := authorization.CanonicalizeVisitorIPPrefixes(input)
	if err != nil {
		problem := errors.New("IP list must contain valid addresses or prefixes")
		if errors.Is(err, authorization.ErrIPPrefixLimit) {
			problem = authorization.ErrIPPrefixLimit
		}
		return nil, failure.Wrap("validate visitor IP list", failure.InvalidCommand, problem)
	}
	return append([]string{}, result...), nil
}
