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
	result, err := authorization.CanonicalizeIPPrefixes(input)
	if err != nil || len(result) > 256 {
		return nil, failure.Wrap("validate visitor IP list", failure.InvalidCommand, errors.New("IP list must contain at most 256 distinct addresses or prefixes"))
	}
	return append([]string{}, result...), nil
}
