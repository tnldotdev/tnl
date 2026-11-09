package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

// the file is control-owned deployment configuration. ingress processes receive
// only their own pool ID and listening ports, never the complete inventory.
func (c Config) IngressPools() ([]ingresspool.Configuration, error) {
	if c.IngressPoolsFile == "" {
		return nil, nil
	}
	if c.Role != RoleControl {
		return nil, errors.New("ingress-pools-file is valid only for the control role")
	}
	if len(c.IngressIPv4Addresses)+len(c.IngressIPv6Addresses) != 0 {
		return nil, errors.New("ingress-pools-file replaces ingress-ipv4-address and ingress-ipv6-address")
	}
	f, err := os.Open(c.IngressPoolsFile)
	if err != nil {
		return nil, fmt.Errorf("open ingress pools file: %w", err)
	}
	defer f.Close()
	var document struct {
		Pools []struct {
			ID                ingresspool.ID `json:"id"`
			IPv4Address       string         `json:"ipv4_address"`
			IPv6Address       string         `json:"ipv6_address"`
			ServicePortRanges []string       `json:"service_port_ranges"`
			Draining          bool           `json:"draining"`
		} `json:"pools"`
	}
	limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("decode ingress pools file: expected a pools object with IDs, addresses, and service_port_ranges")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("decode ingress pools file: expected one JSON document")
	}
	if limited.N == 0 {
		return nil, errors.New("decode ingress pools file: file exceeds 1 MiB")
	}
	var result []ingresspool.Configuration
	for _, input := range document.Pools {
		pool := ingresspool.Configuration{ID: input.ID, Draining: input.Draining}
		for i, value := range []string{input.IPv4Address, input.IPv6Address} {
			if value == "" {
				continue
			}
			address, err := netip.ParseAddr(value)
			if err != nil || address.String() != value {
				return nil, ingresspool.ErrConfiguration
			}
			if i == 0 {
				pool.IPv4Address = address
			} else {
				pool.IPv6Address = address
			}
		}
		pool.Ports, err = tcpport.ParseInventory(input.ServicePortRanges)
		if err != nil {
			return nil, err
		}
		result = append(result, pool)
	}
	if err := ingresspool.ValidateConfigurations(result); err != nil {
		return nil, err
	}
	return result, nil
}
