// package ingresspool names the public ingress-address placement boundary.
package pool

import (
	"errors"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

type ID string

const PrimaryID ID = "ingress-a"

// configuration belongs to one public address, not to a team or an ingress process.
// draining pools keep saved endpoints but receive no new publisher groups.
type Configuration struct {
	ID                       ID
	IPv4Address, IPv6Address netip.Addr
	Ports                    tcpport.Inventory
	Draining                 bool
}

var ErrConfiguration = errors.New("ingress pools require unique IDs and addresses, a primary pool, and valid port inventories")

func ValidateConfigurations(pools []Configuration) error {
	ids := map[ID]bool{}
	addresses := map[netip.Addr]bool{}
	for _, pool := range pools {
		if !naming.ValidAuthorityLabel(string(pool.ID)) || ids[pool.ID] ||
			!pool.IPv4Address.IsValid() && !pool.IPv6Address.IsValid() {
			return ErrConfiguration
		}
		ids[pool.ID] = true
		for i, address := range []netip.Addr{pool.IPv4Address, pool.IPv6Address} {
			if !address.IsValid() {
				continue
			}
			if address.Zone() != "" || i == 0 && !address.Is4() || i == 1 && (!address.Is6() || address.Is4In6()) || addresses[address] {
				return ErrConfiguration
			}
			addresses[address] = true
		}
		if _, err := tcpport.NewInventory(pool.Ports.Ranges()); err != nil {
			return errors.Join(ErrConfiguration, err)
		}
	}
	if !ids[PrimaryID] {
		return ErrConfiguration
	}
	return nil
}
