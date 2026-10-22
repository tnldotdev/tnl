package config

import "github.com/tnldotdev/tnl/internal/naming/tcpport"

func (c Config) ServicePortInventory() (tcpport.Inventory, error) {
	values := c.ServicePortRanges
	if values == nil {
		values = []string{"20000-20015"}
	}
	return tcpport.ParseInventory(values)
}
