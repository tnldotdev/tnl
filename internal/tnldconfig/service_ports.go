package tnldconfig

import "github.com/tnldotdev/tnl/internal/tcpport"

func (c Config) ServicePortInventory() ([]tcpport.Range, error) {
	values := c.ServicePortRanges
	if values == nil {
		values = []string{"20000-20015"}
	}
	return tcpport.ParseInventory(values)
}
