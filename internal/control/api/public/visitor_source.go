package public

import "net/netip"

func validVisitorSource(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Zone() == "" && addr.Unmap().String() == value
}
