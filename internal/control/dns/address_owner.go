package dns

import (
	"strconv"
	"strings"
)

// AddressOwner identifies the service that owns an exact DNS address record.
type AddressOwner struct {
	kind, id string
}

func ServiceOwner(id string) AddressOwner { return AddressOwner{kind: "service", id: id} }

func (o AddressOwner) marker() string {
	if o.id == "" || len(o.id) > 128 || strings.ContainsAny(o.id, "\x00\r\n\"\\ ") ||
		o.kind != "service" && o.kind != "alias-wildcard" {
		return ""
	}
	return strconv.Quote("tnl-" + o.kind + ":" + o.id)
}
