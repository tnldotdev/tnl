package dns

import (
	"strconv"
	"strings"
)

// AddressOwner preserves separate DNS ownership markers without making a
// service acquire a public URL identity.
type AddressOwner struct {
	kind, id string
}

func PublicURLOwner(id string) AddressOwner { return AddressOwner{kind: "public-url", id: id} }
func ServiceOwner(id string) AddressOwner   { return AddressOwner{kind: "service", id: id} }

func (o AddressOwner) marker() string {
	if o.id == "" || len(o.id) > 128 || strings.ContainsAny(o.id, "\x00\r\n\"\\ ") || o.kind != "public-url" && o.kind != "service" {
		return ""
	}
	return strconv.Quote("tnl-" + o.kind + ":" + o.id)
}
