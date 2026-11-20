package config

import (
	"errors"
	"net"
	"os"
)

func (c *Config) resolveFlyIdentity() error {
	if !c.FlyMachineIdentity {
		if c.RelayIDPrefix != "" {
			return errors.New("relay-id-prefix requires fly-machine-identity")
		}
		return nil
	}
	machine, app := os.Getenv("FLY_MACHINE_ID"), os.Getenv("FLY_APP_NAME")
	if !validDNSLabel(machine) || !validDNSLabel(app) {
		return errors.New("fly-machine-identity requires canonical FLY_MACHINE_ID and FLY_APP_NAME")
	}
	switch c.Role {
	case RoleIngress:
		id := "ingress-" + machine
		if c.IngressID != "" && c.IngressID != id || c.RelayIDPrefix != "" {
			return errors.New("fly ingress identity conflicts with explicit process identity")
		}
		c.IngressID = id
	case RoleRelay:
		prefix := c.RelayIDPrefix
		if prefix == "" {
			prefix = c.RelayServiceID
		}
		if !validDNSLabel(prefix) {
			return errors.New("fly relay identity requires a canonical relay service ID or prefix")
		}
		id := prefix + "-" + machine
		listen := c.InternalRelayListen
		if listen == "" {
			listen = ":9445"
		}
		_, port, err := net.SplitHostPort(listen)
		if err != nil || validateListenAddress(listen) != nil {
			return errors.New("fly internal relay listen address is invalid")
		}
		address := net.JoinHostPort(machine+".vm."+app+".internal", port)
		if c.RelayID != "" && c.RelayID != id || c.InternalRelayAddress != "" && c.InternalRelayAddress != address {
			return errors.New("fly relay identity conflicts with explicit identity or forwarding address")
		}
		c.RelayID, c.InternalRelayListen, c.InternalRelayAddress = id, listen, address
	default:
		return errors.New("fly-machine-identity is valid only for ingress and relay")
	}
	return nil
}
