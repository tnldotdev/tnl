package config

import (
	"net"

	"github.com/alecthomas/kong"
)

func Parse(args []string) (Config, error) {
	type arguments Config
	var flags arguments
	parser, err := kong.New(&flags, kong.Name("tnld"), kong.Description("tnl server."))
	if err != nil {
		return Config{}, err
	}
	if _, err := parser.Parse(args); err != nil {
		return Config{}, err
	}
	return Resolve(Config(flags))
}

func Resolve(config Config) (Config, error) {
	config.resolveCapacities(processResources())
	switch config.Role {
	case RoleStandalone:
		setControlDefaults(&config)
		if config.IngressListen == "" {
			config.IngressListen = ":443"
		}
		if config.RelayTCPListen == "" {
			config.RelayTCPListen = ":443"
		}
		if config.RelayUDPListen == "" {
			config.RelayUDPListen = ":443"
		}
	case RoleControl:
		setControlDefaults(&config)
	case RoleIngress:
		if config.IngressListen == "" {
			config.IngressListen = ":443"
		}
	case RoleRelay:
		if config.RelayTCPListen == "" {
			config.RelayTCPListen = ":443"
		}
		if config.RelayUDPListen == "" {
			config.RelayUDPListen = ":443"
		}
		if config.InternalRelayListen == "" && config.InternalRelayAddress != "" {
			_, port, err := net.SplitHostPort(config.InternalRelayAddress)
			if err == nil {
				config.InternalRelayListen = net.JoinHostPort("", port)
			}
		}
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func setControlDefaults(config *Config) {
	if config.ControlListen == "" {
		config.ControlListen = "127.0.0.1:8080"
	}
	if config.PrivateControlListen == "" {
		config.PrivateControlListen = ":9443"
	}
	if config.ACMEDirectoryURL == "" {
		config.ACMEDirectoryURL = defaultACMEDirectoryURL
	}
}
