package config

import (
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRelayQUICProfiles(t *testing.T) {
	for _, profile := range []string{"", "standard", "fly"} {
		t.Run("profile="+profile, func(t *testing.T) {
			t.Setenv("TNLD_RELAY_QUIC_PROFILE", profile)
			t.Setenv("TNLD_RELAY_UDP_LISTEN", "127.0.0.1:443")
			cfg := validCertificateConfig(t, RoleRelay)
			wantProfile := profile
			if wantProfile == "" {
				wantProfile = "standard"
			}
			if cfg.RelayQUICProfile != wantProfile {
				t.Fatalf("profile = %q; want %q", cfg.RelayQUICProfile, wantProfile)
			}
			cfg.QUICIdleTimeout, cfg.QUICMaxIncomingStreams = 17*time.Second, 123
			// neither the bind hostname nor the advertised relay address selects policy.
			for _, address := range []string{"127.0.0.1:443", "fly-global-services:443"} {
				cfg.RelayUDPListen = address
				config := cfg.RelayQUICConfig()
				fly := profile == "fly"
				network := "udp"
				var size uint16
				if fly {
					network, size = "udp4", 1200
				}
				if config.UDPNetwork != network || config.BasicPacketConn != fly || config.Config.InitialPacketSize != size || config.Config.DisablePathMTUDiscovery != fly {
					t.Fatalf("profile %q resolved wrong socket or packet settings: %#v, %#v", profile, config, config.Config)
				}
				if config.Config.MaxIdleTimeout != 17*time.Second || config.Config.MaxIncomingStreams != 123 || !config.Config.EnableDatagrams {
					t.Fatal("profile lost stream limits, idle timeout, or DATAGRAM support")
				}
				config.Config.InitialPacketSize = 1400
				if cfg.RelayQUICConfig().Config.InitialPacketSize != size {
					t.Fatal("resolved listeners share mutable QUIC configuration")
				}
			}
		})
	}
}

func TestRelayQUICFlyRequiresSpecificListenAddress(t *testing.T) {
	for _, role := range []Role{RoleRelay, RoleStandalone} {
		t.Run(string(role), func(t *testing.T) {
			base := validCertificateConfig(t, role)
			for _, profile := range []string{"standard", "fly"} {
				for _, address := range []string{
					"", ":443", "0.0.0.0:443", "[::]:443", "[0:0:0:0:0:0:0:0]:443", "[::ffff:0.0.0.0]:443",
					"127.0.0.1:443", "fly-global-services:443",
				} {
					t.Run(profile+"/"+address, func(t *testing.T) {
						cfg := base
						cfg.RelayQUICProfile, cfg.RelayUDPListen = profile, address
						wantError := profile == "fly" && address != "127.0.0.1:443" && address != "fly-global-services:443"
						for _, validate := range []func() error{cfg.Validate, func() error { _, err := Resolve(cfg); return err }} {
							err := validate()
							if !wantError {
								if err != nil {
									t.Fatal(err)
								}
								continue
							}
							typed, ok := failure.Of(err)
							if !ok || typed.Reason() != failure.ServerConfigInvalid || typed.Setting() != failure.SettingRelayUDPListen {
								t.Fatalf("wildcard fly listener lost its diagnostic setting: %v", err)
							}
							if definition, _ := failure.DefinitionFor(typed.Reason()); definition.Retry != failure.RetryAfterChange {
								t.Fatal("wildcard fly listener must require a configuration change")
							}
						}
					})
				}
			}
		})
	}
}

func TestRelayQUICProfileValidation(t *testing.T) {
	for _, role := range []Role{RoleRelay, RoleStandalone} {
		cfg := validCertificateConfig(t, role)
		cfg.RelayQUICProfile = "invalid-secret-value"
		for _, validate := range []func() error{cfg.Validate, func() error { _, err := Resolve(cfg); return err }} {
			err := validate()
			typed, ok := failure.Of(err)
			if !ok || typed.Reason() != failure.ServerConfigInvalid || typed.Setting() != failure.SettingRelayQUICProfile {
				t.Fatalf("invalid profile did not identify its setting: %v", err)
			}
			if definition, _ := failure.DefinitionFor(typed.Reason()); definition.Retry != failure.RetryAfterChange {
				t.Fatal("invalid profile must require a configuration change")
			}
			if strings.Contains(err.Error(), cfg.RelayQUICProfile) {
				t.Fatal("invalid profile value leaked into error text")
			}
		}
	}
	args := []string{"--role=relay", "--relay-quic-profile=invalid-secret-value"}
	if _, err := Parse(args); err == nil {
		t.Fatal("invalid profile flag was accepted")
	} else if typed, ok := failure.Of(err); !ok || typed.Setting() != failure.SettingRelayQUICProfile {
		t.Fatalf("invalid profile flag lost its setting: %v", err)
	}
	t.Setenv("TNLD_RELAY_QUIC_PROFILE", "invalid-secret-value")
	if _, err := Parse([]string{"--role=relay"}); err == nil {
		t.Fatal("invalid profile environment was accepted")
	} else if typed, ok := failure.Of(err); !ok || typed.Setting() != failure.SettingRelayQUICProfile {
		t.Fatalf("invalid profile environment lost its setting: %v", err)
	}
}
