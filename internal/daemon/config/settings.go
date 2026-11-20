package config

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
)

// SettingApplies describes ownership, independently of the source of a value.
func SettingApplies(name string, role Role) bool {
	switch {
	case name == "role" || name == "metrics_listen" || name == "region" || name == "drain_timeout":
		return true
	case name == "cluster_secret" || name == "cluster_secret_previous":
		return role != RoleStandalone
	case name == "fly_machine_identity" || name == "control_hostname" || name == "private_control_address":
		return role == RoleIngress || role == RoleRelay
	case name == "relay_id_prefix":
		return role == RoleRelay
	case name == "service_port_ranges":
		return role.RunsControl() || role.RunsIngress()
	case name == "ingress_ipv4_address" || name == "ingress_ipv6_address" ||
		name == "ingress_lease_duration" || name == "relay_lease_duration":
		return role.RunsControl()
	case name == "lease_renewal_interval" || name == "control_retry_interval":
		return role.RunsIngress() || role.RunsRelay()
	case strings.HasPrefix(name, "standalone_"):
		return role == RoleStandalone
	case name == "visitor_connection_limit" || name == "client_hello_connection_limit" ||
		name == "require_proxy_header" || strings.HasPrefix(name, "pending_") ||
		strings.HasPrefix(name, "ingress_") || strings.HasPrefix(name, "traffic_source_") ||
		strings.HasPrefix(name, "traffic_process_"):
		return role.RunsIngress()
	case strings.HasPrefix(name, "relay_") || strings.HasPrefix(name, "internal_relay_") ||
		strings.HasPrefix(name, "quic_") || name == "publisher_connection_limit" ||
		name == "publisher_connection_stream_limit":
		return role.RunsRelay()
	default:
		return role.RunsControl()
	}
}

// ResolveExplicit rejects ineffective settings, including file and environment
// values explicitly equal to a default. defaults for unused roles are harmless.
func ResolveExplicit(c Config, supplied map[string]bool) (Config, error) {
	_, legacyStreamEnvironment := os.LookupEnv("TNLD_QUIC_MAX_INCOMING_STREAMS")
	if (supplied["quic_max_incoming_streams"] || legacyStreamEnvironment) &&
		c.QUICMaxIncomingStreams != -1 && c.QUICMaxIncomingStreams <= 0 {
		return Config{}, failure.Wrap("validate legacy publisher connection stream limit", failure.ServerConfigInvalid,
			fmt.Errorf("publisher connection stream limit must be positive or -1"))
	}
	_, streamEnvironment := os.LookupEnv("TNLD_PUBLISHER_CONNECTION_STREAM_LIMIT")
	if (supplied["publisher_connection_stream_limit"] || streamEnvironment) &&
		c.PublisherConnectionStreamLimit != -1 && c.PublisherConnectionStreamLimit <= 0 {
		return Config{}, failure.Wrap("validate publisher connection stream limit", failure.ServerConfigInvalid,
			fmt.Errorf("publisher connection stream limit must be positive or -1"))
	}
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
		_, environment := os.LookupEnv(field.Tag.Get("env"))
		if (supplied[name] || environment) && !SettingApplies(name, c.Role) {
			return Config{}, failure.Wrap(failure.Operation("validate setting ownership "+field.Tag.Get("env")),
				failure.ServerConfigInvalid, fmt.Errorf("%s is not used by role %s", name, c.Role))
		}
	}
	return Resolve(c)
}

type SettingValue struct {
	Value  any    `json:"value"`
	Source string `json:"source"`
}

// Inspect never returns credential material, identity seeds, or configured
// paths to private keys. values are keyed by the same names as static files.
func Inspect(c Config, sources map[string]string) map[string]SettingValue {
	result := map[string]SettingValue{}
	typ, value := reflect.TypeFor[Config](), reflect.ValueOf(c)
	private := []string{"database_url", "cluster_secret", "cluster_secret_previous",
		"storage_key", "storage_key_previous", "web_service_secret", "webhook_secret",
		"oidc_client_secret", "oidc_admission_file", "initial_administrator",
		"initial_team_owner", "default_team_member", "private_control_tls_private_key_file",
		"relay_tls_private_key_file"}
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
		if !SettingApplies(name, c.Role) {
			continue
		}
		source := sources[name]
		if _, ok := os.LookupEnv(field.Tag.Get("env")); ok {
			source = "environment"
		}
		if sources[name] == "flag" {
			source = "flag"
		}
		if source == "" {
			source = "default"
			if field.Tag.Get("default") == "-1" {
				source = "automatic"
			}
			if field.Tag.Get("default") == "" && !value.Field(i).IsZero() {
				source = "derived"
			}
		}
		v := value.Field(i).Interface()
		if name == "service_port_ranges" && c.ServicePortRanges == nil {
			if c.Role == RoleIngress {
				source = "control"
			} else {
				v, source = []string{"20000-20015"}, "default"
			}
		}
		if name == "publisher_connection_stream_limit" {
			v = c.PublisherStreamLimit()
			if source == "automatic" {
				if legacy, ok := sources["quic_max_incoming_streams"]; ok {
					source = legacy
				}
				if _, ok := os.LookupEnv("TNLD_QUIC_MAX_INCOMING_STREAMS"); ok && source != "flag" {
					source = "environment"
				}
			}
		}
		if slices.Contains(private, name) {
			v = "[redacted]"
		}
		result[name] = SettingValue{Value: v, Source: source}
	}
	return result
}
