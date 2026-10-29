package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/serviceapi"
)

func (c Config) validateControl() error {
	if (c.EmailURL == "") != (c.WebhookSecret == "") {
		setting := failure.SettingWebhookSecret
		if c.EmailURL == "" {
			setting = failure.SettingEmailURL
		}
		return failure.WrapSetting("configure invitation email", failure.ServerEmailConfigInvalid, setting,
			errors.New("email URL and webhook secret must be configured together"))
	}
	if c.EmailURL != "" {
		if err := validateHTTPSOrigin(c.EmailURL, "email receiver"); err != nil {
			return failure.WrapSetting("configure email receiver", failure.ServerEmailConfigInvalid, failure.SettingEmailURL, err)
		}
		if _, err := serviceapi.NewBearerSecrets(c.WebhookSecret, ""); err != nil {
			return failure.WrapSetting("configure email webhook", failure.ServerEmailConfigInvalid, failure.SettingWebhookSecret, err)
		}
	}
	if c.WebServiceSecret != "" {
		if c.OIDCIssuer == "" {
			return failure.WrapSetting("configure website identity", failure.ServerWebsiteConfigInvalid, failure.SettingOIDCIssuer,
				errors.New("website identity operations require an OIDC issuer"))
		}
		if _, err := serviceapi.NewBearerSecrets(c.WebServiceSecret, ""); err != nil {
			return failure.WrapSetting("configure website identity", failure.ServerWebsiteConfigInvalid, failure.SettingWebServiceSecret, err)
		}
	}
	if err := validatePostgresURL(c.DatabaseURL); err != nil {
		return failure.WrapSetting("validate pooled database URL", failure.ServerDatabaseURLInvalid, failure.SettingDatabaseURL, err)
	}
	if c.ControlListen == "" {
		return failure.WrapSetting("validate control listen address", failure.ServerListenAddressInvalid,
			failure.SettingControlListen, errors.New("control listen address is required"))
	}
	if c.Role == RoleControl && c.PrivateControlListen == "" {
		return failure.WrapSetting("validate private control listen address", failure.ServerListenAddressInvalid,
			failure.SettingPrivateControlListen, errors.New("private control listen address is required"))
	}
	if c.Role == RoleControl && (c.ControlTLSCertificateFile == "" || c.ControlTLSPrivateKeyFile == "") {
		setting := failure.SettingPrivateControlCert
		if c.ControlTLSCertificateFile != "" {
			setting = failure.SettingPrivateControlKey
		}
		return failure.WrapSetting("configure private control TLS", failure.ServerConfigInvalid, setting,
			errors.New("private control TLS certificate and private key files are required"))
	}
	if err := validateCanonicalHostname(c.ServerDomain, "server domain"); err != nil {
		return err
	}
	if c.ControlURL != "" {
		if err := validateHTTPSOrigin(c.ControlURL, "control URL"); err != nil {
			return err
		}
		origin, _ := url.Parse(c.ControlURL)
		if origin.Hostname() != c.ServerHostname() {
			return errors.New("control URL hostname must match the server control hostname")
		}
	}
	if err := c.ControlProxy().Validate(); err != nil {
		return err
	}
	if err := validateCanonicalHostname(c.ManagedDomain, "managed domain"); err != nil {
		return err
	}
	if c.ManagedURLMode != "" && c.ManagedURLMode != naming.ManagedURLModeSimple && c.ManagedURLMode != naming.ManagedURLModeGenerated {
		return errors.New("managed URL mode must be simple or generated")
	}
	if c.ControlHostname != "" || c.PrivateControlAddress != "" || c.IngressID != "" || c.RelayServiceID != "" || c.RelayID != "" || c.RelayAddress != "" || c.InternalRelayAddress != "" {
		return errors.New("split-process configuration is invalid for control and standalone")
	}
	if c.Role == RoleStandalone {
		if c.ClusterSecret != "" || c.ClusterSecretPrevious != "" {
			return failure.Wrap("validate standalone cluster secret", failure.ServerClusterSecretInvalid,
				errors.New("standalone does not accept a configured cluster secret"))
		}
	} else if _, err := serviceapi.NewBearerSecrets(c.ClusterSecret, c.ClusterSecretPrevious); err != nil {
		return failure.Wrap("validate cluster secret", failure.ServerClusterSecretInvalid, err)
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if _, err := storagekey.New(c.StorageKey, c.StorageKeyPrevious); err != nil {
		return failure.WrapSetting("validate storage key", failure.ServerStorageKeyInvalid, failure.SettingStorageKey, err)
	}
	if err := c.validateACME(); err != nil {
		return err
	}
	if err := c.validateDNSAutomation(); err != nil {
		return err
	}
	if c.ManagedDomainMaxMemberChildLabels < 0 {
		return errors.New("managed-domain-max-member-child-labels must be nonnegative")
	}
	if c.CustomDomainsEnabled && !c.DNSAutomationEnabled() {
		return errors.New("custom domains require managed DNS automation")
	}
	if c.Role == RoleStandalone && c.RelayTLSCertificateFile == "" && c.Route53ServerZoneID == "" {
		return errors.New("standalone requires relay DNS certificate automation or a static relay TLS override")
	}
	if c.AccessTokenLifetime < minimumAccessTokenLifetime || c.AccessTokenLifetime > maximumAccessTokenLifetime {
		return fmt.Errorf("access token lifetime must be between %s and %s", minimumAccessTokenLifetime, maximumAccessTokenLifetime)
	}
	if c.RefreshTokenLifetime < c.AccessTokenLifetime || c.RefreshTokenLifetime > maximumRefreshTokenLifetime {
		return fmt.Errorf("refresh token lifetime must be between the access token lifetime and %s", maximumRefreshTokenLifetime)
	}
	return nil
}

func (c Config) validateACME() (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = failure.Wrap("validate ACME settings", failure.ServerACMEInvalid, retErr)
		}
	}()
	if c.ACMEDirectoryURL == "" || c.ACMEEmail == "" || !c.ACMEAcceptTerms {
		return errors.New("ACME directory, email, and accepted terms are required for control and standalone")
	}
	directory, err := url.Parse(c.ACMEDirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil || directory.Fragment != "" {
		return errors.New("ACME directory must be an HTTPS URL")
	}
	address, err := mail.ParseAddress(c.ACMEEmail)
	if err != nil || address.Address != c.ACMEEmail || address.Name != "" {
		return errors.New("ACME email must be a plain email address")
	}
	if !validDNSLabel(c.ACMEProfile) {
		return errors.New("ACME profile must contain only lowercase letters, digits, and hyphens")
	}
	staticTLS := c.ControlTLSCertificateFile != "" || c.ControlTLSPrivateKeyFile != ""
	if staticTLS && (c.ControlTLSCertificateFile == "" || c.ControlTLSPrivateKeyFile == "") {
		return errors.New("control TLS certificate and private key must be configured together")
	}
	return nil
}

func (c Config) validateDNSAutomation() (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = failure.Wrap("validate DNS automation", failure.ServerDNSConfigInvalid, retErr)
		}
	}()
	configured := c.Route53ManagedZoneID != "" || c.Route53ServerZoneID != "" ||
		len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0
	if !configured {
		return nil
	}
	for _, zone := range []struct{ name, id string }{
		{"managed", c.Route53ManagedZoneID}, {"server", c.Route53ServerZoneID},
	} {
		if zone.id != "" && (strings.TrimSpace(zone.id) != zone.id || strings.ContainsAny(zone.id, "/ ")) {
			return fmt.Errorf("invalid Route 53 %s zone ID: expected a canonical bare hosted zone ID", zone.name)
		}
	}
	if !validDNSLabel(c.Route53Region) {
		return errors.New("invalid Route 53 region")
	}
	if c.Route53ManagedZoneID == "" && (len(c.IngressIPv4Addresses) != 0 || len(c.IngressIPv6Addresses) != 0) {
		return errors.New("ingress IP addresses require a Route 53 managed zone ID")
	}
	if c.Route53ManagedZoneID == "" {
		return nil
	}
	if len(c.IngressIPv4Addresses) == 0 && len(c.IngressIPv6Addresses) == 0 {
		return errors.New("DNS automation requires at least one ingress IP address")
	}
	seen := make(map[netip.Addr]struct{}, len(c.IngressIPv4Addresses)+len(c.IngressIPv6Addresses))
	for _, values := range []struct {
		name string
		want func(netip.Addr) bool
		all  []string
	}{
		{name: "ingress IPv4 address", want: netip.Addr.Is4, all: c.IngressIPv4Addresses},
		{name: "ingress IPv6 address", want: netip.Addr.Is6, all: c.IngressIPv6Addresses},
	} {
		for _, value := range values.all {
			address, err := netip.ParseAddr(value)
			if err != nil || address.String() != value || !values.want(address) {
				return fmt.Errorf("%s %q is not canonical", values.name, value)
			}
			if _, exists := seen[address]; exists {
				return fmt.Errorf("%s %q is configured more than once", values.name, value)
			}
			seen[address] = struct{}{}
		}
	}
	return nil
}
