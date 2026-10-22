package connector

import (
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publisherCLIError(message string) error {
	return failure.Wrap("select publisher identity", failure.InvalidTunnelFlags, errors.New(message))
}

type connectionAuthentication string

const (
	connectionConnector connectionAuthentication = "connector"
)

type Profile struct {
	Schema            int                      `json:"schema"`
	ServiceID         string                   `json:"service_id"`
	Protocol          config.ProtocolName      `json:"protocol"`
	Hostname          string                   `json:"hostname"`
	ServicePort       int                      `json:"service_port"`
	Host              string                   `json:"host"`
	Port              int                      `json:"port"`
	Public            bool                     `json:"public"`
	ConnectorRequired bool                     `json:"connector_required"`
	Authentication    connectionAuthentication `json:"authentication"`
	Instructions      []string                 `json:"instructions,omitempty"`
	DetachedID        string                   `json:"detached_id,omitempty"`
	Command           []string                 `json:"command"`
	URL               string                   `json:"url,omitempty"`
	TLS               string                   `json:"tls"`
	ServerCAFile      string                   `json:"server_ca_file,omitempty"`
	Kubeconfig        *kubeconfig.Result       `json:"kubeconfig,omitempty"`
	Namespace         string                   `json:"namespace,omitempty"`
}

func serviceConnectionProfile(service controlv1.Service, listen string) (Profile, error) {
	profile := Profile{Schema: 1, ServiceID: service.Id, Protocol: config.ProtocolName(service.Protocol)}
	if err := ValidateService(service); err != nil {
		return profile, err
	}
	endpoint := service.Endpoint
	hostname := endpoint.Hostname
	address, err := connectListen(listen)
	if err != nil {
		return profile, err
	}
	host, port, _ := net.SplitHostPort(address)
	profile.Hostname, profile.Public = hostname, endpoint.Public
	profile.ServicePort = endpoint.Port
	profile.Host, profile.Port = host, 0
	profile.Port, _ = strconv.Atoi(port)
	profile.ConnectorRequired = true
	profile.Authentication = connectionConnector
	managedAddress := net.JoinHostPort(hostname, port)
	managedOrigin := net.JoinHostPort(hostname, strconv.Itoa(endpoint.Port))
	switch profile.Protocol {
	case config.ProtocolKubernetes:
		profile.TLS = "HTTPS; managed tnl hostname; system roots; independent cluster CA verification by publisher"
		profile.URL = "https://" + managedOrigin
	case config.ProtocolHTTP:
		profile.TLS = "HTTPS with server hostname verification"
		profile.URL = "https://" + managedOrigin + "/"
		profile.Command = []string{"curl", "--noproxy", hostname, "--connect-to", managedOrigin + ":" + address, profile.URL}
		profile.Instructions = []string{"curl below dials the local listener and verifies the managed TLS hostname"}
		if profile.Port == profile.ServicePort {
			profile.Instructions = append(profile.Instructions, "browser: map the exact managed hostname to the listener in your local hosts file before opening the HTTPS URL:", host+" "+hostname, profile.URL)
		} else {
			profile.Instructions = append(profile.Instructions, "browser: first run tnl connect with --listen="+net.JoinHostPort(host, strconv.Itoa(profile.ServicePort))+" and map the exact managed hostname to that loopback IP in your local hosts file; HTTP requires the allocated port in its URL")
		}
	case config.ProtocolPostgres:
		profile.TLS = "PostgreSQL SSLRequest; verify-full; system roots"
		query := url.Values{"hostaddr": {host}, "sslmode": {"verify-full"}, "sslrootcert": {"system"}, "channel_binding": {"disable"}, "gssencmode": {"disable"}}
		endpoint := url.URL{Scheme: "postgresql", Host: managedAddress, Path: "/", RawQuery: query.Encode()}
		profile.Command = []string{"psql", endpoint.String()}
	case config.ProtocolMySQL:
		roots, err := nativeMySQLRoots()
		if err != nil {
			return profile, err
		}
		profile.TLS = "MySQL SSLRequest; VERIFY_IDENTITY; system CA bundle"
		profile.ServerCAFile = roots
		profile.Instructions = []string{"before running mysql, map the exact managed hostname to the listener in /etc/hosts:", host + " " + hostname, "mysql verifies the managed hostname; --host=localhost would verify the wrong identity"}
		profile.Command = []string{"mysql", "--protocol=TCP", "--host=" + hostname, "--port=" + port, "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=" + roots}
	case config.ProtocolTCP:
		profile.TLS = "tnl verifies the service hostname before opaque bytes"
		profile.Command = []string{"nc", host, port}
	}
	return profile, nil
}

// mysql requires an explicit CA file even in VERIFY_IDENTITY mode. use the
// platform/OpenSSL server roots, never control's application-client issuer.
func nativeMySQLRoots() (string, error) {
	paths := []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}
	if selected := os.Getenv("SSL_CERT_FILE"); selected != "" {
		paths = []string{selected}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		_ = file.Close()
		if readErr != nil || len(data) > 4<<20 || !x509.NewCertPool().AppendCertsFromPEM(data) {
			continue
		}
		if absolute, err := filepath.Abs(path); err == nil {
			return absolute, nil
		}
	}
	return "", failure.Wrap("select mysql server roots", failure.ConnectServerRootsUnavailable, os.ErrNotExist)
}

// ValidateService checks the approved managed endpoint before local preparation.
func ValidateService(service controlv1.Service) error {
	if !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || !config.ProtocolName(service.Protocol).Valid() || service.Endpoint == nil || !service.Enabled {
		return publisherCLIError("service has no managed TLS endpoint; refresh its applied configuration")
	}
	endpoint := service.Endpoint
	hostname, err := naming.CanonicalizeHostname(endpoint.Hostname)
	if err != nil || hostname != endpoint.Hostname || endpoint.Port < 1024 || endpoint.Port > 65535 {
		return publisherCLIError("service returned an invalid managed TLS endpoint")
	}
	return nil
}
