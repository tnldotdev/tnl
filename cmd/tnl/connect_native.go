package main

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/kubeconfig"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type connectionAuthentication string

const (
	connectionConnector connectionAuthentication = "connector"
)

type nativeConnectionProfile struct {
	Schema            int                      `json:"schema"`
	ServiceID         string                   `json:"private_service_id"`
	Protocol          config.ProtocolName      `json:"protocol"`
	Hostname          string                   `json:"hostname"`
	ManagedPort       int                      `json:"managed_port"`
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

func serviceConnectionProfile(service controlv1.PrivateService, listen string) (nativeConnectionProfile, error) {
	profile := nativeConnectionProfile{Schema: 1, ServiceID: service.Id, Protocol: config.ProtocolName(service.Protocol)}
	if err := validateProfileService(service); err != nil {
		return profile, err
	}
	endpoint := service.ManagedTls
	hostname := endpoint.Hostname
	address, err := connectListen(listen)
	if err != nil {
		return profile, err
	}
	host, port, _ := net.SplitHostPort(address)
	profile.Hostname, profile.Public = hostname, endpoint.Public
	profile.ManagedPort = endpoint.Port
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
		if profile.Port == profile.ManagedPort {
			profile.Instructions = append(profile.Instructions, "browser: map the exact managed hostname to the listener in your local hosts file before opening the HTTPS URL:", host+" "+hostname, profile.URL)
		} else {
			profile.Instructions = append(profile.Instructions, "browser: first run tnl connect with --listen="+net.JoinHostPort(host, strconv.Itoa(profile.ManagedPort))+" and map the exact managed hostname to that loopback IP in your local hosts file; HTTP requires the allocated port in its URL")
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

func validateProfileService(service controlv1.PrivateService) error {
	if !opaqueid.Valid(service.Id, opaqueid.PrivateServicePrefix) || !config.ProtocolName(service.Protocol).Valid() || service.ManagedTls == nil || !service.Enabled {
		return publisherCLIError("service has no managed TLS endpoint; refresh its applied configuration")
	}
	endpoint := service.ManagedTls
	hostname, err := naming.CanonicalizeHostname(endpoint.Hostname)
	if err != nil || hostname != endpoint.Hostname || endpoint.Port < 1024 || endpoint.Port > 65535 {
		return publisherCLIError("service returned an invalid managed TLS endpoint")
	}
	return nil
}

func writeNativeConnection(output io.Writer, profile nativeConnectionProfile, mode statusOutputMode, listen string) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(profile)
	}
	fields := []clioutput.Field{{Label: "service", Value: profile.ServiceID}, {Label: "protocol", Value: string(profile.Protocol)}, {Label: "hostname", Value: profile.Hostname}, {Label: "port", Value: strconv.Itoa(profile.Port)}, {Label: "TLS", Value: profile.TLS}, {Label: "authentication", Value: string(profile.Authentication)}}
	footer := "keep tnl running while using the service"
	if listen != "" {
		fields = append(fields, clioutput.Field{Label: "listen", Value: listen})
		footer = "keep tnl running while using the service"
	}
	if profile.URL != "" {
		label := "url"
		if profile.Protocol == config.ProtocolHTTP {
			label = "curl url"
		}
		fields = append(fields, clioutput.Field{Label: label, Value: profile.URL})
	}
	if profile.DetachedID != "" {
		fields = append(fields, clioutput.Field{Label: "detached ID", Value: profile.DetachedID})
		footer = "stop with tnl detached stop " + profile.DetachedID
	}
	if profile.ServerCAFile != "" {
		fields = append(fields, clioutput.Field{Label: "server CA", Value: profile.ServerCAFile})
	}
	if kube := profile.Kubeconfig; kube != nil {
		fields = append(fields, clioutput.Field{Label: "kubeconfig", Value: kube.File}, clioutput.Field{Label: "context", Value: kube.Context})
		if kube.Namespace != "" {
			fields = append(fields, clioutput.Field{Label: "namespace", Value: kube.Namespace})
		}
		if kube.Qualified {
			footer = "context name was qualified to preserve an existing installation"
		}
	}
	command := make([]string, len(profile.Command))
	for i, argument := range profile.Command {
		command[i] = "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, instruction := range profile.Instructions {
		blocks = append(blocks, clioutput.Text(instruction))
	}
	blocks = append(blocks, clioutput.Section("client command", clioutput.Text(strings.Join(command, " "))))
	return writeHumanFrame(output, "tnl connect", "ready", footer, blocks...)
}
