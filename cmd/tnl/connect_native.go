package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
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
	connectionMTLS      connectionAuthentication = "mtls"
)

type connectionClientCertificate struct {
	CertificateFile string    `json:"certificate_file"`
	KeyFile         string    `json:"key_file"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type nativeConnectionProfile struct {
	ServiceID         string                       `json:"private_service_id"`
	Protocol          config.ProtocolName          `json:"protocol"`
	Hostname          string                       `json:"hostname"`
	Port              int                          `json:"port"`
	Public            bool                         `json:"public"`
	ConnectorRequired bool                         `json:"connector_required"`
	Authentication    connectionAuthentication     `json:"authentication"`
	ClientCertificate *connectionClientCertificate `json:"client_certificate,omitempty"`
	Command           []string                     `json:"command"`
	URL               string                       `json:"url,omitempty"`
	TLS               string                       `json:"tls"`
	ServerCAFile      string                       `json:"server_ca_file,omitempty"`
	Kubeconfig        *kubeconfig.Result           `json:"kubeconfig,omitempty"`
	Namespace         string                       `json:"namespace,omitempty"`
}

func serviceConnectionProfile(service controlv1.PrivateService, material *clientstate.ServiceClientMaterial) (nativeConnectionProfile, error) {
	profile := nativeConnectionProfile{ServiceID: service.Id, Protocol: config.ProtocolName(service.Protocol)}
	if err := validateProfileService(service); err != nil {
		return profile, err
	}
	endpoint := service.ManagedTls
	hostname := endpoint.Hostname
	profile.Hostname, profile.Port, profile.Public = hostname, endpoint.Port, endpoint.Public
	profile.ConnectorRequired = !profile.Public || profile.Protocol == config.ProtocolTCP
	profile.Authentication = connectionConnector
	if profile.Public {
		profile.Authentication = connectionMTLS
	}
	if !profile.Public && material != nil {
		return profile, publisherCLIError("private clients use connector authentication without an application client certificate")
	}
	if material != nil {
		if material.CertificateFile == "" || material.KeyFile == "" || !material.ExpiresAt.After(time.Now()) {
			return profile, publisherCLIError("service client certificate is unavailable or expired; run tnl connect again")
		}
		profile.ClientCertificate = &connectionClientCertificate{CertificateFile: material.CertificateFile, KeyFile: material.KeyFile, ExpiresAt: material.ExpiresAt}
	}
	if profile.Authentication == connectionMTLS && profile.ClientCertificate == nil {
		return profile, publisherCLIError("public service requires a client certificate; run tnl connect again")
	}
	address := net.JoinHostPort(hostname, strconv.Itoa(endpoint.Port))
	switch profile.Protocol {
	case config.ProtocolKubernetes:
		profile.TLS = "HTTPS; managed tnl hostname; system roots; independent cluster CA verification by publisher"
		profile.URL = "https://" + address
	case config.ProtocolHTTP:
		profile.TLS = "HTTPS with server hostname verification"
		profile.URL = "https://" + address + "/"
		profile.Command = []string{"curl"}
		if material != nil {
			profile.Command = append(profile.Command, "--cert", material.CertificateFile, "--key", material.KeyFile)
		}
		profile.Command = append(profile.Command, profile.URL)
	case config.ProtocolPostgres:
		profile.TLS = "PostgreSQL SSLRequest; verify-full; system roots"
		query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"system"}, "channel_binding": {"disable"}, "gssencmode": {"disable"}}
		if material != nil {
			query.Set("sslcert", material.CertificateFile)
			query.Set("sslkey", material.KeyFile)
		}
		endpoint := url.URL{Scheme: "postgresql", Host: address, Path: "/", RawQuery: query.Encode()}
		profile.Command = []string{"psql", endpoint.String()}
	case config.ProtocolMySQL:
		roots, err := nativeMySQLRoots()
		if err != nil {
			return profile, err
		}
		profile.TLS = "MySQL SSLRequest; VERIFY_IDENTITY; system CA bundle"
		profile.ServerCAFile = roots
		profile.Command = []string{"mysql", "--host=" + hostname, "--port=" + strconv.Itoa(endpoint.Port), "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=" + roots}
		if material != nil {
			profile.Command = append(profile.Command, "--ssl-cert="+material.CertificateFile, "--ssl-key="+material.KeyFile)
		}
	case config.ProtocolTCP:
		profile.TLS = "tnl verifies the service hostname before opaque bytes"
		profile.Command = []string{"tnl", "connect", "start", service.Id, "--stdio"}
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

func ensureConnectCertificate(ctx context.Context, session *teamSession, service string) (clientstate.ServiceClientMaterial, error) {
	identity := session.identity.Identity.Id
	device, err := session.store.EnsureEnrolledVisitorDevice(ctx, identity, session.authenticated.Control.EnrollVisitorDevice)
	if err != nil {
		return clientstate.ServiceClientMaterial{}, err
	}
	return session.store.EnsureServiceClientCertificate(ctx, identity, service, device.ID, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		return session.authenticated.Control.IssueServiceClientCertificate(ctx, service, device.ID, csr)
	})
}

func writeNativeConnection(output io.Writer, profile nativeConnectionProfile, mode statusOutputMode, listen string) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(profile)
	}
	fields := []clioutput.Field{{Label: "service", Value: profile.ServiceID}, {Label: "protocol", Value: string(profile.Protocol)}, {Label: "hostname", Value: profile.Hostname}, {Label: "port", Value: strconv.Itoa(profile.Port)}, {Label: "TLS", Value: profile.TLS}, {Label: "authentication", Value: string(profile.Authentication)}}
	footer := "connect directly with the native client"
	if listen != "" {
		fields = append(fields, clioutput.Field{Label: "listen", Value: listen})
		footer = "keep tnl running while using the service"
	}
	if profile.URL != "" {
		fields = append(fields, clioutput.Field{Label: "url", Value: profile.URL})
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
	if material := profile.ClientCertificate; material != nil {
		fields = append(fields, clioutput.Field{Label: "certificate", Value: material.CertificateFile}, clioutput.Field{Label: "key file", Value: material.KeyFile}, clioutput.Field{Label: "expires", Value: material.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	command := make([]string, len(profile.Command))
	for i, argument := range profile.Command {
		command[i] = "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
	}
	return writeHumanFrame(output, "tnl connect", "ready", footer, clioutput.Fields(fields...), clioutput.Section("client command", clioutput.Text(strings.Join(command, " "))))
}
