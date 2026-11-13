package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

// local target discovery is supplied by process composition, not by a connector
// importing the publisher. it must verify container and worktree placement.
type LocalTargetResolver interface {
	ResolveTargetIdentity(context.Context, clientproject.Project, string) (string, string, error)
}

// a local listener has no tunnel identity, serving lease, or control credential.
type LocalConnection struct {
	Schema     int                          `json:"schema"`
	Protocol   string                       `json:"protocol"`
	Host       string                       `json:"host"`
	Port       int                          `json:"port"`
	SSL        *connectorruntime.TLSOptions `json:"ssl,omitempty"`
	URL        string                       `json:"url,omitempty"`
	Server     string                       `json:"server,omitempty"`
	Kubeconfig string                       `json:"kubeconfig,omitempty"`
	Context    string                       `json:"context,omitempty"`
	Binding    string                       `json:"binding"`
}

// ConnectLocal selects only explicitly configured local listeners.
// failure after selection is terminal: never fall back to a saved remote service.
func ConnectLocal(ctx context.Context, directory, name, protocol string, resolver LocalTargetResolver) (_ *LocalConnection, result error) {
	defer func() {
		if result != nil {
			result = failure.Wrap("resolve local connection", failure.TargetUnavailable, result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selection, err := clientproject.SelectProjectConfig(ctx, directory, "", os.Getenv("TNL_CONFIG"), false)
	if err != nil {
		return nil, err
	}
	p, err := clientproject.Resolve(ctx, selection, directory, [32]byte{})
	if err != nil {
		return nil, err
	}
	service, found := p.Config.Services[name]
	if !found || config.PublisherGroupName(service) != "local" || config.IsPublicService(service) {
		return nil, errors.New("select a configured local private service")
	}
	if !config.ValidProtocol(protocol) || config.Protocol(service) != protocol {
		return nil, errors.New("local connection requires a matching service protocol")
	}
	var address string
	var identity string
	switch config.TargetType(service) {
	case "compose", "docker":
		if resolver == nil {
			return nil, errors.New("local container target discovery is required")
		}
		address, identity, err = resolver.ResolveTargetIdentity(ctx, p, name)
		if err != nil {
			return nil, err
		}
		if identity == "" {
			return nil, errors.New("local container target identity is required")
		}
	case "address":
		// the project's target resolver normalizes configured bare ports and
		// HTTP origins; discovered addresses remain bound to their container.
		address = string(*service.Target.Address)
	default:
		return nil, errors.New("local connection requires an address, compose, or docker target")
	}
	resolved, err := p.ResolvePublish(name, address)
	if err != nil {
		return nil, err
	}
	trustAddress := string(*resolved.Target)
	if protocol == "http" || protocol == "kubernetes" {
		origin, err := url.Parse(trustAddress)
		if err != nil || origin.Host == "" || !strings.Contains(origin.Host, ":") {
			return nil, errors.New("local connection requires an HTTP origin")
		}
		address = origin.Host
	} else {
		address = trustAddress
	}
	// no DNS lookup or remote address is admitted through the local path.
	if host, port, err := net.SplitHostPort(address); err == nil && host == "localhost" {
		address = net.JoinHostPort("127.0.0.1", port)
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return nil, errors.New("local connection requires a loopback TCP address")
	}
	trust, err := p.CaptureServiceTrust(ctx, nil, name, trustAddress)
	if err != nil {
		return nil, err
	}
	connection := &LocalConnection{Schema: 1, Protocol: protocol, Host: endpoint.Addr().Unmap().String(), Port: int(endpoint.Port())}
	if trust != nil {
		connection.SSL = &connectorruntime.TLSOptions{ServerName: trust.Hostname, RejectUnauthorized: true, CA: string(trust.PEM)}
	}
	if protocol == "http" || protocol == "kubernetes" {
		scheme := "http"
		if connection.SSL != nil {
			scheme = "https"
		}
		host := connection.Host
		if connection.SSL != nil {
			host = connection.SSL.ServerName
		}
		connection.URL = (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(connection.Port))}).String()
		if protocol == "kubernetes" {
			connection.Server = (&url.URL{Scheme: "https", Host: net.JoinHostPort(connection.Host, strconv.Itoa(connection.Port))}).String()
			connection.URL = ""
			connection.Kubeconfig, connection.Context, err = localKubeconfig(connection.Server, connection.SSL)
			if err != nil {
				return nil, err
			}
		}
	}
	encoded, err := json.Marshal([]any{p.Root, name, identity, connection})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	connection.Binding = hex.EncodeToString(digest[:])
	return connection, nil
}
