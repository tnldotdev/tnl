package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"

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
// omitted ssl means the explicitly configured local database uses plaintext.
type LocalConnection struct {
	Schema   int                          `json:"schema"`
	Protocol string                       `json:"protocol"`
	Host     string                       `json:"host"`
	Port     int                          `json:"port"`
	SSL      *connectorruntime.TLSOptions `json:"ssl,omitempty"`
	Binding  string                       `json:"binding"`
}

// ConnectLocal selects only explicitly configured local database listeners.
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
		return nil, errors.New("select a configured local database service")
	}
	if protocol != "postgres" || config.Protocol(service) != protocol {
		return nil, errors.New("local connection requires a matching PostgreSQL service")
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
		address = string(*service.Target.Address)
	default:
		return nil, errors.New("local connection requires an address, compose, or docker target")
	}
	// no DNS lookup or remote address is admitted through the local path.
	trustAddress := address
	if host, port, err := net.SplitHostPort(address); err == nil && host == "localhost" {
		address = net.JoinHostPort("127.0.0.1", port)
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return nil, errors.New("local connection requires a loopback TCP address")
	}
	trust, err := p.CaptureServiceTrust(ctx, name, trustAddress)
	if err != nil {
		return nil, err
	}
	connection := &LocalConnection{Schema: 1, Protocol: protocol, Host: endpoint.Addr().Unmap().String(), Port: int(endpoint.Port())}
	if trust != nil {
		connection.SSL = &connectorruntime.TLSOptions{ServerName: trust.Hostname, RejectUnauthorized: true, CA: string(trust.PEM)}
	}
	encoded, err := json.Marshal([]any{p.Root, name, identity, connection})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	connection.Binding = hex.EncodeToString(digest[:])
	return connection, nil
}
