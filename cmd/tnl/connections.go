package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/connector"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

type connectionsCommand struct {
	Capabilities   connectionsCapabilities   `cmd:""`
	Context        connectionsContextOptions `cmd:""`
	Start          connectionsStartOptions   `cmd:""`
	Identity       connectionsContextOptions `cmd:"" hidden:""`
	Attach         connectionsHandleOptions  `cmd:"" hidden:""`
	Recover        connectionsHandleOptions  `cmd:"" hidden:""`
	Serve          connectionsServeOptions   `cmd:"" hidden:""`
	Status         connectionsHandleOptions  `cmd:""`
	Read           connectionsReadOptions    `cmd:"" help:"Read one prepared connection from its existing owner without starting or authenticating."`
	Prepare        connectionsReadOptions    `cmd:"" hidden:""`
	Stop           connectionsHandleOptions  `cmd:""`
	KubeCredential connectionsKubeOptions    `cmd:"" hidden:""`
}
type connectionsCapabilities struct {
	Output string `name:"output" enum:"json" default:"json"`
}
type connectionsContextOptions struct {
	Directory string   `name:"directory" required:"" type:"path"`
	Workload  string   `name:"workload"`
	Manifest  string   `name:"workload-manifest" type:"path"`
	Service   []string `name:"service"`
	TeamID    string   `name:"team-id"`
	StateDir  string   `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Output    string   `name:"output" enum:"json" default:"json"`
}
type connectionsStartOptions struct {
	connectionsContextOptions `embed:""`
	RunnerTemp                string `name:"runner-temp" env:"RUNNER_TEMP" type:"path"`
	ParentPID                 int    `name:"parent-pid"`
	KubeTokenFile             string `name:"kube-token-file" type:"path"`
	KubeUserConfig            string `name:"kube-user-config" type:"path"`
	KubeUser                  string `name:"kube-user"`
	Namespace                 string `name:"namespace"`
}
type connectionsServeOptions struct {
	connectionsStartOptions `embed:""`
	OwnerDirectory          string `name:"owner-directory" required:"" type:"path"`
}
type connectionsHandleOptions struct {
	Handle string `name:"handle" required:"" type:"path"`
	Output string `name:"output" enum:"json" default:"json"`
}
type connectionsKubeOptions struct {
	connectionsHandleOptions `embed:""`
	Service                  string `name:"service" required:""`
}
type connectionsReadOptions struct {
	connectionsHandleOptions `embed:""`
	Service                  string `name:"service" required:""`
}

func (o connectionsContextOptions) options() connector.ContextOptions {
	return connector.ContextOptions{Directory: o.Directory, Workload: o.Workload, Manifest: o.Manifest, Service: o.Service, TeamID: o.TeamID, StateDir: o.StateDir}
}
func (o connectionsStartOptions) options() connector.OwnerStartOptions {
	return connector.OwnerStartOptions{ContextOptions: o.connectionsContextOptions.options(), RunnerTemp: o.RunnerTemp, ParentPID: o.ParentPID, KubeTokenFile: o.KubeTokenFile, KubeUserConfig: o.KubeUserConfig, KubeUser: o.KubeUser, Namespace: o.Namespace}
}

func runConnections(ctx context.Context, command string, flags connectionsCommand, output io.Writer) (result error) {
	defer func() {
		if reason := connector.Reason(result); reason != "" {
			result = failure.Wrap("manage native connections", reason, result)
		}
	}()
	write := func(value any, err error) error {
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(value)
	}
	stopped := func(err error) error { return write(map[string]any{"schema": 1, "state": "stopped"}, err) }
	switch command {
	case "runtime connections identity":
		identity, err := connector.Identify(ctx, flags.Identity.options(), os.Stdin)
		if err != nil {
			return err
		}
		return write(map[string]any{"schema": 1, "binding": identity.Binding, "assertion_expires_at": identity.AssertionExpiresAt}, nil)
	case "runtime connections attach":
		return write(connector.Attach(ctx, flags.Attach.Handle, os.Stdin))
	case "runtime connections recover":
		return stopped(connectorruntime.OwnerStopped(flags.Recover.Handle))
	case "runtime connections capabilities":
		return write(map[string]any{"schema": 1, "capabilities": []string{"context", "identity", "start", "attach", "status", "stop", "recover", "connect", "prepare", "read", "kube-credential"}, "workload_private": true, "workload_manifest": true, "opaque_private_preflight": true, "team_names": "saved_policy"}, nil)
	case "runtime connections context":
		return write(connector.ResolveContext(ctx, flags.Context.options()))
	case "runtime connections start":
		return connector.StartOwner(ctx, flags.Start.options(), os.Stdin, output)
	case "runtime connections serve":
		return connectorOperations().ServeOwner(ctx, connector.OwnerServeOptions{OwnerStartOptions: flags.Serve.options(), OwnerDirectory: flags.Serve.OwnerDirectory}, os.Stdin, output)
	case "runtime connections read":
		return write(connector.ReadPrepared(ctx, flags.Read.Handle, flags.Read.Service))
	case "runtime connections prepare":
		return write(connector.Prepare(ctx, flags.Prepare.Handle, flags.Prepare.Service))
	case "runtime connections status":
		return write(connector.Status(ctx, flags.Status.Handle))
	case "runtime connections stop":
		return stopped(connector.Stop(ctx, flags.Stop.Handle))
	case "runtime connections kube-credential":
		return write(connector.KubeCredential(ctx, flags.KubeCredential.Handle, flags.KubeCredential.Service))
	}
	return connectorruntime.ErrInvalid
}
