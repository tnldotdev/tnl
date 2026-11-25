package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/spf13/cobra"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/local"
)

type runtimeCommand struct {
	Connections   connectionsCommand
	Endpoint      runtimeEndpointOptions
	OwnerEndpoint runtimeOptions
	Serve         runtimeOptions
	Publisher     runtimePublisherOptions
}

type runtimeOptions struct {
	telemetry     *clienttelemetry.Collector
	Directory     string `name:"directory" required:"" type:"path"`
	StateDir      string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	SnapshotStdin bool   `name:"snapshot-stdin" hidden:""`
	Publications  bool   `name:"publications" hidden:""`
}

type runtimeEndpointOptions struct {
	runtimeOptions `embed:""`
	Service        string `name:"service"`
	InvocationID   string `name:"invocation-id"`
}

type runtimePublisherOptions struct {
	StateDir   string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Instance   string `name:"instance"`
	ControlURL string `name:"control-url"`
}

func runRuntimePublisher(ctx context.Context, options runtimePublisherOptions, output io.Writer) error {
	return local.ServeSDKPublisher(ctx, local.Options{Directory: ".", StateDir: options.StateDir},
		options.Instance, options.ControlURL, os.Stdin, output)
}

func (o runtimeOptions) settings() local.Options {
	settings := local.Options{Telemetry: o.telemetry, Directory: o.Directory, StateDir: o.StateDir, Publications: o.Publications}
	if o.SnapshotStdin {
		settings.Snapshot = os.Stdin
	}
	return settings
}

func runRuntimeOwnerEndpoint(ctx context.Context, options runtimeOptions, output io.Writer) error {
	endpoint, err := local.OwnerEndpoint(ctx, options.settings())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

func runRuntimeEndpoint(ctx context.Context, options runtimeEndpointOptions, output io.Writer) error {
	endpoint, err := local.Endpoint(ctx, options.settings(), options.Service, options.InvocationID)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

func runRuntimeServe(ctx context.Context, options runtimeOptions) error {
	return local.Serve(ctx, options.settings())
}

func runtimeProject(ctx context.Context, options runtimeOptions) (projectConfiguration, string, error) {
	project, root, err := local.ResolveProject(ctx, options.settings())
	return projectConfiguration{Project: project}, root, err
}

func configuredRuntimeServices(project projectConfiguration) []app.Service {
	return app.ConfiguredServices(project.Project)
}

func (a *commandApp) newRuntimeCommand() *cobra.Command {
	f := a.flags
	cRuntime := &cobra.Command{Use: "runtime", Short: "", Hidden: true}
	cRuntime.AddCommand(a.newRuntimeJobCommand())
	cRuntimeConnections := &cobra.Command{Use: "connections", Short: "", Hidden: true}
	cRuntimeConnectionsCapabilities := &cobra.Command{Use: "capabilities", Short: ""}
	a.leaf(cRuntimeConnectionsCapabilities, &f.Runtime.Connections.Capabilities, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections capabilities", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsCapabilities)
	cRuntimeConnectionsContext := &cobra.Command{Use: "context", Short: ""}
	a.leaf(cRuntimeConnectionsContext, &f.Runtime.Connections.Context, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections context", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsContext)
	cRuntimeConnectionsLocal := &cobra.Command{Use: "local", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsLocal, &f.Runtime.Connections.Local, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections local", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsLocal)
	cRuntimeConnectionsCredential := &cobra.Command{Use: "credential", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsCredential, &f.Runtime.Connections.Credential, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections credential", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsCredential)
	cRuntimeConnectionsManagement := &cobra.Command{Use: "management", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsManagement, &f.Runtime.Connections.Management, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections management", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsManagement)
	cRuntimeConnectionsStart := &cobra.Command{Use: "start", Short: ""}
	a.leaf(cRuntimeConnectionsStart, &f.Runtime.Connections.Start, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections start", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsStart)
	cRuntimeConnectionsIdentity := &cobra.Command{Use: "identity", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsIdentity, &f.Runtime.Connections.Identity, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections identity", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsIdentity)
	cRuntimeConnectionsAttach := &cobra.Command{Use: "attach", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsAttach, &f.Runtime.Connections.Attach, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections attach", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsAttach)
	cRuntimeConnectionsRecover := &cobra.Command{Use: "recover", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsRecover, &f.Runtime.Connections.Recover, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections recover", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsRecover)
	cRuntimeConnectionsServe := &cobra.Command{Use: "serve", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsServe, &f.Runtime.Connections.Serve, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections serve", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsServe)
	cRuntimeConnectionsStatus := &cobra.Command{Use: "status", Short: ""}
	a.leaf(cRuntimeConnectionsStatus, &f.Runtime.Connections.Status, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections status", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsStatus)
	cRuntimeConnectionsRead := &cobra.Command{Use: "read", Short: "Read one prepared connection from its existing owner without starting or authenticating."}
	a.leaf(cRuntimeConnectionsRead, &f.Runtime.Connections.Read, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections read", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsRead)
	cRuntimeConnectionsPrepare := &cobra.Command{Use: "prepare", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsPrepare, &f.Runtime.Connections.Prepare, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections prepare", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsPrepare)
	cRuntimeConnectionsSDKPrepare := &cobra.Command{Use: "sdk-prepare", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsSDKPrepare, &f.Runtime.Connections.SDKPrepare, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections sdk-prepare", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsSDKPrepare)
	cRuntimeConnectionsSDKWorkload := &cobra.Command{Use: "sdk-workload", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsSDKWorkload, &f.Runtime.Connections.SDKWorkload, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections sdk-workload", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsSDKWorkload)
	cRuntimeConnectionsSDKStop := &cobra.Command{Use: "sdk-stop", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsSDKStop, &f.Runtime.Connections.SDKStop, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections sdk-stop", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsSDKStop)
	cRuntimeConnectionsSDKClose := &cobra.Command{Use: "sdk-close", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsSDKClose, &f.Runtime.Connections.SDKClose, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections sdk-close", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsSDKClose)
	cRuntimeConnectionsStop := &cobra.Command{Use: "stop", Short: ""}
	a.leaf(cRuntimeConnectionsStop, &f.Runtime.Connections.Stop, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections stop", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsStop)
	cRuntimeConnectionsKubeCredential := &cobra.Command{Use: "kube-credential", Short: "", Hidden: true}
	a.leaf(cRuntimeConnectionsKubeCredential, &f.Runtime.Connections.KubeCredential, func(call commandCall) error {
		return runConnections(call.ctx, "runtime connections kube-credential", f.Runtime.Connections, a.out)
	})
	cRuntimeConnections.AddCommand(cRuntimeConnectionsKubeCredential)
	cRuntime.AddCommand(cRuntimeConnections)
	cRuntimeEndpoint := &cobra.Command{Use: "endpoint", Short: "", Hidden: true}
	a.leaf(cRuntimeEndpoint, &f.Runtime.Endpoint, func(call commandCall) error {
		return runRuntimeEndpoint(call.ctx, f.Runtime.Endpoint, a.out)
	})
	cRuntime.AddCommand(cRuntimeEndpoint)
	cRuntimeOwnerEndpoint := &cobra.Command{Use: "owner-endpoint", Short: "", Hidden: true}
	a.leaf(cRuntimeOwnerEndpoint, &f.Runtime.OwnerEndpoint, func(call commandCall) error {
		return runRuntimeOwnerEndpoint(call.ctx, f.Runtime.OwnerEndpoint, a.out)
	})
	cRuntime.AddCommand(cRuntimeOwnerEndpoint)
	cRuntimeServe := &cobra.Command{Use: "serve", Short: "", Hidden: true}
	a.leaf(cRuntimeServe, &f.Runtime.Serve, func(call commandCall) error {
		return runRuntimeServe(call.ctx, f.Runtime.Serve)
	})
	cRuntime.AddCommand(cRuntimeServe)
	cRuntimePublisher := &cobra.Command{Use: "publisher", Short: "", Hidden: true}
	a.leaf(cRuntimePublisher, &f.Runtime.Publisher, func(call commandCall) error {
		return runRuntimePublisher(call.ctx, f.Runtime.Publisher, a.out)
	})
	cRuntime.AddCommand(cRuntimePublisher)
	return cRuntime
}
