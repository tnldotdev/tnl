package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/connector"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

type connectionsCommand struct {
	telemetry      *clienttelemetry.Collector
	disabled       bool
	Capabilities   connectionsCapabilities       `cmd:""`
	Context        connectionsContextOptions     `cmd:""`
	Local          connectionsLocalOptions       `cmd:"" hidden:""`
	Credential     struct{}                      `cmd:"" hidden:""`
	Start          connectionsStartOptions       `cmd:""`
	Identity       connectionsContextOptions     `cmd:"" hidden:""`
	Attach         connectionsHandleOptions      `cmd:"" hidden:""`
	Recover        connectionsHandleOptions      `cmd:"" hidden:""`
	Serve          connectionsServeOptions       `cmd:"" hidden:""`
	Status         connectionsHandleOptions      `cmd:""`
	Read           connectionsReadOptions        `cmd:"" help:"Read one prepared connection from its existing owner without starting or authenticating."`
	Prepare        connectionsReadOptions        `cmd:"" hidden:""`
	SDKPrepare     connectionsSDKOptions         `cmd:"" hidden:""`
	SDKWorkload    connectionsSDKWorkloadOptions `cmd:"" hidden:""`
	SDKStop        connectionsSDKStopOptions     `cmd:"" hidden:""`
	SDKClose       connectionsSDKCloseOptions    `cmd:"" hidden:""`
	Stop           connectionsHandleOptions      `cmd:""`
	KubeCredential connectionsKubeOptions        `cmd:"" hidden:""`
}
type connectionsCapabilities struct {
	Output string `name:"output" enum:"json" default:"json"`
}

type connectionsLocalOptions struct {
	Directory string `name:"directory" required:"" type:"path"`
	Service   string `name:"service" required:""`
	Protocol  string `name:"protocol" enum:"http,postgres,mysql,tcp,kubernetes" required:""`
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
	SDKRegistry               string `name:"sdk-registry" hidden:"" type:"path"`
	RequestHandle             string `name:"sdk-request-handle" hidden:"" type:"path"`
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
type connectionsSDKOptions struct {
	connectionsStartOptions `embed:""`
	Registry                string `name:"registry" required:"" type:"path"`
	SelectedService         string `name:"selected-service" required:""`
	RecoverHandle           string `name:"recover-handle" type:"path"`
	RequestedAt             string `name:"requested-at"`
	RetainStartFailure      bool   `name:"retain-start-failure"`
}
type connectionsSDKWorkloadOptions struct {
	Directory string `name:"directory" required:"" type:"path"`
	Service   string `name:"service" required:""`
}
type connectionsSDKStopOptions struct {
	Registry  string `name:"registry" required:"" type:"path"`
	ParentPID int    `name:"parent-pid" required:""`
}

type connectionsSDKCloseOptions struct {
	connectionsSDKStopOptions `embed:""`
	Handle                    string `name:"handle" type:"path"`
	FailureHandle             string `name:"failure-handle"`
	RequestHandle             string `name:"request-handle" type:"path"`
}

func (o connectionsContextOptions) options() connector.ContextOptions {
	return connector.ContextOptions{Directory: o.Directory, Workload: o.Workload, Manifest: o.Manifest, Service: o.Service, TeamID: o.TeamID, StateDir: o.StateDir}
}
func (o connectionsStartOptions) options() connector.OwnerStartOptions {
	return connector.OwnerStartOptions{ContextOptions: o.connectionsContextOptions.options(), RunnerTemp: o.RunnerTemp, ParentPID: o.ParentPID, SDKRegistry: o.SDKRegistry, RequestHandle: o.RequestHandle, KubeTokenFile: o.KubeTokenFile, KubeUserConfig: o.KubeUserConfig, KubeUser: o.KubeUser, Namespace: o.Namespace}
}

func runConnections(ctx context.Context, command string, flags connectionsCommand, output io.Writer) (result error) {
	defer func() {
		if reason := connector.Reason(result); reason != "" {
			result = failure.Wrap("manage connector connections", reason, result)
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
	case "runtime connections credential":
		var request struct {
			Schema  int    `json:"schema"`
			Project string `json:"project"`
			Token   string `json:"token"`
		}
		if connectorruntime.ReadJSON(os.Stdin, &request) != nil || request.Schema != 1 {
			return connectorruntime.ErrInvalid
		}
		credential, err := auth.ParseDeploymentCredential(request.Token)
		if err != nil {
			return err
		}
		if err := credential.SelectProject(request.Project); err != nil {
			return err
		}
		source, err := auth.NewDeploymentTokenSource(credential, nil)
		if err != nil {
			return err
		}
		token, err := source.Token(ctx)
		if err != nil {
			return err
		}
		return write(struct {
			Schema     int       `json:"schema"`
			Server     string    `json:"server"`
			TeamID     string    `json:"team_id"`
			ProjectKey string    `json:"project_key"`
			Token      string    `json:"token"`
			ExpiresAt  time.Time `json:"expires_at"`
		}{1, credential.ControlURL, credential.Approval.TeamId, credential.Approval.ProjectKey, token, source.ExpiresAt()}, nil)
	case "runtime connections local":
		return write(connector.ConnectLocal(ctx, flags.Local.Directory, flags.Local.Service, flags.Local.Protocol, runtimeTargetResolver))
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
		options := flags.Start.options()
		options.TelemetryDisabled = flags.disabled
		return connector.StartOwner(ctx, options, os.Stdin, output)
	case "runtime connections serve":
		operations := connectorOperations()
		operations.Telemetry = flags.telemetry
		return operations.ServeOwner(ctx, connector.OwnerServeOptions{OwnerStartOptions: flags.Serve.options(), OwnerDirectory: flags.Serve.OwnerDirectory}, os.Stdin, output)
	case "runtime connections read":
		return write(connector.ReadPrepared(ctx, flags.Read.Handle, flags.Read.Service))
	case "runtime connections prepare":
		return write(connector.Prepare(ctx, flags.Prepare.Handle, flags.Prepare.Service))
	case "runtime connections sdk-prepare":
		options := flags.SDKPrepare.connectionsStartOptions.options()
		options.TelemetryDisabled = flags.disabled
		return write(connector.PrepareSDK(ctx, connector.SDKOptions{OwnerStartOptions: options, Registry: flags.SDKPrepare.Registry, Service: flags.SDKPrepare.SelectedService, RecoverHandle: flags.SDKPrepare.RecoverHandle, RequestedAt: flags.SDKPrepare.RequestedAt, RetainStartFailure: flags.SDKPrepare.RetainStartFailure}, os.Stdin))
	case "runtime connections sdk-workload":
		return write(connector.SelectSDKWorkload(flags.SDKWorkload.Directory, flags.SDKWorkload.Service, os.Stdin))
	case "runtime connections sdk-stop":
		return stopped(connector.StopSDK(ctx, flags.SDKStop.Registry, flags.SDKStop.ParentPID))
	case "runtime connections sdk-close":
		return stopped(connector.CloseSDK(ctx, connector.SDKCloseOptions{Registry: flags.SDKClose.Registry, ParentPID: flags.SDKClose.ParentPID, Handle: flags.SDKClose.Handle, FailureHandle: flags.SDKClose.FailureHandle, RequestHandle: flags.SDKClose.RequestHandle}))
	case "runtime connections status":
		return write(connector.Status(ctx, flags.Status.Handle))
	case "runtime connections stop":
		return stopped(connector.Stop(ctx, flags.Stop.Handle))
	case "runtime connections kube-credential":
		return write(connector.KubeCredential(ctx, flags.KubeCredential.Handle, flags.KubeCredential.Service))
	}
	return connectorruntime.ErrInvalid
}
