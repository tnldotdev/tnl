package main

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/localpublisher"
)

type runtimeCommand struct {
	Endpoint runtimeOptions `cmd:"" hidden:""`
	Serve    runtimeOptions `cmd:"" hidden:""`
}
type runtimeOptions struct {
	Directory string `name:"directory" required:"" type:"path"`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	App       bool   `name:"app" help:"Locate the credential for one configured app."`
	Service   string `name:"service" help:"Configured app service; required when several apps are configured."`
	AdHoc     bool   `name:"ad-hoc" help:"Locate the credential for an ad-hoc invocation."`
	Listen    string `name:"listen" help:"Private listen address of an external project publisher API."`
}

func (o runtimeOptions) options() localpublisher.Options {
	return localpublisher.Options{Directory: o.Directory, StateDir: o.StateDir, App: o.App, Service: o.Service, AdHoc: o.AdHoc, Listen: o.Listen}
}
func runRuntimeServe(ctx context.Context, options runtimeOptions) error {
	return localpublisher.Serve(ctx, options.options())
}
func runRuntimeEndpoint(ctx context.Context, options runtimeOptions, output io.Writer) error {
	return localpublisher.WriteEndpoint(ctx, options.options(), output)
}
func runtimeProject(ctx context.Context, options runtimeOptions) (projectConfiguration, string, error) {
	project, root, err := localpublisher.ResolveProject(ctx, options.options())
	return projectConfiguration{project}, root, err
}
func runtimeKey(project, state string) (string, error) { return localpublisher.Key(project, state) }
func runtimeAvailable(ctx context.Context, key string) bool {
	return localpublisher.Available(ctx, key)
}
func configuredRuntimeServices(project projectConfiguration) []clientruntime.Service {
	return localpublisher.ConfiguredServices(project.Project)
}
func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type localPublisherEndpoint = localpublisher.Endpoint

func runtimeTCPEndpointPath(key string) string { return localpublisher.OwnerEndpointPath(key) }
func runtimeAppEndpointPath(key, service string) string {
	return localpublisher.AppEndpointPath(key, service)
}
func runtimeAdHocEndpointPath(key string) string { return localpublisher.AdHocEndpointPath(key) }
func readRuntimeTCPEndpoint(key string) (localPublisherEndpoint, error) {
	return localpublisher.ReadEndpoint(key)
}
func writeRuntimeTCPEndpoint(path string, endpoint localPublisherEndpoint) error {
	return localpublisher.WriteDescriptor(path, endpoint)
}
func publisherCredential() (string, error) { return localpublisher.Credential() }
func selectedPublisherEndpoint(ctx context.Context, project projectConfiguration) (localPublisherEndpoint, error) {
	return localpublisher.SelectedEndpoint(ctx, project.Project)
}
func remotePublisherScope(ctx context.Context, project projectConfiguration, app, adHoc bool, service string) (localPublisherEndpoint, error) {
	return localpublisher.RemoteScope(ctx, project.Project, app, adHoc, service)
}
func readPublisherOwnerCredential(root, selected string) (string, error) {
	return localpublisher.ReadOwnerCredential(root, selected)
}
func publisherHTTPClient(timeout time.Duration) *http.Client {
	return localpublisher.HTTPClient(timeout)
}
