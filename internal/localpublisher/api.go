// package localpublisher owns the project publisher process and its local API.
package localpublisher

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Options = runtimeOptions
type Endpoint = localPublisherEndpoint
type Settings = tunnelFlags
type MetadataResolver = projectMetadataResolver
type DockerResolver = dockerPublishResolver

func Serve(ctx context.Context, options Options) error { return runRuntimeServe(ctx, options) }
func WriteEndpoint(ctx context.Context, options Options, output io.Writer) error {
	return runRuntimeEndpoint(ctx, options, output)
}
func ResolveProject(ctx context.Context, options Options) (projectconfig.Project, string, error) {
	project, state, err := runtimeProject(ctx, options)
	return project.Project, state, err
}
func Key(project, state string) (string, error)      { return runtimeKey(project, state) }
func Available(ctx context.Context, key string) bool { return runtimeAvailable(ctx, key) }
func OwnerEndpointPath(key string) string            { return runtimeTCPEndpointPath(key) }
func AppEndpointPath(key, service string) string     { return runtimeAppEndpointPath(key, service) }
func AdHocEndpointPath(key string) string            { return runtimeAdHocEndpointPath(key) }
func ReadEndpoint(key string) (Endpoint, error)      { return readRuntimeTCPEndpoint(key) }
func WriteDescriptor(path string, endpoint Endpoint) error {
	return writeRuntimeTCPEndpoint(path, endpoint)
}
func Credential() (string, error) { return publisherCredential() }
func ConfiguredServices(project projectconfig.Project) []clientruntime.Service {
	return configuredRuntimeServices(projectConfiguration{project})
}
func SelectedEndpoint(ctx context.Context, project projectconfig.Project) (Endpoint, error) {
	return selectedPublisherEndpoint(ctx, projectConfiguration{project})
}
func RemoteScope(ctx context.Context, project projectconfig.Project, app, adHoc bool, service string) (Endpoint, error) {
	return remotePublisherScope(ctx, projectConfiguration{project}, app, adHoc, service)
}
func ReadOwnerCredential(root, selected string) (string, error) {
	return readPublisherOwnerCredential(root, selected)
}
func HTTPClient(timeoutDuration time.Duration) *http.Client {
	return publisherHTTPClient(timeoutDuration)
}
func NormalizeTarget(target string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	return normalizePublishTarget(target, protocol)
}
func SavedPublicAddress(route controlv1.PublicURL) (string, error) {
	if !route.ServiceProtocol.Valid() {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid, errors.New("control returned a public URL with an unknown service protocol"))
	}
	if route.ServiceProtocol != controlv1.Http {
		if route.PublicPort == nil || !tcpport.Valid(*route.PublicPort) {
			return "", failure.Wrap("read TCP public URL", failure.ServerResponseInvalid, errors.New("control returned a TCP public URL without a public port"))
		}
		return net.JoinHostPort(route.CanonicalHostname, strconv.Itoa(*route.PublicPort)), nil
	}
	if route.PublicPort != nil {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid, errors.New("control returned an HTTP public URL with a public TCP port"))
	}
	return "https://" + route.CanonicalHostname, nil
}

// handler composes an API around managers whose lifetimes remain with the caller.
func Handler(project projectconfig.Project, state *clientstate.Database, manager *clientruntime.Manager, adHoc *clientruntime.AdHocManager, authHTTP *http.Client) http.Handler {
	return (&appRuntime{project: projectConfiguration{project}, state: state, manager: manager, adhoc: adHoc,
		authHTTP: authHTTP, prepared: map[string]appPreparation{}}).handler()
}
func StartAPI(key string, handler http.Handler, listen, owner string, services ...clientruntime.Service) (*http.Server, <-chan error, error) {
	return startRuntimeTCPWithOptions(key, handler, listen, owner, services...)
}
func StopAPI(ctx context.Context, server *http.Server, key string) error {
	return stopRuntimeTCP(ctx, server, key)
}

func (p Services) Config(target string, prefixes []string, limits publisher.ApplicationLimits, traffic ...trafficlimits.Selection) publisher.Config {
	return p.config(target, prefixes, limits, traffic...)
}
func PrepareServices(ctx context.Context, state *clientstate.Database, server, publicURL, name, domain, team string, ephemeral bool, auth *clientauth.Client) (Services, error) {
	return preparePublisherServices(ctx, state, server, publicURL, name, domain, team, ephemeral, auth)
}
func ResolveIPPolicy(ctx context.Context, control clientIPLookup, prefixes []string, public bool) ([]string, string, error) {
	policy, err := resolveIPPolicy(ctx, control, prefixes, public)
	return policy.prefixes, policy.current, err
}
func EnsurePreview(ctx context.Context, state *clientstate.Database, store *clientstate.Store, control previewControl, server, teamID, project string) (string, error) {
	return ensurePreview(ctx, state, store, control, server, teamID, project)
}

type TeamFacts struct {
	Team       authorityv1.Team
	Membership authorityv1.Membership
	Domains    []authorityv1.Domain
	Mode       naming.ManagedURLMode
	Builtin    bool
}

func (c teamContext) facts() TeamFacts {
	return TeamFacts{c.team, c.membership, c.domains, c.mode, c.builtin}
}
func teamFromFacts(c TeamFacts) teamContext {
	return teamContext{c.Team, c.Membership, c.Domains, c.Mode, c.Builtin}
}

type TeamSelection struct {
	Store                     *clientstate.Store
	Authenticated             *clientauth.Client
	API                       teamAPI
	Identity                  authorityv1.IdentityContext
	ProjectTeam, SelectedTeam string
}

func (s TeamSelection) session() *teamSession {
	return &teamSession{s.Store, s.Authenticated, s.API, s.Identity, s.ProjectTeam, s.SelectedTeam}
}
func (s TeamSelection) Current(ctx context.Context, domains bool) (TeamFacts, error) {
	var current teamContext
	var err error
	if domains {
		current, err = s.session().currentWithDomains(ctx)
	} else {
		current, err = s.session().current(ctx)
	}
	return current.facts(), err
}
func (s TeamSelection) CurrentMembership(ctx context.Context) (authorityv1.Membership, error) {
	return s.session().currentMembership(ctx)
}
func (s TeamSelection) ResolveMembership(ctx context.Context, team string) (authorityv1.Membership, error) {
	return s.session().resolveMembership(ctx, team)
}
func ResolveHostname(url, name, domain string, current TeamFacts) (string, authorityv1.Domain, controlv1.PublicURLScope, error) {
	return resolvePublishHostname(url, name, domain, teamFromFacts(current))
}
func ReadyDomain(current TeamFacts, selected string) (authorityv1.Domain, error) {
	return readyDomain(teamFromFacts(current), selected)
}
func Namespace(current TeamFacts, domain authorityv1.Domain) (string, bool) {
	return teamFromFacts(current).namespace(domain)
}
func ConfiguredProjectService(service string, worktree projectconfig.Worktree, effective config.TNL, current TeamFacts) (projectmeta.Service, error) {
	return configuredProjectService(service, worktree, effective, teamFromFacts(current))
}

func NewMetadataResolver(state *clientstate.Database, project projectconfig.Project, authenticate func(context.Context, string) (*clientauth.Client, error)) *MetadataResolver {
	resolver := newProjectMetadataResolver(state, projectConfiguration{project})
	resolver.authenticate = authenticate
	return resolver
}
func (r *projectMetadataResolver) Server(ctx context.Context, configured *string) (string, error) {
	return r.server(ctx, configured)
}
func (r *projectMetadataResolver) Client(ctx context.Context, server string) (*clientauth.Client, error) {
	return r.client(ctx, server)
}
func (r *projectMetadataResolver) ResolveContext(ctx context.Context, effective config.TNL) (*clientauth.Client, TeamFacts, error) {
	client, current, err := r.resolveContext(ctx, effective)
	return client, current.facts(), err
}
func NewDockerResolver(ctx context.Context, root string, selection config.DockerSelection, label string, http bool) *DockerResolver {
	return newDockerPublishResolver(ctx, root, dockerPublishTarget{selection, label}, http)
}
func (r *dockerPublishResolver) Initial() (string, error) { return r.initial() }
func (r *dockerPublishResolver) Target() string           { return r.target() }

func (f tunnelFlags) Limits() publisher.ApplicationLimits          { return f.limits() }
func (f tunnelFlags) Traffic() (trafficlimits.Selection, error)    { return f.traffic() }
func (f tunnelFlags) InspectionPolicy() (inspection.Policy, error) { return f.inspectionPolicy() }

type SettingSources struct{ AllowAllIPs, Ephemeral, InspectionMode, InspectionRetention, InspectionMaxBytes bool }

func (f *tunnelFlags) SetSources(s SettingSources) {
	f.allowAllIPsFromCLI, f.ephemeralFromCLI = s.AllowAllIPs, s.Ephemeral
	f.inspectionModeFromCLI, f.inspectionRetentionFromCLI, f.inspectionMaxBytesFromCLI = s.InspectionMode, s.InspectionRetention, s.InspectionMaxBytes
}
func ApplyTunnel(settings *Settings, tunnel *config.Tunnel, protocol ...string) {
	applyTunnelConfiguration(settings, tunnel, protocol...)
}
func ApplyLimits(settings *Settings, limits *config.Limits, protocol ...string) {
	applyTunnelLimits(settings, limits, protocol...)
}
func ApplyInspection(settings *Settings, effective config.TNL) { applyInspection(settings, effective) }
func InspectionRoots(ctx context.Context, project string) (string, string, error) {
	return inspectionRoots(ctx, project)
}
func NewInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string, settings Settings) (*clientstate.InspectionRecorder, error) {
	return newInspectionRecorder(ctx, tunnel, project, service, settings)
}
func HTTPObservation(recorder *clientstate.InspectionRecorder) func(publisher.RequestObservation) {
	return httpObservation(recorder)
}
func SQLObservation(recorder *clientstate.InspectionRecorder, mode config.InspectionMode) func(publisher.DatabaseObservation) {
	return sqlObservation(recorder, mode)
}

func IntegrationGroup(project projectconfig.Project, namespace string) string {
	return projectIntegrationGroup(project, namespace)
}
func OAuthServices(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server, team string, auth *clientauth.Client) (projectmeta.IntegrationOrigin, Services, error) {
	return projectOAuthPublisher(ctx, state, project, server, team, auth)
}
func IntegrationConfig(services Services, hostname string, purpose controlv1.PublicURLPurpose) publisher.Config {
	return integrationURLConfig(services, hostname, purpose)
}
func StartOAuth(ctx context.Context, state *clientstate.Database, services Services, origin projectmeta.IntegrationOrigin, tunnel *clientstate.Tunnel, progress Progress, reporter IntegrationReporter) func() {
	return startOAuthIntegrationURL(ctx, state, services, origin, tunnel, &publishOutput{progress}, reporter)
}
func StartWebhooks(ctx context.Context, state *clientstate.Database, services Services, project projectconfig.Project, tunnel *clientstate.Tunnel, service, group string, progress Progress, reporter IntegrationReporter) func() {
	return startWebhookIntegrationURL(ctx, state, services, project, tunnel, service, group, &publishOutput{progress}, reporter)
}
func ReadyWebhookDelivery(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook) string {
	return readyWebhookDelivery(ctx, state, server, group, hostname, definitions)
}
func PrepareAlias(ctx context.Context, state *clientstate.Database, project projectconfig.Project, name string, alias config.Alias, server, team string, auth *clientauth.Client) (Services, error) {
	return prepareAliasServices(ctx, state, projectConfiguration{project}, name, alias, server, team, auth)
}
func CheckAliasPolicy(services Services) error { return checkAliasHostnamePolicy(services) }
func AliasScope(project projectconfig.Project, name string, services Services) clientstate.AliasScope {
	return aliasScope(projectConfiguration{project}, name, services)
}
func RegisterAlias(ctx context.Context, state *clientstate.Database, project projectconfig.Project, name string, definition config.Alias, services Services, tunnelID, group string) (clientstate.AliasSelection, error) {
	return registerProjectAlias(ctx, state, projectConfiguration{project}, name, definition, services, tunnelID, group)
}
func AliasChoiceError(err error) error { return aliasChoiceError(err) }
func StartAliases(ctx context.Context, state *clientstate.Database, project projectconfig.Project, service, team string, parent Services, base publisher.Config, group string, tunnel *clientstate.Tunnel, progress Progress) func() {
	return startProjectAliases(ctx, state, projectConfiguration{project}, service, team, parent, base, group, tunnel, &publishOutput{progress})
}
