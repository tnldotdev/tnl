package invocation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	publisherprovision "github.com/tnldotdev/tnl/internal/publisher/setup"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// installed jobs never fall back to a login server profile.
type BackgroundSettings struct {
	System         bool
	ServiceName    string
	SystemStateDir string
	ServerCAFile   string
}

func ValidateBackground(flags BackgroundOptions, selection EnrolledSelection, background BackgroundSettings) error {
	if flags.TargetTLS != nil && !*flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "" || strings.HasPrefix(flags.Target, "https://")) {
		return publisherCLIError("target TLS cannot be disabled while target trust is configured")
	}
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherID, selection.PublisherFile} {
		if value != "" {
			selected++
		}
	}
	if flags.ServerURL == "" || selected > 1 {
		return publisherjob.ErrScope
	}
	if selected == 0 && (flags.Service == "" || background.System) {
		return failure.Wrap("select installed publisher", failure.InstalledPublisherSelectionMissing, errors.New("an explicit system-scoped enrollment or publisher identity is required"))
	}
	if flags.ServerFromConfig && flags.Service == "" {
		return publisherjob.ErrScope
	}
	if flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo || flags.Ephemeral || flags.Anonymous || flags.Access != nil || len(flags.IP) > 0 || flags.Open {
		return publisherjob.ErrScope
	}
	if flags.InspectionModeFromCLI && string(flags.InspectionMode) != "none" {
		return failure.Wrap("select installed inspection", failure.PublisherInstallInspection, errors.New("inspection capture selected"))
	}
	return nil
}

// runEnrolledBackgroundPublish stages one exact grant, then hands its private
// credential to the shared installer. no operator session reaches the service.
func InstallEnrolled(ctx context.Context, flags BackgroundOptions, selection EnrolledSelection, background BackgroundSettings, options publisherjob.ServiceOptions, presentation publisherprovision.Presentation, input io.Reader, executor publisherjob.Executor) error {
	if selection.PublisherFile != "" {
		f, err := credentialfile.Read(selection.PublisherFile)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" {
			server, err := naming.CanonicalControlURL(flags.ServerURL)
			if err != nil || server != f.ControlURL {
				return publisherjob.ErrScope
			}
		}
		flags.ServerURL = f.ControlURL
	}
	if flags.Service != "" && flags.ServerURL == "" && !background.System {
		server, state, err := resolveServer(ctx, flags.StateDir, "")
		if err != nil {
			return err
		}
		flags.ServerURL = server
		if err := state.Close(); err != nil {
			return err
		}
	}
	if err := ValidateBackground(flags, selection, background); err != nil {
		return err
	}
	if flags.Protocol == "" || flags.Protocol == "http" {
		target, err := targetplan.NormalizePublicAddress(flags.Target, controlv1.Http)
		if err != nil {
			return err
		}
		trust, err := localproxy.TargetOptionsForCA(flags.TargetCAFile, flags.ProjectRoot)
		if err != nil {
			return err
		}
		trust.ServerName = flags.TargetTLSName
		if err := localproxy.PreflightWithOptions(ctx, target, trust); err != nil {
			return err
		}
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	flags.StateDir = root
	digest := sha256.Sum256([]byte(options.Root))
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: filepath.Join(root, "publisher-install-"+hex.EncodeToString(digest[:12])), User: true})
	if err != nil {
		return err
	}
	defer registry.Close()
	var id string
	if err := InstallBackgroundJob(ctx, registry, flags, selection, background, input, publisherjob.Clients, &id); err != nil {
		return err
	}
	job, err := registry.ResolveJob(ctx, id)
	if err != nil {
		return err
	}
	credential, err := registry.Credential(ctx, job)
	if err != nil {
		return err
	}
	job.VerifyReadiness = job.Kind == publisherjob.KindPublicURL
	if executor != nil {
		options.BinarySource, err = os.Executable()
		if err != nil {
			return err
		}
		return publisherprovision.Register(ctx, options, publisherprovision.Installation{Job: job, Credential: credential}, executor, presentation.Jobs)
	}
	return publisherprovision.DeliverInstallation(ctx, options, publisherprovision.Installation{Job: job, Credential: credential}, presentation)
}

func InstallBackgroundJob(ctx context.Context, registry *publisherjob.Registry, flags BackgroundOptions, selection EnrolledSelection, background BackgroundSettings, input io.Reader, clients publisherjob.ClientFactory, installedID *string) error {
	if err := ValidateBackground(flags, selection, background); err != nil {
		return err
	}
	job := publisherjob.Job{Kind: publisherjob.KindPublicURL, Name: background.ServiceName, Server: flags.ServerURL, Target: flags.Target, Protocol: config.ProtocolName(flags.Protocol), TargetTLSName: flags.TargetTLSName}
	job.ReadinessPath = flags.ReadinessPath
	job.Limits = flags.Limits
	var err error
	job.Server, err = clientstate.CanonicalServer(job.Server)
	if err != nil {
		return publisherjob.ErrScope
	}
	caPath := flags.TargetCAFile
	if caPath != "" && !filepath.IsAbs(caPath) && flags.ProjectRoot != "" {
		caPath = filepath.Join(flags.ProjectRoot, caPath)
	}
	job.TargetCAPEM, err = publisherprovision.ReadTrust(caPath)
	if err != nil {
		return err
	}
	job.ServerCAPEM, err = publisherprovision.ReadTrust(background.ServerCAFile)
	if err != nil {
		return err
	}
	if err := publisherjob.ValidateTrust(job.TargetCAPEM); err != nil {
		return err
	}
	if err := publisherjob.ValidateTrust(job.ServerCAPEM); err != nil {
		return err
	}
	control, authority, err := clients(job)
	if err != nil {
		return err
	}
	var native *nativeauth.Native
	var identity authorityv1.PublisherEnrollmentResult
	var private ed25519.PrivateKey
	var profile *clientstate.Store
	var publicURL controlv1.PublicURL
	var serviceScope InstallScope
	if flags.Service != "" && (selection.EnrollmentKey != "" || selection.PublisherID != "" || selection.PublisherFile != "") {
		serviceScope, err = ResolveConfiguredInstallScope(ctx, flags, nil)
		if err != nil {
			return err
		}
	}
	if selection.EnrollmentKey == "" && selection.PublisherID == "" && selection.PublisherFile == "" {
		native, identity, private, publicURL, err = selectConfiguredInstalledPublisher(ctx, flags, job.Server, control, authority)
		if err != nil {
			return err
		}
		// implicit selection already matched the resolved hostname, team,
		// domain and grant before returning this saved URL.
		serviceScope = InstallScope{Hostname: publicURL.CanonicalHostname, TeamID: identity.TeamId, DomainID: publicURL.DomainId}
	} else {
		profile, err = registry.Profile(ctx, job.Server)
		if err != nil {
			return err
		}
	}
	if selection.EnrollmentKey != "" {
		secret, err := EnrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			return err
		}
	} else if selection.PublisherID != "" {
		// explicit IDs refer to the invoking client's profile. the setup journal
		// is a destination for the exact grant, not a second credential search path.
		root, err := clientStateRoot(flags.StateDir)
		if err != nil {
			return err
		}
		database, err := clientstate.Open(ctx, root)
		if err != nil {
			return err
		}
		defer database.Close()
		profile, err = database.Server(ctx, job.Server)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.LoadNative(ctx, profile, control, authority, selection.PublisherID)
		if err != nil {
			return err
		}
	} else if selection.PublisherFile != "" {
		f, err := credentialfile.Read(selection.PublisherFile)
		if err != nil {
			return err
		}
		identity, private, err = f.Validate()
		if err != nil {
			return err
		}
		native, err = nativeauth.LoadFile(selection.PublisherFile, job.Server, control, authority)
		if err != nil {
			return err
		}
	}
	if identity.Kind == authorityv1.PrivateService {
		flags.ConfiguredPrivate = true
		if identity.PrivateServiceId == nil || flags.Service != "" {
			return publisherjob.ErrScope
		}
		job.Kind, job.PrivateServiceID = publisherjob.KindPrivateService, *identity.PrivateServiceId
		job.ReadinessPath = ""
		job.ID = publisherjob.PrivateServiceJobKey(job.Server, job.PrivateServiceID)
		service, err := native.SavedPrivateService(ctx)
		if err != nil {
			return err
		}
		if err := validateProfileService(service); err != nil {
			return failure.Wrap("read managed service endpoint", failure.ServerResponseInvalid, err)
		}
		if job.Protocol != "" && string(job.Protocol) != string(service.Protocol) {
			return publisherjob.ErrScope
		}
		job.Protocol = config.ProtocolName(service.Protocol)
		if flags.SelectProtocol != nil {
			job.Limits, err = flags.SelectProtocol(string(job.Protocol), true)
			if err != nil {
				return err
			}
		}
		job.Trust, err = nativeauth.PrivateServiceTrust(service)
		if err != nil {
			return err
		}
		if flags.TargetTLS != nil || flags.TargetTLSName != "" || flags.TargetCAFile != "" {
			job.Trust, err = CapturePrivateTargetTrust(ctx, flags.PrivateOptions, service.Protocol, job.Target)
			if err != nil {
				return err
			}
			if err := nativeauth.MatchPrivateServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
				return err
			}
		}
		job.TargetTLSName, job.TargetCAPEM = "", nil
		if err := targetplan.PreflightPrivate(ctx, job.PrivateTargetPlan()); err != nil {
			return err
		}
		job.TrustRevision, job.PublisherPool = service.TrustRevision, service.PublisherPool
		if private == nil {
			_, private, err = SigningIdentity(ctx, profile, identity.ClientId)
			if err != nil {
				return err
			}
		}
		job.PublisherID, job.GrantID = identity.ClientId, identity.GrantId
		if err := registry.Install(ctx, job, identity, private); err != nil {
			return err
		}
		if installedID != nil {
			*installedID = job.ID
		}
		return nil
	}
	if publicURL.Id == "" {
		publicURL, err = native.SavedURL(ctx)
		if err != nil {
			return err
		}
	} // namespace enrollment cannot become an installed saved URL job.
	if publicURL.Ephemeral || publicURL.Purpose != controlv1.App || publicURL.ServiceProtocol != controlv1.Http {
		return publisherjob.ErrScope
	}
	if flags.Service != "" && !serviceScope.Matches(publicURL, identity) {
		return failure.Wrap("select installed service", failure.PublisherGrantMismatch, errors.New("grant differs from configured public URL"))
	}
	if flags.Protocol != "" && flags.Protocol != string(publicURL.ServiceProtocol) {
		return publisherjob.ErrScope
	}
	job.Protocol = config.ProtocolHTTP
	if flags.SelectProtocol != nil {
		if _, err := flags.SelectProtocol(string(job.Protocol), false); err != nil {
			return err
		}
	}
	job.Target, err = targetplan.EnrolledAddress(publicURL, flags.Target)
	if err != nil {
		return err
	}
	// load the completed enrollment without exporting native adapter private keys.
	// the final job-scoped key remains authenticated by its own public binding.
	if private == nil {
		saved, found, err := profile.PublisherIdentity(ctx, identity.ClientId)
		if err != nil {
			return err
		}
		if !found {
			return publisherjob.ErrScope
		}
		private = ed25519.PrivateKey(saved.SigningKey)
	}
	job.PublisherID, job.GrantID, job.PublicURLID = identity.ClientId, identity.GrantId, publicURL.Id
	job.ID = publisherjob.PublicURLJobKey(job.Server, job.PublicURLID)
	if err := registry.Install(ctx, job, identity, private); err != nil {
		return err
	}
	if installedID != nil {
		*installedID = job.ID
	}
	return nil
}

// this never creates or edits a public URL. the project inventory only narrows
// candidates; the saved scoped identity must sign a current read of its exact
// public URL before its key can be copied into user service state.
func selectConfiguredInstalledPublisher(ctx context.Context, flags BackgroundOptions, server string, control nativeauth.NativeControl, authority nativeauth.EnrollmentAuthority) (*nativeauth.Native, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, controlv1.PublicURL, error) {
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	database, err := clientstate.Open(ctx, root)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	defer database.Close()
	ids, err := database.KnownProjectURLs(ctx, flags.ProjectRoot, server)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	profile, err := database.Server(ctx, server)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	scope, err := ResolveConfiguredInstallScope(ctx, flags, database)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	return SelectConfiguredPublisherCandidates(ctx, server, profile, ids, scope, control, authority)
}

func SelectConfiguredPublisherCandidates(ctx context.Context, server string, profile *clientstate.Store, ids []string, scope InstallScope, control nativeauth.NativeControl, authority nativeauth.EnrollmentAuthority) (*nativeauth.Native, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, controlv1.PublicURL, error) {
	missing := failure.Wrap("select installed publisher", failure.InstalledPublisherSelectionMissing, errors.New("no saved scoped grant matches this configured service"))
	var found *nativeauth.Native
	var selected authorityv1.PublisherEnrollmentResult
	var key ed25519.PrivateKey
	var savedURL controlv1.PublicURL
	for _, id := range ids {
		selection := ProjectPublisherScope(server, id)
		saved, exists, err := profile.SelectedPublisherIdentity(ctx, "project", selection)
		if err != nil {
			return nil, selected, nil, savedURL, err
		}
		if !exists {
			continue
		}
		var identity authorityv1.PublisherEnrollmentResult
		if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != saved.ID || identity.PublicUrlId == nil || *identity.PublicUrlId != id || identity.Kind != authorityv1.SavedUrl {
			return nil, selected, nil, savedURL, publisherjob.ErrScope
		}
		native, err := nativeauth.NewNative(control, authority, identity, saved.SigningKey)
		if err != nil {
			return nil, selected, nil, savedURL, err
		}
		item, err := native.SavedURL(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, selected, nil, savedURL, ctx.Err()
			}
			// another configured service may have an expired or revoked grant.
			// it must not prevent selecting a different, live saved URL.
			continue
		}
		if item.Id != id {
			return nil, selected, nil, savedURL, publisherjob.ErrScope
		}
		if !scope.Matches(item, identity) {
			continue
		}
		if found != nil {
			return nil, selected, nil, savedURL, publisherCLIError("more than one saved scoped grant matches this service; select --publisher explicitly")
		}
		found, selected, key, savedURL = native, identity, ed25519.PrivateKey(saved.SigningKey), item
	}
	if found == nil {
		return nil, selected, nil, savedURL, missing
	}
	return found, selected, key, savedURL, nil
}

type InstallScope struct {
	Hostname string
	TeamID   string
	DomainID string
}

func (scope InstallScope) Matches(item controlv1.PublicURL, identity authorityv1.PublisherEnrollmentResult) bool {
	return scope.Hostname != "" && item.CanonicalHostname == scope.Hostname &&
		identity.PublicUrlId != nil && *identity.PublicUrlId == item.Id && identity.TeamId == item.TeamId &&
		(scope.TeamID == "" || scope.TeamID == item.TeamId) && (scope.DomainID == "" || scope.DomainID == item.DomainId)
}

// a full configured public URL selects one hostname without a login session.
// generated names require the current selected team and ready domain so a
// different team's or worktree's same-label URL cannot be installed.
func ResolveConfiguredInstallScope(ctx context.Context, flags BackgroundOptions, state *clientstate.Database) (InstallScope, error) {
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	effective, err := project.EffectiveService(flags.Service)
	if err != nil || flags.Service == "" {
		return InstallScope{}, publisherjob.ErrScope
	}
	if effective.Tunnel != nil && effective.Tunnel.PublicURL != nil && effective.Team == nil {
		hostname, err := naming.ParseExactPublicURL(*effective.Tunnel.PublicURL)
		if err != nil {
			return InstallScope{}, publisherjob.ErrScope
		}
		if effective.Tunnel.Domain != nil && hostname != *effective.Tunnel.Domain && !strings.HasSuffix(hostname, "."+*effective.Tunnel.Domain) {
			return InstallScope{}, publisherjob.ErrScope
		}
		return InstallScope{Hostname: hostname}, nil
	}
	if state == nil {
		root, err := clientStateRoot(flags.StateDir)
		if err != nil {
			return InstallScope{}, err
		}
		state, err = clientstate.Open(ctx, root)
		if err != nil {
			return InstallScope{}, err
		}
		defer state.Close()
	}
	server := flags.ServerURL
	effective.Server = &server
	resolver := resolve.NewMetadataResolver(state, project.Project, authenticateRuntime)
	_, selectedTeam, err := resolver.Context(ctx, effective)
	if err != nil {
		return InstallScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	return ConfiguredInstallScopeForTeam(project.Project, flags.Service, FromTeamContext(selectedTeam))
}

func ConfiguredInstallScopeForTeam(project projectconfig.Project, name string, current TeamSelection) (InstallScope, error) {
	effective, err := project.EffectiveService(name)
	if err != nil {
		return InstallScope{}, err
	}
	service, err := resolve.ConfiguredService(name, project.Worktree, effective, current.Context())
	if err != nil {
		return InstallScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	var domain authorityv1.Domain
	if effective.Tunnel != nil && effective.Tunnel.PublicURL != nil {
		domain, err = team.ReadyDomainForHostname(current.domains, service.Hostname)
	} else {
		selected := ""
		if effective.Tunnel != nil && effective.Tunnel.Domain != nil {
			selected = *effective.Tunnel.Domain
		}
		domain, err = current.Context().ReadyDomain(selected)
	}
	if err != nil {
		return InstallScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	return InstallScope{Hostname: service.Hostname, TeamID: current.team.Id, DomainID: domain.Id}, nil
}
