package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// installed jobs never fall back to a login server profile.
type backgroundPublishFlags struct {
	Install        bool   `name:"install" help:"Register a saved URL with an installed supervisor."`
	Detach         bool   `name:"detach" help:"Run independently of the terminal without automatic restart."`
	DetachedChild  string `name:"detached-child" hidden:"" help:"Internal detached publication ID."`
	System         bool   `name:"system" help:"Use the unattended system supervisor with --install."`
	ServiceName    string `name:"service-name" help:"Name for service start, stop, and remove; defaults to the configured service."`
	SystemStateDir string `name:"system-state-dir" type:"path" help:"Private installed supervisor state directory."`
	ServerCAFile   string `name:"server-ca-file" type:"path" help:"Additional PEM certificate authorities for this job's control server."`
}

func backgroundSelection(flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags) error {
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
	if background.System && flags.Service != "" {
		return publisherCLIError("system publications require an explicit target and system-scoped publisher; project services need user state")
	}
	if flags.serverFromConfig && flags.Service == "" {
		return publisherjob.ErrScope
	}
	if flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo || flags.Ephemeral || flags.Anonymous || flags.access != nil || len(flags.IP) > 0 || flags.Open {
		return publisherjob.ErrScope
	}
	if flags.inspectionModeFromCLI && string(flags.InspectionMode) != "none" {
		return publisherCLIError("installed publications support --inspection-mode=none")
	}
	return nil
}

// runEnrolledBackgroundPublish registers one desired job with an already
// installed supervisor. preflight must precede enrollment and registry writes.
func runEnrolledBackgroundPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, output io.Writer, input io.Reader, executor publisherjob.Executor) error {
	scope := systemStateFlags{System: background.System, SystemStateDir: background.SystemStateDir}
	options, err := scope.options()
	if err != nil {
		return err
	}
	if err := requireInstalledService(ctx, options, executor); err != nil {
		return err
	}
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
	if err := backgroundSelection(flags, selection, background); err != nil {
		return err
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	var id string
	if err := installBackgroundJob(ctx, registry, flags, selection, background, input, publisherjob.Clients, &id); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl publish", id)
}

func installBackgroundJob(ctx context.Context, registry *publisherjob.Registry, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, input io.Reader, clients publisherjob.ClientFactory, installedID *string) error {
	if err := backgroundSelection(flags, selection, background); err != nil {
		return err
	}
	job := publisherjob.Job{Name: background.ServiceName, Server: flags.ServerURL, Target: flags.Target, Protocol: controlv1.PublicURLServiceProtocol(flags.Protocol), TargetTLS: flags.TargetTLS, TargetTLSName: flags.TargetTLSName}
	job.Limits = flags.limits()
	var err error
	job.Server, err = clientstate.CanonicalServer(job.Server)
	if err != nil {
		return publisherjob.ErrScope
	}
	caPath := flags.TargetCAFile
	if caPath != "" && !filepath.IsAbs(caPath) && flags.projectRoot != "" {
		caPath = filepath.Join(flags.projectRoot, caPath)
	}
	job.TargetCAPEM, err = systemTrustInput(caPath)
	if err != nil {
		return err
	}
	job.ServerCAPEM, err = systemTrustInput(background.ServerCAFile)
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
	var serviceScope installedServiceScope
	if flags.Service != "" && (selection.EnrollmentKey != "" || selection.PublisherID != "" || selection.PublisherFile != "") {
		serviceScope, err = resolveConfiguredInstallScope(ctx, flags, nil)
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
		serviceScope = installedServiceScope{hostname: publicURL.CanonicalHostname, teamID: identity.TeamId, domainID: publicURL.DomainId}
	} else {
		profile, err = registry.Profile(ctx, job.Server)
		if err != nil {
			return err
		}
	}
	if selection.EnrollmentKey != "" {
		secret, err := enrollmentKeyInput(selection.EnrollmentKey, input)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			return err
		}
	} else if selection.PublisherID != "" {
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
	if publicURL.Id == "" {
		publicURL, err = native.SavedURL(ctx)
		if err != nil {
			return err
		}
	} // namespace enrollment cannot become an installed saved URL job.
	if publicURL.Ephemeral || publicURL.Purpose != controlv1.App || !publicURL.ServiceProtocol.Valid() {
		return publisherjob.ErrScope
	}
	if flags.Service != "" && !serviceScope.matches(publicURL, identity) {
		return publisherCLIError("publisher grant does not match the configured service public URL")
	}
	if flags.Protocol != "" && flags.Protocol != string(publicURL.ServiceProtocol) {
		return publisherjob.ErrScope
	}
	job.Protocol = publicURL.ServiceProtocol
	if err := validateTCPPublishOptions(flags, job.Protocol); err != nil {
		return err
	}
	job.Target, err = enrolledTarget(publicURL, flags.Target)
	if err != nil {
		return err
	}
	// load the completed enrollment without exporting native adapter private keys.
	// the final job-scoped key remains authenticated by its own public binding.
	if private == nil {
		saved, found, err := profile.PublisherSigningIdentity(ctx, "publisher:"+identity.ClientId)
		if err != nil {
			return err
		}
		if !found {
			return publisherjob.ErrScope
		}
		private = ed25519.PrivateKey(saved.PrivateValue)
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
func selectConfiguredInstalledPublisher(ctx context.Context, flags publishCommand, server string, control nativeauth.NativeControl, authority nativeauth.EnrollmentAuthority) (*nativeauth.Native, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, controlv1.PublicURL, error) {
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	database, err := clientstate.Open(ctx, root)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	defer database.Close()
	ids, err := database.KnownProjectURLs(ctx, flags.projectRoot, server)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	profile, err := database.Server(ctx, server)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	scope, err := resolveConfiguredInstallScope(ctx, flags, database)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, nil, controlv1.PublicURL{}, err
	}
	return selectConfiguredPublisherCandidates(ctx, server, profile, ids, scope, control, authority)
}

func selectConfiguredPublisherCandidates(ctx context.Context, server string, profile *clientstate.Store, ids []string, scope installedServiceScope, control nativeauth.NativeControl, authority nativeauth.EnrollmentAuthority) (*nativeauth.Native, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, controlv1.PublicURL, error) {
	missing := failure.Wrap("select installed publisher", failure.InstalledPublisherSelectionMissing, errors.New("no saved scoped grant matches this configured service"))
	var found *nativeauth.Native
	var selected authorityv1.PublisherEnrollmentResult
	var key ed25519.PrivateKey
	var savedURL controlv1.PublicURL
	for _, id := range ids {
		scope := projectPublisherScope(server, id)
		saved, exists, err := profile.SelectedPublisherIdentity(ctx, "project", scope)
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
		if !scope.matches(item, identity) {
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

type installedServiceScope struct {
	hostname string
	teamID   string
	domainID string
}

func (scope installedServiceScope) matches(item controlv1.PublicURL, identity authorityv1.PublisherEnrollmentResult) bool {
	return scope.hostname != "" && item.CanonicalHostname == scope.hostname &&
		identity.PublicUrlId != nil && *identity.PublicUrlId == item.Id && identity.TeamId == item.TeamId &&
		(scope.teamID == "" || scope.teamID == item.TeamId) && (scope.domainID == "" || scope.domainID == item.DomainId)
}

// a full configured public URL selects one hostname without a login session.
// generated names require the current selected team and ready domain so a
// different team's or worktree's same-label URL cannot be installed.
func resolveConfiguredInstallScope(ctx context.Context, flags publishCommand, state *clientstate.Database) (installedServiceScope, error) {
	effective, err := flags.project.EffectiveService(flags.Service)
	if err != nil || flags.Service == "" {
		return installedServiceScope{}, publisherjob.ErrScope
	}
	if effective.Tunnel != nil && effective.Tunnel.PublicURL != nil && effective.Team == nil {
		hostname, err := naming.ParseExactPublicURL(*effective.Tunnel.PublicURL)
		if err != nil {
			return installedServiceScope{}, publisherjob.ErrScope
		}
		if effective.Tunnel.Domain != nil && hostname != *effective.Tunnel.Domain && !strings.HasSuffix(hostname, "."+*effective.Tunnel.Domain) {
			return installedServiceScope{}, publisherjob.ErrScope
		}
		return installedServiceScope{hostname: hostname}, nil
	}
	if state == nil {
		root, err := clientStateRoot(flags.StateDir)
		if err != nil {
			return installedServiceScope{}, err
		}
		state, err = clientstate.Open(ctx, root)
		if err != nil {
			return installedServiceScope{}, err
		}
		defer state.Close()
	}
	server := flags.ServerURL
	effective.Server = &server
	resolver := newProjectMetadataResolver(state, flags.project, nil, io.Discard, "tnl publish")
	resolver.silent = true
	_, current, err := resolver.resolveContext(ctx, effective)
	if err != nil {
		return installedServiceScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	return configuredInstallScopeForTeam(flags.project, flags.Service, current)
}

func configuredInstallScopeForTeam(project projectConfiguration, name string, current teamContext) (installedServiceScope, error) {
	effective, err := project.EffectiveService(name)
	if err != nil {
		return installedServiceScope{}, err
	}
	service, err := configuredProjectService(name, project.Worktree, effective, current)
	if err != nil {
		return installedServiceScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	var domain authorityv1.Domain
	if effective.Tunnel != nil && effective.Tunnel.PublicURL != nil {
		domain, err = readyDomainForHostname(current.domains, service.Hostname)
	} else {
		selected := ""
		if effective.Tunnel != nil && effective.Tunnel.Domain != nil {
			selected = *effective.Tunnel.Domain
		}
		domain, err = readyDomain(current, selected)
	}
	if err != nil {
		return installedServiceScope{}, failure.Wrap("select configured service", failure.InstalledServiceIdentityUnavailable, err)
	}
	return installedServiceScope{hostname: service.Hostname, teamID: current.team.Id, domainID: domain.Id}, nil
}

func systemTrustInput(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	value, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(value) > 128<<10 {
		return nil, publisherjob.ErrScope
	}
	return value, nil
}
