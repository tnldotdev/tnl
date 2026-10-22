package invocation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	privatepublisher "github.com/tnldotdev/tnl/internal/publisher/managed"
	publisherprovision "github.com/tnldotdev/tnl/internal/publisher/setup"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func SigningIdentity(ctx context.Context, profile *clientstate.Store, id string) (authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey, error) {
	saved, found, err := profile.PublisherIdentity(ctx, id)
	if err != nil {
		return authorityv1.PublisherEnrollmentResult{}, nil, err
	}
	var identity authorityv1.PublisherEnrollmentResult
	if !found || json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != id || saved.ID != id || len(saved.SigningKey) != ed25519.PrivateKeySize {
		return identity, nil, nativeauth.ErrScope
	}
	return identity, ed25519.PrivateKey(saved.SigningKey), nil
}

// private publication never reserves a hostname or asks for a visitor certificate.
// only the person's session creates saved state; runs use the exact signed grant.
func PublishPrivate(ctx context.Context, flags PrivateOptions, output *PrivatePresentation) error {
	project := projectConfiguration{Project: flags.Project, targetResolver: flags.Resolver}
	protocol, err := privatePublishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if protocol == controlv1.PrivateHttp && !flags.ConfiguredPrivate || flags.Demo {
		return publisherCLIError("private HTTP requires a configured service without publicURL; select tcp, mysql, or postgres for an opaque target")
	}
	if flags.System && !flags.Install || flags.ServiceName != "" && !flags.Install || flags.SystemStateDir != "" && !flags.Install || flags.ServerCAFile != "" && !flags.Install {
		return publisherCLIError("--system, --service-name, --system-state-dir, and --server-ca-file require --install")
	}
	var options publisherjob.ServiceOptions
	if flags.Install {
		options = flags.Installation
	}
	serverCAPEM, err := publisherprovision.ReadTrust(flags.ServerCAFile)
	if err != nil {
		return err
	}
	if err := publisherjob.ValidateTrust(serverCAPEM); err != nil {
		return err
	}
	if flags.Service != "" {
		definition := project.Config.Services[flags.Service]
		if config.Protocol(definition) != string(protocol) {
			return publisherCLIError("--protocol differs from the configured private service")
		}
		if config.TargetType(definition) == "app" {
			return publisherCLIError("private publication requires an address, Docker, or Compose target")
		}
		resolved, err := targetplan.ResolveTarget(ctx, project.Project, flags.Service, flags.Resolver)
		if err != nil {
			return err
		}
		if resolved.Target == nil {
			return publisherCLIError("private target has not been discovered")
		}
		flags.Target = string(*resolved.Target)
	}
	target, err := targetplan.NormalizePrivateAddress(flags.Target, protocol)
	if err != nil {
		return err
	}
	trust, err := CapturePrivateTargetTrust(ctx, flags, protocol, target)
	if err != nil {
		return err
	}
	selected := 0
	for _, value := range []string{flags.EnrollmentKey, flags.PublisherID, flags.PublisherFile} {
		if value != "" {
			selected++
		}
	}
	if selected > 1 || selected != 0 && (flags.AccessToken != "" || flags.Team != "" || flags.Name != "") {
		return publisherCLIError("select one scoped publisher identity, or sign in and name a private service")
	}
	if selected != 0 && flags.Domain != "" {
		return publisherCLIError("scoped publishers use the saved service domain")
	}
	if flags.PublisherFile != "" {
		file, err := credentialfile.Read(flags.PublisherFile)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" {
			server, err := naming.CanonicalControlURL(flags.ServerURL)
			if err != nil || server != file.ControlURL {
				return nativeauth.ErrScope
			}
		}
		flags.ServerURL = file.ControlURL
	}
	if flags.System && (selected != 1 || flags.Service != "" || flags.ServerURL == "") {
		return publisherCLIError("system publications require an explicit server, target, and scoped publisher")
	}
	if selected == 0 || flags.Service != "" || flags.TargetTLS != nil || flags.TargetTLSName != "" || flags.TargetCAFile != "" {
		if err := targetplan.PreflightPrivate(ctx, targetplan.PrivateTargetPlan{Protocol: config.ProtocolName(protocol), Target: target, Trust: trust}); err != nil {
			return err
		}
	}
	var registry *publisherjob.Registry
	if flags.Install {
		registry, err = publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
		if err != nil {
			return err
		}
		defer registry.Close()
	}
	var server string
	var profile *clientstate.Store
	var database *clientstate.Database
	if flags.System {
		server, err = clientstate.CanonicalServer(flags.ServerURL)
		if err != nil {
			return err
		}
		profile, err = registry.Profile(ctx, server)
		if err != nil {
			return err
		}
	} else {
		server, database, err = resolveServer(ctx, flags.StateDir, flags.ServerURL)
		if err != nil {
			return err
		}
		defer database.Close()
		profile, err = database.Server(ctx, server)
		if err != nil {
			return err
		}
	}
	control, authority, err := publisherjob.Clients(publisherjob.Job{Server: server, ServerCAPEM: serverCAPEM})
	if err != nil {
		return err
	}
	var native *nativeauth.Native
	var identity authorityv1.PublisherEnrollmentResult
	var signing ed25519.PrivateKey
	name := flags.Name
	if flags.Service != "" {
		name = config.ServiceName(flags.Service, project.Config.Services[flags.Service])
	}
	if selected == 0 {
		if !naming.ValidServiceName(name) {
			return publisherCLIError("select a configured private service or pass --name NAME")
		}
		if err := clientauth.RequireSignInOutsideDemo(ctx, database, server, flags.AccessToken); err != nil {
			return err
		}
		authenticated, err := flags.Authenticate(ctx, database, server, flags.AccessToken)
		if err != nil {
			return err
		}
		currentIdentity, err := authenticated.Authority.IdentityContext(ctx)
		if err != nil {
			return err
		}
		team := flags.SelectedTeam
		if flags.Team != "" {
			team = flags.Team
		}
		session := clientteam.NewSession(nil, profile, authenticated, currentIdentity, clientteam.Options{SelectedTeam: team})
		selectedContext, err := session.Current(ctx)
		if err != nil {
			return err
		}
		current := FromTeamContext(selectedContext)
		services, err := authenticated.Control.ListPrivateServices(ctx, current.team.Id)
		if err != nil {
			return err
		}
		var service controlv1.PrivateService
		if flags.Service != "" {
			realized, err := RealizeLocalService(ctx, authenticated.Control, LocalService{Project: project.Project, Team: current, Name: flags.Service, Domain: flags.Domain, TargetResolver: flags.Resolver})
			if err != nil {
				return err
			}
			service, err = authenticated.Control.GetPrivateService(ctx, realized.ServiceId)
			if err != nil {
				return err
			}
		} else {
			worktree := project.LocalWorktreeKey()
			label := project.Worktree.Label.FullLabel
			domain, err := selectedContext.ReadyDomain(flags.Domain)
			if err != nil {
				return err
			}
			for _, item := range services {
				if item.Name != name || item.Placement == nil || item.Placement.WorktreeKey == nil || *item.Placement.WorktreeKey != worktree || item.ManagedTls == nil || item.DomainId == nil {
					continue
				}
				for _, savedDomain := range current.domains {
					if savedDomain.Id != *item.DomainId {
						continue
					}
					owner := naming.MemberNamespace(savedDomain.CanonicalDomain, savedDomain.Kind == "managed", current.membership.ManagedLabel, current.membership.MemberSlug)
					if strings.HasSuffix(item.ManagedTls.Hostname, "."+owner) {
						if flags.Domain != "" && domain.Id != savedDomain.Id {
							return nativeauth.ErrScope
						}
						service, err = authenticated.Control.GetPrivateService(ctx, item.Id)
						if err != nil {
							return err
						}
					}
				}
			}
			if service.Id == "" {
				key, err := randomIdempotencyKey()
				if err != nil {
					return err
				}
				placement := &controlv1.PrivateServicePlacement{DomainId: &domain.Id, WorktreeKey: &worktree}
				if label != "" {
					placement.WorktreeLabel = &label
				}
				service, err = authenticated.Control.CreatePrivateServiceAt(ctx, current.team.Id, name, key, placement,
					controlv1.PrivateServiceMetadata{Protocol: protocol, TargetTls: nativeauth.PrivateServiceTLS(trust), TrustRevision: 1})
				if err != nil {
					return err
				}
			}
		}
		if !service.Enabled || flags.Service == "" && service.Name != name || service.TeamId != current.team.Id {
			return nativeauth.ErrScope
		}
		if err := nativeauth.MatchPrivateServiceDeclaration(service, string(protocol), trust); err != nil {
			return failure.Wrap("match private service declaration", failure.ServerConflict, errors.Join(err, errors.New("saved private service protocol or TLS trust differs from the configured service")))
		}
		native, identity, err = nativeauth.EnsurePrivateServiceOwner(ctx, profile, session.Authenticated().Control, session.Authenticated().Authority, service)
		if err != nil {
			return err
		}
	} else if flags.EnrollmentKey != "" {
		secret, err := EnrollmentKeyInput(flags.EnrollmentKey, flags.EnrollmentInput)
		if err != nil {
			return err
		}
		native, identity, err = nativeauth.EnrollNative(ctx, profile, control, authority, secret)
		if err != nil {
			return err
		}
	} else if flags.PublisherID != "" {
		native, identity, err = nativeauth.LoadNative(ctx, profile, control, authority, flags.PublisherID)
		if err != nil {
			return err
		}
	} else {
		file, err := credentialfile.Read(flags.PublisherFile)
		if err != nil {
			return err
		}
		identity, signing, err = file.Validate()
		if err != nil {
			return err
		}
		native, err = nativeauth.NewNative(control, authority, identity, signing)
		if err != nil {
			return err
		}
	}
	if flags.Install && signing == nil {
		identity, signing, err = SigningIdentity(ctx, profile, identity.ClientId)
		if err != nil {
			return err
		}
	}
	if identity.Kind != authorityv1.PrivateService || identity.PrivateServiceId == nil {
		return publisherCLIError("private publication requires an exact private-service publisher grant")
	}
	approved, err := native.SavedPrivateService(ctx)
	if err != nil {
		return err
	}
	if err := validateProfileService(approved); err != nil {
		return failure.Wrap("read managed service endpoint", failure.ServerResponseInvalid, err)
	}
	if flags.Service != "" {
		source := project.LocalPublicationIdentity()
		if approved.Source == nil || approved.Source.ProjectKey != source.Key || approved.Source.SourceFingerprint != source.Fingerprint || approved.Source.Service != flags.Service || approved.Source.WorktreeKey != project.LocalWorktreeKey() {
			return failure.Wrap("select local service publisher", failure.PublisherGrantMismatch, errors.New("grant differs from local publication identity"))
		}
	}
	// a scoped, ad-hoc publisher uses its saved target trust unless the caller
	// made an explicit local declaration. explicit plaintext is a constraint too.
	if selected != 0 && flags.Service == "" && flags.TargetTLS == nil && flags.TargetTLSName == "" && flags.TargetCAFile == "" {
		trust, err = nativeauth.PrivateServiceTrust(approved)
		if err != nil {
			return err
		}
		if protocol == controlv1.PrivateHttp && trust != nil && !strings.Contains(flags.Target, "://") {
			target = "https://" + strings.TrimPrefix(target, "http://")
		}
		if err := targetplan.PreflightPrivate(ctx, targetplan.PrivateTargetPlan{Protocol: config.ProtocolName(protocol), Target: target, Trust: trust}); err != nil {
			return err
		}
	}
	if err := nativeauth.MatchPrivateServiceDeclaration(approved, string(protocol), trust); err != nil {
		return failure.Wrap("match private service declaration", failure.ServerConflict, errors.Join(err, errors.New("saved private service protocol or TLS trust differs from the local declaration")))
	}
	job := publisherjob.Job{Kind: publisherjob.KindPrivateService, ID: publisherjob.PrivateServiceJobKey(server, *identity.PrivateServiceId), Name: name, Server: server,
		PrivateServiceID: *identity.PrivateServiceId, PublisherID: identity.ClientId, GrantID: identity.GrantId, Target: target, Protocol: config.ProtocolName(protocol), Trust: trust, ServerCAPEM: serverCAPEM,
		TrustRevision: approved.TrustRevision, PublisherPool: approved.PublisherPool}
	job.Limits = flags.Limits
	if flags.Service != "" {
		job.Project, job.ProjectService = &project.Project, flags.Service
	}
	if flags.Install {
		if flags.ServiceName != "" {
			job.Name = flags.ServiceName
		}
		if err := registry.Install(ctx, job, identity, signing); err != nil {
			return err
		}
		jobs, err := registry.List(ctx)
		if err != nil {
			return err
		}
		return output.Installed(jobs, job.ID)
	}
	if output.Starting != nil {
		output.Starting()
	}
	emit := func(state string) error {
		return output.Event(PrivateEvent{State: state, PrivateServiceID: job.PrivateServiceID, Name: name, Target: target, Hostname: approved.ManagedTls.Hostname, Port: approved.ManagedTls.Port})
	}
	if err := emit("starting"); err != nil {
		return err
	}
	if selected != 0 {
		stopRuntime, err := startDeployedPublisher(ctx, native, server)
		if err != nil {
			return err
		}
		defer stopRuntime()
	}
	err = targetplan.PublishPrivate(ctx, job.PrivateTargetPlan(), privatepublisher.RunConfig{Control: native.ManagedRunControl(), State: profile, Access: native.Access, Identity: identity, PrivateServiceID: job.PrivateServiceID, Target: target, Metadata: nativeauth.PrivateServiceMetadata(approved), StreamCapacity: int32(job.Limits.Concurrency),
		Ready: func() error {
			if output.Ready != nil {
				output.Ready()
			}
			return emit("ready")
		}})
	if err != nil && !errors.Is(err, context.Canceled) {
		return failure.Wrap("publish private service", failure.TunnelUnavailable, err)
	}
	return emit("stopped")
}

func CapturePrivateTargetTrust(ctx context.Context, flags PrivateOptions, protocol controlv1.PrivateServiceProtocol, target string) (*privatetrust.Snapshot, error) {
	if flags.Service != "" {
		return flags.Project.CaptureServiceTrust(ctx, nil, flags.Service, target)
	}
	if !(flags.TargetTLS != nil && *flags.TargetTLS || flags.TargetCAFile != "" || flags.TargetTLSName != "") {
		return nil, nil
	}
	setting := config.TrustSource{CA: "system"}
	if flags.TargetTLSName != "" {
		setting.Hostname = &flags.TargetTLSName
	}
	root := flags.ProjectRoot
	if flags.TargetCAFile != "" {
		setting.CA = flags.TargetCAFile
		if filepath.IsAbs(setting.CA) {
			root, setting.CA = filepath.Dir(setting.CA), filepath.Base(setting.CA)
		}
	}
	address, close, err := targetplan.PrivateTarget(ctx, targetplan.PrivateTargetPlan{Protocol: config.ProtocolName(protocol), Target: target})
	if err != nil {
		return nil, err
	}
	close()
	trust, err := privatetrust.NewCache(nil).Capture(ctx, root, address, setting)
	return &trust, err
}
