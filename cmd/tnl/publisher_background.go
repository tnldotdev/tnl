package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherStopCommand struct {
	Server string `name:"server" required:"" help:"Control URL of the enrolled publisher."`
	ID     string `arg:"" name:"public-url-id" required:"" help:"Saved public URL ID of the job."`
}

func runBackgroundEnrollment(ctx context.Context, flags publishCommand, out io.Writer, input io.Reader) error {
	if flags.EnrollKey == "" || flags.ServerURL == "" || flags.PublishCredential != "" || flags.AccessToken != "" || flags.Demo || flags.Ephemeral || flags.Name != "" || flags.Team != "" || flags.Domain != "" || flags.PublicURL != "" || flags.AllowAllIPs || len(flags.AllowIP) != 0 || flags.TargetCAFile != "" || flags.TargetTLS || flags.TargetTLSName != "" || flags.Protocol != "" {
		return failure.Wrap("validate background publisher", failure.InvalidTunnelFlags, errors.New("--bg needs --enroll-key, --server, and a saved URL target without project or policy options"))
	}
	server, err := clientstate.CanonicalServer(flags.ServerURL)
	if err != nil {
		return err
	}
	store, err := publisherjob.Open(publisherjob.Dir())
	if err != nil {
		return err
	}
	key, err := enrollmentKeyInput(flags.EnrollKey, input)
	if err != nil {
		return err
	}
	authority, err := authorityclient.New(server, nil, "")
	if err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity, err := authority.RedeemPublisherEnrollment(ctx, key, public)
	if err != nil {
		return err
	}
	if err := publisherjob.ValidJob(publisherjob.Job{Identity: identity}); err != nil ||
		!opaqueid.Valid(identity.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(identity.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		!opaqueid.Valid(identity.GrantId, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(*identity.PublicUrlId, opaqueid.PublicURLPrefix) {
		return failure.Wrap("validate enrollment", failure.ServerResponseInvalid, errors.New("control returned an invalid saved URL enrollment"))
	}
	client, err := controlclient.New(server, nil, "")
	if err != nil {
		return err
	}
	control := &enrolledControl{Client: client, authority: authority, private: private, identity: identity}
	token, err := control.access(ctx)
	if err != nil {
		return err
	}
	route, err := client.PublisherPublicURL(ctx, token)
	if err != nil {
		return err
	}
	if route.Id != *identity.PublicUrlId || route.TeamId != identity.TeamId || route.Ephemeral || route.Purpose != controlv1.App || route.LifecycleState != controlv1.Enabled {
		return failure.Wrap("validate publisher scope", failure.ServerResponseInvalid, errors.New("enrollment does not select an enabled saved app URL"))
	}
	protocol := route.ServiceProtocol
	if protocol == "" {
		protocol = controlv1.Http
	}
	target, err := selectScopedPublishTargetForProtocol(route.Target, flags.Target, protocol)
	if err != nil {
		return err
	}
	if err := store.Add(publisherjob.Job{Server: server, Target: target, Identity: identity, Private: private}); err != nil {
		return err
	}
	if err := publisherjob.Install(ctx, store); err != nil {
		return fmt.Errorf("publisher job saved; run 'sudo tnl publisher service install' to start it: %w", err)
	}
	return writeHumanFrame(out, "tnl publish", "installed", "stop: sudo tnl publisher stop --server "+server+" "+route.Id,
		clioutput.Fields(clioutput.Field{Label: "public URL", Value: route.CanonicalHostname}))
}

func runPublisherStop(flags publisherStopCommand, out io.Writer) error {
	server, err := clientstate.CanonicalServer(flags.Server)
	if err != nil {
		return err
	}
	if !opaqueid.Valid(flags.ID, opaqueid.PublicURLPrefix) {
		return errors.New("pass a saved public URL ID")
	}
	store, err := publisherjob.Open(publisherjob.Dir())
	if err != nil {
		return err
	}
	if err := store.Remove(server, flags.ID); err != nil {
		return err
	}
	return writeHumanFrame(out, "tnl publisher stop", "stopped", "server grant remains active; revoke it separately", clioutput.Fields(clioutput.Field{Label: "public URL", Value: flags.ID}))
}

func installPublisherService(ctx context.Context, out io.Writer) error {
	store, err := publisherjob.Open(publisherjob.Dir())
	if err != nil {
		return err
	}
	if err := publisherjob.Install(ctx, store); err != nil {
		return err
	}
	return writeHumanFrame(out, "tnl publisher service install", "installed", "")
}

func runPublisherService(ctx context.Context) error {
	store, err := publisherjob.Open(publisherjob.Dir())
	if err != nil {
		return err
	}
	return publisherjob.Run(ctx, store, func(ctx context.Context, job publisherjob.Job) error {
		err := runPublisherJob(ctx, job)
		if err != nil && ctx.Err() == nil {
			log.Printf("publisher job %s stopped; retrying", job.ID())
		}
		return err
	})
}

func runPublisherJob(ctx context.Context, job publisherjob.Job) (result error) {
	state, err := clientstate.OpenService(ctx, filepath.Join(publisherjob.Dir(), "client"))
	if err != nil {
		return err
	}
	defer state.Close()
	client, err := controlclient.New(job.Server, nil, "")
	if err != nil {
		return err
	}
	authority, err := authorityclient.New(job.Server, nil, "")
	if err != nil {
		return err
	}
	control := &enrolledControl{Client: client, authority: authority, private: job.Private, identity: job.Identity}
	token, err := control.access(ctx)
	if err != nil {
		return err
	}
	route, err := client.PublisherPublicURL(ctx, token)
	if err != nil {
		return err
	}
	if route.Id != job.ID() || route.TeamId != job.Identity.TeamId || route.Ephemeral || route.Purpose != controlv1.App || route.LifecycleState != controlv1.Enabled {
		return errors.New("saved publisher scope is no longer available")
	}
	flags := publishCommand{Target: job.Target, projectRoot: state.Root(), Output: publishOutputHuman, tunnelFlags: tunnelFlags{InspectionMode: config.InspectionNone}}
	output, err := newPublishOutput(flags.Output, "tnl publish", io.Discard, io.Discard, nil)
	if err != nil {
		return err
	}
	defer func() { _ = output.finish(ctx, result) }()
	// the system process does not use a team session or an interactive keychain.
	return runSelectedPublish(ctx, flags, output, nil, state, job.Server, route, control, nil)
}
