package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// system state never falls back to a login server profile.
type backgroundPublishFlags struct {
	BG             bool   `name:"bg" help:"Install an enrolled saved URL as a boot-started system publication."`
	Job            string `name:"job" help:"Stable lowercase system publisher job name; required with --bg."`
	SystemStateDir string `name:"system-state-dir" type:"path" help:"Private root-owned system publisher state directory."`
	ServerCAFile   string `name:"server-ca-file" type:"path" help:"Additional PEM certificate authorities for this job's control server."`
}

func backgroundSelection(flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags) error {
	selected := 0
	for _, value := range []string{selection.EnrollmentKey, selection.PublisherID, selection.PublisherFile} {
		if value != "" {
			selected++
		}
	}
	if flags.ServerURL == "" || flags.serverFromConfig || background.Job == "" || selected != 1 {
		return publisherjob.ErrScope
	}
	if flags.Name != "" || flags.PublicURL != "" || flags.Domain != "" || flags.Team != "" || flags.AccessToken != "" || flags.Demo || flags.Ephemeral || flags.Anonymous || flags.access != nil || len(flags.IP) > 0 || flags.Open {
		return publisherjob.ErrScope
	}
	if flags.inspectionModeFromCLI && string(flags.InspectionMode) != "none" {
		return publisherCLIError("system publications support --inspection-mode=none")
	}
	return nil
}

// runEnrolledBackgroundPublish enrolls directly into file-protected system
// state, installs one job, refreshes the binary, and starts the system service.
func runEnrolledBackgroundPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, output io.Writer, input io.Reader, executor publisherjob.Executor) error {
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
	if err := backgroundSelection(flags, selection, background); err != nil {
		return err
	}
	root := background.SystemStateDir
	if root == "" {
		root = publisherjob.DefaultRoot(runtime.GOOS)
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: root})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := installBackgroundJob(ctx, registry, flags, selection, background, input, publisherjob.Clients); err != nil {
		return err
	}
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if err := publisherjob.InstallService(ctx, publisherjob.ServiceOptions{Root: registry.Root(), BinarySource: binary}, executor); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl publish", background.Job)
}

func installBackgroundJob(ctx context.Context, registry *publisherjob.Registry, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, input io.Reader, clients publisherjob.ClientFactory) error {
	if err := backgroundSelection(flags, selection, background); err != nil {
		return err
	}
	job := publisherjob.Job{ID: background.Job, Server: flags.ServerURL, Target: flags.Target, Protocol: controlv1.PublicURLServiceProtocol(flags.Protocol), TargetTLS: flags.TargetTLS, TargetTLSName: flags.TargetTLSName}
	job.Limits = flags.limits()
	var err error
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
	control, authority, err := clients(job)
	if err != nil {
		return err
	}
	profile, err := registry.Profile(ctx, job.Server)
	if err != nil {
		return err
	}
	var native *nativeauth.Native
	var identity authorityv1.PublisherEnrollmentResult
	var private ed25519.PrivateKey
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
	} else {
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
	publicURL, err := native.SavedURL(ctx)
	if err != nil {
		return err
	} // namespace enrollment cannot become a system job.
	if publicURL.Ephemeral || publicURL.Purpose != controlv1.App || !publicURL.ServiceProtocol.Valid() {
		return publisherjob.ErrScope
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
	return registry.Install(ctx, job, identity, private)
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
