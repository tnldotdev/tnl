package main

import (
	"context"
	"io"
	"os"
	"runtime"

	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

type backgroundPublishFlags struct {
	Foreground     bool   `name:"foreground" help:"Run in this terminal (the default)."`
	Install        bool   `name:"install" help:"Install a publisher supervisor and keep this saved publication running."`
	Detach         bool   `name:"detach" help:"Run independently of the terminal without automatic restart."`
	DetachedChild  string `name:"detached-child" hidden:"" help:"Internal detached publication ID."`
	System         bool   `name:"system" help:"Use the unattended system supervisor with --install."`
	ServiceName    string `name:"service-name" help:"Name for service start, stop, and remove; defaults to the configured service."`
	SystemStateDir string `name:"system-state-dir" type:"path" help:"Private installed supervisor state directory."`
	ServerCAFile   string `name:"server-ca-file" type:"path" help:"Additional PEM certificate authorities for this job's control server."`
}

func (flags backgroundPublishFlags) settings() invocation.BackgroundSettings {
	return invocation.BackgroundSettings{System: flags.System, ServiceName: flags.ServiceName, SystemStateDir: flags.SystemStateDir, ServerCAFile: flags.ServerCAFile}
}

func backgroundOptions(flags publishCommand) invocation.BackgroundOptions {
	options := invocation.BackgroundOptions{PrivateOptions: privateOptions(flags), Open: flags.Open, ServerFromConfig: flags.serverFromConfig, InspectionModeFromCLI: flags.inspectionModeFromCLI, ReadinessPath: flags.publicationReadinessPath()}
	options.SelectProtocol = func(protocol string, private bool) (publisher.ApplicationLimits, error) {
		flags.privateService = private
		if private {
			if err := applyProtocolLimits(&flags.tunnelFlags, protocol); err != nil {
				return publisher.ApplicationLimits{}, err
			}
		}
		if err := validateTCPPublishOptions(flags, protocol); err != nil {
			return publisher.ApplicationLimits{}, err
		}
		return flags.limits(), nil
	}
	return options
}

func backgroundSelection(flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags) error {
	return invocation.ValidateBackground(backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherID: selection.PublisherID, PublisherFile: selection.PublisherFile}, background.settings())
}

func runEnrolledBackgroundPublish(ctx context.Context, flags publishCommand, selection enrolledPublishSelection, background backgroundPublishFlags, output io.Writer, input io.Reader, executor publisherjob.Executor) error {
	options, err := (systemStateFlags{System: background.System, SystemStateDir: background.SystemStateDir}).options()
	if err != nil {
		return err
	}
	if _, err := publisherjob.ServiceUnit(runtime.GOOS, "/tnl", options.Root); err != nil {
		return err
	}
	return invocation.InstallEnrolled(ctx, backgroundOptions(flags), invocation.EnrolledSelection{EnrollmentKey: selection.EnrollmentKey, PublisherID: selection.PublisherID, PublisherFile: selection.PublisherFile}, background.settings(), options, installationPresentation(output, os.Stderr), input, executor)
}

func (flags publishCommand) publicationReadinessPath() string {
	service := flags.project.Config.Services[flags.Service]
	if service.HTTP != nil && service.HTTP.Readiness != nil {
		return service.HTTP.Readiness.Path
	}
	return ""
}
