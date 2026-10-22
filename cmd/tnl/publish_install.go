package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprovision "github.com/tnldotdev/tnl/internal/publisher/setup"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func runPublicationInstall(ctx context.Context, flags publishCommand, output, diagnostics io.Writer) error {
	if flags.Service != "" {
		effective, err := flags.project.EffectiveService(flags.Service)
		if err != nil {
			return err
		}
		applyTunnelConfiguration(&flags.tunnelFlags, effective.Tunnel)
		applyBuiltInHostname(&flags.tunnelFlags, flags.Service, flags.project.Worktree)
		if flags.Team == "" {
			flags.selectedTeam, err = resolve.TeamForServer(flags.ServerURL, effective.Server, effective.Team)
			if err != nil {
				return err
			}
		}
	}
	if flags.Name == "" && flags.PublicURL == "" || flags.Demo || flags.Ephemeral || flags.Open || flags.Protocol != "" && flags.Protocol != "http" {
		return failure.Wrap("select installed publication", failure.PublisherInstallOptions, errors.New("unsupported installation options"))
	}
	if flags.inspectionModeFromCLI && flags.InspectionMode != config.InspectionNone {
		return failure.Wrap("select installed inspection", failure.PublisherInstallInspection, errors.New("inspection capture selected"))
	}
	if err := validateTCPPublishOptions(flags, controlv1.Http); err != nil {
		return err
	}
	options, err := (systemStateFlags{System: flags.System, SystemStateDir: flags.SystemStateDir}).options()
	if err != nil {
		return err
	}
	if _, err := publisherjob.ServiceUnit(runtime.GOOS, "/tnl", options.Root); err != nil {
		return err
	}
	settings := invocation.InstallationOptions{PublicOptions: publicOptions(flags), Installation: options, ServiceName: flags.ServiceName, ReadinessPath: flags.publicationReadinessPath(), ServerCAFile: flags.ServerCAFile}
	settings.Authenticate = publisherAuthentication(diagnostics)
	return invocation.InstallHTTP(ctx, settings, installationPresentation(output, diagnostics))
}

func installationPresentation(output, diagnostics io.Writer) publisherprovision.Presentation {
	return publisherprovision.Presentation{Input: os.Stdin, Output: output, Diagnostics: diagnostics, Installing: func() error {
		return writeHumanFrame(diagnostics, "tnl publish", "installing", "sudo will ask for permission to install the system publisher")
	}, Jobs: func(jobs []publisherjob.Job, selected string) error {
		return renderSystemJobs(output, "tnl publish", jobs, selected)
	}}
}

func runPublicationRegister(ctx context.Context, flags serviceRegisterCommand, input io.Reader, output io.Writer, executor publisherjob.Executor) error {
	if flags.PrivateResult {
		flags.PrivateResult = false
		var buffer bytes.Buffer
		result := publisherprovision.RegistrationResult{}
		err := runPublicationRegister(ctx, flags, input, &buffer, executor)
		if err == nil {
			result.Output = buffer.String()
		} else if classified, ok := failure.Of(err); ok {
			result.Reason = classified.Reason()
		} else {
			result.Reason = failure.ClientStateUnavailable
		}
		return json.NewEncoder(output).Encode(result)
	}
	return publisherprovision.RegisterInput(ctx, flags.options, input, executor, func(jobs []publisherjob.Job, selected string) error {
		return renderSystemJobs(output, "tnl publish", jobs, selected)
	})
}
