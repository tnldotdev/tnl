package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func installBackgroundPublisher(ctx context.Context, job localpublisher.ServiceJob, output *publishOutput, route controlv1.PublicURL) error {
	if output.mode != publishOutputHuman {
		return failure.Wrap("install background publisher", failure.InvalidTunnelFlags,
			errors.New("--bg requires human output"))
	}
	data, err := json.Marshal(job)
	if err != nil {
		return errors.New("invalid publisher service job")
	}
	defer clear(data)
	if os.Geteuid() == 0 {
		err = localpublisher.InstallServiceJob(ctx, bytes.NewReader(data))
	} else {
		executable, lookupErr := os.Executable()
		if lookupErr != nil {
			return lookupErr
		}
		command := exec.CommandContext(ctx, "sudo", "--", executable, "--no-telemetry", "publisher", "service", "install")
		command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(data), io.Discard, io.Discard
		err = command.Run()
	}
	if err != nil {
		return failure.Wrap("install background publisher", failure.ClientStateUnavailable,
			fmt.Errorf("administrator service installation failed; issue a new enrollment key before retrying: %w", err))
	}
	address, err := savedPublicAddress(route)
	if err != nil {
		return err
	}
	return writeHumanFrame(output.stderr, "tnl publish", "installed", "the publisher starts at boot and retries when the target is unavailable",
		clioutput.Fields(clioutput.Field{Label: "public URL", Value: address},
			clioutput.Field{Label: "URL ID", Value: route.Id}))
}

func validateBackgroundPublishOptions(flags publishCommand) error {
	if flags.Output != publishOutputHuman || flags.Open || flags.TargetCAFile != "" || flags.TargetTLS ||
		flags.TargetTLSName != "" || flags.resolveTarget != nil ||
		flags.Requests != nil || flags.RateRequests != nil || flags.RateBurst != nil || flags.RatePer != "" ||
		flags.Concurrency != nil || flags.TrafficConnections != nil || flags.TrafficRateCount != nil ||
		flags.TrafficRateBurst != nil || flags.TrafficRatePer != "" || flags.TrafficUpload != "" ||
		flags.TrafficDownload != "" || flags.InspectionRetention != 0 || flags.InspectionMaxBytes != "" ||
		flags.InspectionMode != "summary" {
		return failure.Wrap("install background publisher", failure.InvalidTunnelFlags,
			errors.New("--bg uses the saved public URL settings and a stable local target; omit per-run limits, inspection, TLS, Docker, --open, and --output options"))
	}
	return nil
}

func runPublisherStop(ctx context.Context, id string, diagnostics io.Writer) error {
	if !opaqueid.Valid(id, opaqueid.PublicURLPrefix) {
		return failure.Wrap("stop background publisher", failure.InvalidTunnelFlags,
			errors.New("pass an enrolled public URL ID"))
	}
	var err error
	if os.Geteuid() == 0 {
		err = localpublisher.RemoveServiceJob(ctx, id)
	} else {
		executable, lookupErr := os.Executable()
		if lookupErr != nil {
			return lookupErr
		}
		command := exec.CommandContext(ctx, "sudo", "--", executable, "--no-telemetry", "publisher", "service", "remove", id)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		err = command.Run()
	}
	if err != nil {
		return failure.Wrap("stop background publisher", failure.ClientStateUnavailable,
			fmt.Errorf("administrator access or the local publisher service failed: %w", err))
	}
	return writeHumanFrame(diagnostics, "tnl publisher stop", "stopped", "the publisher grant remains available",
		clioutput.Fields(clioutput.Field{Label: "URL ID", Value: id}))
}
