package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
)

func (a *commandApp) launchBackground(call commandCall, kind background.Kind, stateDir string, machine bool) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(parsedBackgroundInvocation(a.flags, call.command, kind))
	if err != nil {
		return err
	}
	label := "Starting background publication"
	switch kind {
	case background.KindConnect:
		label = "Starting connector"
	case background.KindPublisher:
		label = "Starting deployment publisher"
	}
	stopProgress := clioutput.StartProgress(call.ctx, a.out, a.errOut, !machine, label)
	defer stopProgress()
	return background.Launch(call.ctx, background.LaunchOptions{
		StateDir: stateDir, Binary: binary, Args: []string{"runtime", "job"},
		Kind: kind, Payload: payload,
	}, func(ctx context.Context, entry background.Entry) error {
		stopProgress()
		if stateDir != "" {
			stateDir = entry.StateDir
		}
		err := writeBackgroundReceipt(background.ReceiptWriter(ctx, a.out), background.ReceiptWriter(ctx, a.errOut), entry, stateDir, machine)
		if _, ok := failure.ReasonOf(err); ok {
			return err
		}
		return failure.Wrap("write background receipt", failure.OutputUnavailable, err)
	})
}

func (a *commandApp) newRuntimeJobCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "job", Hidden: true, Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return background.RunChild(cmd.Context(), func(ctx context.Context, spec background.Bootstrap) error {
			var inv backgroundInvocation
			if err := json.Unmarshal(spec.Payload, &inv); err != nil {
				return errors.New("invalid background operation")
			}
			serving := commandApp{flags: &cli{}, out: a.out, errOut: a.errOut, factories: a.factories}
			root := serving.root()
			path, err := inv.restore(serving.flags, spec.Kind, spec.StateDir)
			if err != nil {
				return err
			}
			selected, _, err := root.Find(path)
			if err != nil {
				return err
			}
			selected.SetContext(ctx)
			selected.InheritedFlags()
			for _, name := range inv.Changed {
				if flag := selected.Flags().Lookup(name); flag != nil {
					flag.Changed = true
				}
			}
			selected.Flags().Lookup("output").Changed = true
			return classifyCommandError(selected.RunE(selected, nil))
		})
	}
	return cmd
}

func writeBackgroundReceipt(output, diagnostics io.Writer, entry background.Entry, stateDir string, machine bool) error {
	visitURL := cmp.Or(entry.GuestEntryURL, entry.Address)
	if entry.Kind == background.KindConnect {
		var profile connector.Profile
		if json.Unmarshal(entry.Profile, &profile) != nil || profile.Schema != 1 || !profile.ConnectorRequired {
			return failure.Wrap("read connection receipt", failure.ServerResponseInvalid, errors.New("invalid prepared connection"))
		}
		profile.JobID = entry.JobID
		if machine {
			return json.NewEncoder(output).Encode(profile)
		}
		if err := writeConnectorReady(output, profile, statusOutputHuman, entry.Address, stateDir, false); err != nil {
			return err
		}
	} else if machine {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int      `json:"schema_version"`
			JobID         string   `json:"job_id"`
			Mode          string   `json:"mode"`
			Target        string   `json:"target"`
			URL           string   `json:"url,omitempty"`
			TunnelID      string   `json:"tunnel_id,omitempty"`
			ServiceID     string   `json:"service_id,omitempty"`
			Connect       []string `json:"connect_command,omitempty"`
		}{1, entry.JobID, "background", entry.Target, visitURL, entry.TunnelID, entry.ServiceID, entry.ConnectCommand})
	}
	args := []string{"tnl", "stop", entry.JobID}
	if stateDir != "" {
		args = append(args, "--state-dir", stateDir)
	}
	if err := writeResult(diagnostics, clioutput.Section("To stop", clioutput.Literal(guidanceCommand(args)))); err != nil {
		return err
	}
	if entry.Kind != background.KindConnect && visitURL != "" {
		return writeResult(output, clioutput.Literal(visitURL))
	}
	if len(entry.ConnectCommand) != 0 {
		return writeResult(output, clioutput.Literal(guidanceCommand(entry.ConnectCommand)))
	}
	if entry.Kind == background.KindPublisher {
		return writeResult(output, clioutput.Line("Deployment publisher ready: "+entry.Target))
	}
	return nil
}
