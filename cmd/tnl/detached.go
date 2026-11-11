package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/tnldotdev/tnl/internal/client/detached"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
)

type detachedCommand struct {
	List detachedListCommand `cmd:"" help:"List detached publications for this client state."`
	Stop detachedStopCommand `cmd:"" help:"Stop a detached publication."`
}
type detachedListCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}
type detachedStopCommand struct {
	detachedListCommand `embed:""`
	ID                  string `arg:"" name:"id" help:"Detached publication ID."`
}

func detachPublish(ctx context.Context, args []string, stateDir string, output io.Writer, title string) error {
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return err
	}
	id, err := detached.NewID()
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := make([]string, 0, len(args)+1)
	for _, arg := range args {
		if arg != "--detach" && arg != "--detach=true" {
			childArgs = append(childArgs, arg)
		}
	}
	childArgs = append(childArgs, "--detached-child="+id)
	return detached.Launch(ctx, root, id, binary, childArgs, func(root, pid string) error {
		if title == "tnl connect" {
			mode := statusOutputHuman
			for i, arg := range args {
				if arg == "--output=json" || arg == "--output" && i+1 < len(args) && args[i+1] == "json" {
					mode = statusOutputJSON
				}
			}
			return writeDetachedConnection(root, id, mode, output)
		}
		return writeHumanFrame(output, title, "detached", "", clioutput.Fields(clioutput.Field{Label: "id", Value: id}, clioutput.Field{Label: "pid", Value: pid}, clioutput.Field{Label: "state", Value: "ready"}))
	})
}

func writeDetachedConnection(root, id string, mode statusOutputMode, output io.Writer) error {
	data, err := detached.ReadConnection(root, id)
	if err != nil {
		return err
	}
	var profile connector.Profile
	if json.Unmarshal(data, &profile) != nil || profile.Schema != 1 || !profile.ConnectorRequired {
		return failure.Wrap("read detached connection", failure.ServerResponseInvalid, errors.New("invalid prepared connection"))
	}
	profile.DetachedID = id
	return writeNativeConnection(output, profile, mode, net.JoinHostPort(profile.Host, strconv.Itoa(profile.Port)))
}

func runDetachedList(flags detachedListCommand, output io.Writer) error {
	entries, err := detached.List(flags.StateDir)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{}
	for _, entry := range entries {
		fields := []clioutput.Field{{Label: "id", Value: entry.ID}}
		if entry.PID != "" {
			fields = append(fields, clioutput.Field{Label: "pid", Value: entry.PID})
		}
		fields = append(fields, clioutput.Field{Label: "state", Value: entry.State})
		blocks = append(blocks, clioutput.Fields(fields...))
	}
	state := "no publications"
	if len(entries) > 0 {
		state = "detached"
	}
	return writeHumanFrame(output, "tnl detached list", state, "", blocks...)
}

func runDetachedStop(flags detachedStopCommand, output io.Writer) error {
	if err := detached.Stop(flags.StateDir, flags.ID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl detached stop", "stopping", "", clioutput.Fields(clioutput.Field{Label: "id", Value: flags.ID}))
}
