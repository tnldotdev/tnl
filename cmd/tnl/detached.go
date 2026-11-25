package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/detached"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
)

type detachedCommand struct {
	List detachedListCommand
	Stop detachedStopCommand
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
		stop := "tnl detached stop " + shellWord(id)
		if stateDir != "" {
			stop += " --state-dir=" + shellWord(stateDir)
		}
		return writeResult(output, clioutput.Text("Publishing in the background. To stop:"), clioutput.Literal(stop))
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
	return writeNativeConnection(output, profile, mode, net.JoinHostPort(profile.Host, strconv.Itoa(profile.Port)), root)
}

func runDetachedList(flags detachedListCommand, output io.Writer) error {
	entries, err := detached.List(flags.StateDir)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, entry := range entries {
		rows = append(rows, []string{entry.ID, entry.State})
	}
	return writeResult(output, clioutput.Table([]string{"ID", "STATE"}, rows, "No detached tunnels."))
}

func runDetachedStop(flags detachedStopCommand, output io.Writer) error {
	if err := detached.Stop(flags.StateDir, flags.ID); err != nil {
		return err
	}
	return writeResult(output, clioutput.Line("Stopping "+flags.ID+"."))
}

func (a *commandApp) newDetachedCommand() *cobra.Command {
	f := a.flags
	cDetached := &cobra.Command{Use: "detached", Short: "List or stop tunnels started with --detach.", GroupID: "deploy"}
	cDetachedList := &cobra.Command{Use: "list", Short: "List detached publications for this client state."}
	a.leaf(cDetachedList, &f.Detached.List, func(call commandCall) error {
		return runDetachedList(f.Detached.List, a.out)
	})
	cDetached.AddCommand(cDetachedList)
	cDetachedStop := &cobra.Command{Use: "stop", Short: "Stop a detached publication."}
	a.leaf(cDetachedStop, &f.Detached.Stop, func(call commandCall) error {
		return runDetachedStop(f.Detached.Stop, a.out)
	})
	cDetached.AddCommand(cDetachedStop)
	return cDetached
}
