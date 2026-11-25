package main

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/cliflags"
)

func isMachineFormat(format string) bool { return format == "json" || format == "ndjson" }

func publishOutputModeError(mode string) error {
	message := mode + " requires --output=human."
	return &commandGuidance{error: publisherCLIError(message), message: message}
}

func fixedMachineCommand(cmd *cobra.Command) bool {
	path := selectedPath(cmd)
	return path == "runtime connections" || strings.HasPrefix(path, "runtime connections ")
}

// environmentOutput uses the declared formats and the selected run mode.
// preferences do not add formats to raw streams, credentials, or private commands.
func environmentOutput(cmd *cobra.Command, value func(string) string, passthrough bool) (string, error) {
	output := cmd.Flags().Lookup("output")
	if output == nil || !publicCommandPath(cmd) {
		return "", nil
	}
	boolFlag := func(name string) bool {
		on, _ := strconv.ParseBool(value(name))
		return on
	}
	switch selectedPath(cmd) {
	case "publish":
		if boolFlag("detach") || boolFlag("install") || value("detached-child") != "" {
			return "", nil
		}
	case "connect start":
		if boolFlag("stdio") || value("client") != "" || passthrough {
			return "", nil
		}
	case "publisher setup", "share token create", "share service token create", "share service invite create":
		return "", nil
	}
	choices := cliflags.FlagHelp(output).Choices
	if !slices.Contains(choices, "human") {
		return "", nil
	}
	switch os.Getenv("TNL_OUTPUT") {
	case "", "auto":
		return "", nil
	case "human":
		return "human", nil
	case "machine":
		for _, choice := range choices {
			if isMachineFormat(choice) {
				return choice, nil
			}
		}
		return "", nil
	default:
		return "", errors.New("invalid TNL_OUTPUT value")
	}
}

func (a *commandApp) selectOutput(cmd *cobra.Command) error {
	a.outputSelected = true
	a.machineOutput = fixedMachineCommand(cmd)
	flags := cmd.Flags()
	output := flags.Lookup("output")
	if output == nil {
		return nil
	}
	if !output.Changed {
		format, err := environmentOutput(cmd, func(name string) string {
			if flag := flags.Lookup(name); flag != nil {
				return flag.Value.String()
			}
			return ""
		}, cmd.ArgsLenAtDash() > 0 && cmd.ArgsLenAtDash() < flags.NArg())
		if err != nil {
			return invalidCommandInput(cmd, err, "Set TNL_OUTPUT to human, machine, or auto.")
		}
		if format != "" {
			if err := output.Value.Set(format); err != nil {
				return err
			}
		}
	}
	a.machineOutput = a.machineOutput || isMachineFormat(output.Value.String())
	return nil
}

// machineDiagnosticForInput is used only when normal parsing did not reach
// output selection. look for intent without applying flags or reading state.
func machineDiagnosticForInput(cmd *cobra.Command, args []string) bool {
	var flags *pflag.FlagSet
	var path []string
	if cmd != nil {
		if fixedMachineCommand(cmd) {
			return true
		}
		flags = cmd.Flags()
		path = strings.Fields(cmd.CommandPath())[1:]
	}
	input := readOutputInput(flags, args)
	if (len(path) == 0 || len(path) == 1 && path[0] == "runtime") && input.prefix == [2]string{"runtime", "connections"} {
		// Cobra can miss the private path when a preceding unknown flag
		// makes it drop a command word. keep SDK errors in the wire format.
		return true
	}
	if output, explicit := input.flags["output"]; explicit {
		return isMachineFormat(output)
	}
	if cmd == nil {
		return false
	}
	passthrough := input.hasTail && input.positionals > len(path)
	preference, _ := environmentOutput(cmd, func(name string) string { return input.flags[name] }, passthrough)
	if preference != "" {
		return isMachineFormat(preference)
	}
	if flag := cmd.Flags().Lookup("output"); flag != nil {
		return isMachineFormat(flag.DefValue)
	}
	return false
}

type outputInput struct {
	flags       map[string]string
	prefix      [2]string
	positionals int
	hasTail     bool
}

func readOutputInput(flags *pflag.FlagSet, args []string) outputInput {
	input := outputInput{flags: make(map[string]string)}
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "--" {
			input.hasTail = i+1 < len(args)
			break
		}
		if !strings.HasPrefix(word, "--") {
			if !strings.HasPrefix(word, "-") {
				if input.positionals < len(input.prefix) {
					input.prefix[input.positionals] = word
				}
				input.positionals++
			}
			continue
		}
		name, value, inline := strings.Cut(word[2:], "=")
		var flag *pflag.Flag
		if flags != nil {
			flag = flags.Lookup(name)
		}
		if !inline {
			switch {
			case flag != nil && flag.NoOptDefVal != "":
				value = flag.NoOptDefVal
			case (flag != nil || name == "output") && i+1 < len(args) && args[i+1] != "--":
				i++
				value = args[i]
			}
		}
		switch name {
		case "output", "stdio", "client", "detach", "detached-child", "install":
			input.flags[name] = value
		}
	}
	return input
}
