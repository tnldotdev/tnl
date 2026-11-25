package main

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
)

func writeNativeConnection(output io.Writer, profile connector.Profile, mode statusOutputMode, listen, stateDir string) error {
	return writeConnectorReady(output, profile, mode, listen, stateDir, false)
}

func writeConnectorReady(output io.Writer, profile connector.Profile, mode statusOutputMode, listen, stateDir string, installed bool) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(profile)
	}
	var blocks []clioutput.Block
	if len(profile.Command) > 0 {
		command := make([]string, len(profile.Command))
		for i, argument := range profile.Command {
			command[i] = shellWord(argument)
		}
		blocks = append(blocks, clioutput.Literal(strings.Join(command, " ")))
	} else if profile.Protocol == config.ProtocolHTTP && profile.URL != "" {
		blocks = append(blocks, clioutput.Text("Use a client dial override for this HTTPS URL:"), clioutput.Literal(profile.URL))
	}
	for _, instruction := range profile.Instructions {
		if profile.Protocol == config.ProtocolHTTP {
			instruction = strings.Replace(instruction, "curl below", "curl", 1)
		}
		blocks = append(blocks, clioutput.Text(instruction))
	}
	if listen != "" {
		blocks = append(blocks, clioutput.Line("Listening on "+listen))
	}
	if (profile.Protocol == config.ProtocolTCP || profile.Protocol == config.ProtocolKubernetes) && profile.Hostname != "" {
		blocks = append(blocks, clioutput.Line("TLS hostname: "+profile.Hostname))
	}
	if profile.TLS != "" {
		blocks = append(blocks, clioutput.Text("TLS: "+profile.TLS))
	}
	if profile.ServerCAFile != "" {
		blocks = append(blocks, clioutput.Line("Server CA: "+profile.ServerCAFile))
	}
	if kube := profile.Kubeconfig; kube != nil {
		if kube.Namespace != "" {
			blocks = append(blocks, clioutput.Line("Namespace: "+kube.Namespace))
		}
		if kube.Qualified {
			blocks = append(blocks, clioutput.Text("The context name was qualified to preserve an existing installation."))
		}
	}
	footer := "Keep this terminal open while using the service."
	if profile.DetachedID != "" {
		stop := "tnl detached stop " + shellWord(profile.DetachedID)
		if stateDir != "" {
			stop += " --state-dir=" + shellWord(stateDir)
		}
		blocks = append(blocks, clioutput.Text("Stop the detached connector:"), clioutput.Literal(stop))
		footer = ""
	} else if installed {
		footer = "The installed connector runs in the background."
	}
	if footer != "" {
		blocks = append(blocks, clioutput.Text(footer))
	}
	return writeResult(output, blocks...)
}
