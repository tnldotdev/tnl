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
		blocks = append(blocks, clioutput.Literal(profile.URL))
	}
	lifetime := "Ctrl+C to stop."
	if profile.JobID != "" && !installed {
		lifetime = "Running in the background."
	} else if installed {
		lifetime = "Installed; running in the background."
	}
	if listen != "" {
		blocks = append(blocks, clioutput.Line("Listening on "+listen+". "+lifetime))
	}
	switch profile.Protocol {
	case config.ProtocolHTTP:
		blocks = append(blocks, clioutput.Text("Use a dial override to reach the local listener. Keep the URL's HTTPS hostname."))
		if profile.Public {
			blocks = append(blocks, clioutput.Text("Opening the URL in a browser uses the public endpoint."))
		}
	case config.ProtocolMySQL:
		blocks = append(blocks, clioutput.Text("Dial the listener with the SDK mysql2 connection factory or a compatible driver."), clioutput.Fields(
			clioutput.Field{Label: "Verify TLS hostname", Value: profile.Hostname},
			clioutput.Field{Label: "Server CA", Value: profile.ServerCAFile},
		))
	case config.ProtocolTCP:
		blocks = append(blocks, clioutput.Line("tnl verifies TLS for "+profile.Hostname+"."))
	}
	if kube := profile.Kubeconfig; kube != nil {
		if kube.Namespace != "" {
			blocks = append(blocks, clioutput.Line("Namespace: "+kube.Namespace))
		}
		if kube.Qualified {
			blocks = append(blocks, clioutput.Text("The context name includes a suffix because the original name is in use."))
		}
	}
	return writeResult(output, blocks...)
}
