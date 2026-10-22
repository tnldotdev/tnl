package main

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
)

func writeNativeConnection(output io.Writer, profile connector.Profile, mode statusOutputMode, listen string) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(profile)
	}
	fields := []clioutput.Field{{Label: "service", Value: profile.ServiceID}, {Label: "protocol", Value: string(profile.Protocol)}, {Label: "hostname", Value: profile.Hostname}, {Label: "port", Value: strconv.Itoa(profile.Port)}, {Label: "TLS", Value: profile.TLS}, {Label: "authentication", Value: string(profile.Authentication)}}
	footer := "keep tnl running while using the service"
	if listen != "" {
		fields = append(fields, clioutput.Field{Label: "listen", Value: listen})
	}
	if profile.URL != "" {
		label := "url"
		if profile.Protocol == config.ProtocolHTTP {
			label = "curl url"
		}
		fields = append(fields, clioutput.Field{Label: label, Value: profile.URL})
	}
	if profile.DetachedID != "" {
		fields = append(fields, clioutput.Field{Label: "detached ID", Value: profile.DetachedID})
		footer = "stop with tnl detached stop " + profile.DetachedID
	}
	if profile.ServerCAFile != "" {
		fields = append(fields, clioutput.Field{Label: "server CA", Value: profile.ServerCAFile})
	}
	if kube := profile.Kubeconfig; kube != nil {
		fields = append(fields, clioutput.Field{Label: "kubeconfig", Value: kube.File}, clioutput.Field{Label: "context", Value: kube.Context})
		if kube.Namespace != "" {
			fields = append(fields, clioutput.Field{Label: "namespace", Value: kube.Namespace})
		}
		if kube.Qualified {
			footer = "context name was qualified to preserve an existing installation"
		}
	}
	command := make([]string, len(profile.Command))
	for i, argument := range profile.Command {
		command[i] = "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, instruction := range profile.Instructions {
		blocks = append(blocks, clioutput.Text(instruction))
	}
	blocks = append(blocks, clioutput.Section("client command", clioutput.Text(strings.Join(command, " "))))
	return writeHumanFrame(output, "tnl connect", "ready", footer, blocks...)
}
