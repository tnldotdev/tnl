package main

import (
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/oidcauth"
)

func writeHumanFrame(output io.Writer, command, state, footer string, blocks ...clioutput.Block) error {
	return clioutput.Write(output, clioutput.Frame{
		Command: command,
		State:   state,
		Blocks:  blocks,
		Footer:  footer,
	})
}

func authenticationPrompt(output io.Writer, command string) func(oidcauth.Prompt) error {
	return func(prompt oidcauth.Prompt) error {
		fields := []clioutput.Field{{Label: "open", Value: prompt.URL}}
		if prompt.Code != "" {
			fields = append(fields, clioutput.Field{Label: "code", Value: prompt.Code})
		}
		return writeHumanFrame(output, command, "authentication required", "waiting for authentication",
			clioutput.Fields(fields...),
		)
	}
}

func writeHumanTransition(
	output io.Writer,
	command, state, from, detail, to, footer string,
	fields ...clioutput.Field,
) error {
	blocks := []clioutput.Block{clioutput.Transition(from, detail, to)}
	if len(fields) != 0 {
		blocks = append(blocks, clioutput.Fields(fields...))
	}
	return writeHumanFrame(output, command, state, footer, blocks...)
}

func countState(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func allowedState(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "blocked"
}
