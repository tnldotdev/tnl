package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
)

func writeHumanFrame(output io.Writer, command, state, footer string, blocks ...clioutput.Block) error {
	return failure.Wrap("write command result", failure.OutputUnavailable, clioutput.Write(output, clioutput.Frame{
		Command: command,
		State:   state,
		Blocks:  blocks,
		Footer:  footer,
	}))
}

func authenticationPrompt(output io.Writer, command string) func(auth.Prompt) error {
	return func(prompt auth.Prompt) error {
		return writeHumanFrame(output, command, "authentication required", "waiting for authentication",
			approvalBlocks(prompt.URL, prompt.Code)...,
		)
	}
}

func approvalBlocks(url, code string) []clioutput.Block {
	blocks := []clioutput.Block{clioutput.Section("open this URL", clioutput.Literal(url))}
	if code != "" {
		blocks = append(blocks, clioutput.Section("match this code", clioutput.Literal(code)))
	}
	return blocks
}

func shellWord(word string) string {
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:@%+=,-"
	if word != "" && strings.Trim(word, safe) == "" {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", "'\\''") + "'"
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
