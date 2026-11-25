package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
)

func writeResult(output io.Writer, blocks ...clioutput.Block) error {
	return failure.Wrap("write command result", failure.OutputUnavailable, clioutput.Write(output, clioutput.Message{Blocks: blocks}))
}

func writeWithHint(output io.Writer, hint string, blocks ...clioutput.Block) error {
	if hint != "" {
		blocks = append(blocks, clioutput.Line(hint))
	}
	return writeResult(output, blocks...)
}

func authenticationPrompt(output io.Writer, _ string) func(auth.Prompt) error {
	return func(prompt auth.Prompt) error {
		return writeResult(output, approvalBlocks(prompt.URL, prompt.Code, false)...)
	}
}

func approvalBlocks(url, code string, opening bool) []clioutput.Block {
	if opening && code != "" {
		return []clioutput.Block{clioutput.Line("Match code: " + code), clioutput.Text("If your browser doesn't open, visit:"), clioutput.Literal(url)}
	}
	blocks := []clioutput.Block{clioutput.Text("Open this URL to sign in:"), clioutput.Literal(url)}
	if code != "" {
		blocks = append(blocks, clioutput.Line("Match code: "+code))
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
