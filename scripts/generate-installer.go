//go:build ignore

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	template, err := os.ReadFile(filepath.Join(*root, "scripts/install.sh.in"))
	if err != nil {
		panic(err)
	}
	parser, err := os.ReadFile(filepath.Join(*root, "scripts/install-release.awk"))
	if err != nil {
		panic(err)
	}
	missingAWK, err := clioutput.Render(clioutput.Frame{
		Command: "tnl install", State: "failed",
		Blocks: []clioutput.Block{clioutput.Fields(
			clioutput.Field{Label: "error", Value: "awk is required to install tnl"},
			clioutput.Field{Label: "action", Value: "install awk and run the installer again"},
		)},
	})
	if err != nil {
		panic(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	output := strings.NewReplacer(
		"@CLI_OUTPUT@", clioutput.ShellFunction(),
		"@RELEASE_PARSER@", quote(string(parser)),
		"@MISSING_AWK@", quote(missingAWK),
	).Replace(string(template))
	if err := os.WriteFile(filepath.Join(*root, "scripts/install.sh"), []byte(output), 0o644); err != nil {
		panic(err)
	}
}
