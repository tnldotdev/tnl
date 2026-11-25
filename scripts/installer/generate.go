//go:build ignore

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	template, err := os.ReadFile(filepath.Join(*root, "scripts/installer/install.sh.in"))
	if err != nil {
		panic(err)
	}
	var messages strings.Builder
	messages.WriteString("tnl_message() {\n  case \"$1\" in\n")
	for _, message := range []struct{ name, text string }{
		{"installing", "Downloading and verifying tnl..."},
		{"installed", "Installed tnl. Add the installation directory to PATH if needed."},
		{"failed", "Could not install tnl. Check the version, curl, tar, a SHA-256 tool, and write access to the install directory."},
		{"stable_failed", "Could not find a stable tnl release. Check GitHub access or set TNL_VERSION to an exact release."},
		{"checksum_failed", "The release checksum is missing, invalid, or does not match. Download the release again."},
	} {
		text, err := clioutput.Render(clioutput.Message{Blocks: []clioutput.Block{clioutput.Text(message.text)}})
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&messages, "    %s) printf '%%s' '%s' ;;\n", message.name, strings.ReplaceAll(text, "'", "'\\''"))
	}
	messages.WriteString("  esac\n}\n")
	output := strings.ReplaceAll(string(template), "@MESSAGES@", messages.String())
	if err := os.WriteFile(filepath.Join(*root, "scripts/install.sh"), []byte(output), 0o644); err != nil {
		panic(err)
	}
}
