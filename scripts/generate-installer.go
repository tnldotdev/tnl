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
	template, err := os.ReadFile(filepath.Join(*root, "scripts/install.sh.in"))
	if err != nil {
		panic(err)
	}
	var messages strings.Builder
	messages.WriteString("tnl_message() {\n  case \"$1\" in\n")
	for _, message := range []struct{ name, state, text, footer string }{
		{"installing", "installing", "downloading and verifying the tnl client", ""},
		{"installed", "installed", "tnl is installed. add the installation directory to PATH if needed.", "start with: tnl publish 3000"},
		{"failed", "failed", "could not install tnl. check the selected version, curl, tar, a SHA-256 tool, and write access to the install directory.", "run the installer again"},
		{"checksum_failed", "failed", "the release checksum is missing, invalid, or does not match. download the release again.", "run the installer again"},
	} {
		frame, err := clioutput.Render(clioutput.Frame{
			Command: "tnl install", State: message.state,
			Blocks: []clioutput.Block{clioutput.Text(message.text)}, Footer: message.footer,
		})
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(&messages, "    %s) printf '%%s\\n' '%s' ;;\n", message.name, strings.ReplaceAll(frame, "'", "'\\''"))
	}
	messages.WriteString("  esac\n}\n")
	output := strings.ReplaceAll(string(template), "@MESSAGES@", messages.String())
	if err := os.WriteFile(filepath.Join(*root, "scripts/install.sh"), []byte(output), 0o644); err != nil {
		panic(err)
	}
}
