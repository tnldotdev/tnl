package main

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/cliflags"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

func configureClientHelp(root *cobra.Command) {
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		out := cmd.OutOrStdout()
		if _, err := io.WriteString(out, clientHelp(cmd, clioutput.TerminalWidth(out, 80))); err != nil {
			cmd.PrintErrln(err)
		}
	})
}

type helpPage struct {
	strings.Builder
	width int
}

func clientHelp(cmd *cobra.Command, width int) string {
	p := helpPage{width: min(width, 112)}
	desc := cmd.Long
	if desc == "" {
		desc = cmd.Short
	}
	if desc != "" {
		for line := range strings.SplitSeq(strings.TrimSpace(desc), "\n") {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "  ") {
				// cobra's shell completion instructions include literal shell commands.
				p.line("  " + strings.TrimLeft(line, " \t"))
			} else {
				p.prose(line, "", "")
			}
		}
	}

	p.heading("Usage")
	hasChildren := cmd.HasAvailableSubCommands()
	shorthand := cmd.Annotations["default"]
	if !hasChildren || shorthand != "" {
		usage := cmd.UseLine()
		if cmd.CommandPath() == "tnl connect" || cmd.CommandPath() == "tnl connect start" {
			usage += " [-- client-args...]"
		}
		p.line("  " + usage)
	}
	if hasChildren {
		path := cmd.CommandPath()
		if !cmd.HasParent() {
			path += " [global flags]"
		}
		p.line("  " + path + " <command>")
	}

	argCmd := cmd
	if shorthand != "" {
		for _, child := range cmd.Commands() {
			if child.Name() == shorthand {
				argCmd = child
				break
			}
		}
	}
	var args []helpRow
	for _, label := range strings.Fields(argCmd.Use)[1:] {
		name := strings.Trim(label, "<>[]")
		if meta, ok := cliflags.ArgumentHelp(argCmd, name); ok {
			args = append(args, helpRow{label, inputHelp(name, meta)})
		}
	}
	p.rows("Arguments", args)

	if cmd.HasExample() {
		p.heading("Examples")
		for line := range strings.SplitSeq(strings.Trim(cmd.Example, "\n"), "\n") {
			text := strings.TrimSpace(line)
			switch {
			case text == "":
				p.line("")
			case strings.HasPrefix(text, "# "):
				p.prose(strings.TrimPrefix(text, "# "), "  # ", "  # ")
			default:
				// preserve quoted arguments and shell continuations verbatim.
				p.line(line)
			}
		}
	}

	commands := make(map[string][]helpRow)
	for _, sub := range cmd.Commands() {
		if sub.IsAvailableCommand() || sub.Name() == "help" && !sub.Hidden {
			commands[sub.GroupID] = append(commands[sub.GroupID], helpRow{sub.Name(), sub.Short})
		}
	}
	for _, g := range cmd.Groups() {
		p.rows(g.Title, commands[g.ID])
	}
	p.rows("Commands", commands[""])

	flags := make(map[string][]helpRow)
	collect := func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		meta := cliflags.FlagHelp(f)
		if f.Name == "help" && f.Shorthand == "h" {
			meta.Usage = "Show help for this command."
		}
		label := "--" + f.Name
		if f.Shorthand != "" && f.ShorthandDeprecated == "" {
			label = "-" + f.Shorthand + ", " + label
		}
		if f.NoOptDefVal == "" {
			label += " " + flagMetavar(f, meta)
		}
		group := flagGroup(cmd, f)
		flags[group] = append(flags[group], helpRow{label, inputHelp(f.Name, meta)})
	}
	cmd.LocalFlags().VisitAll(collect)
	cmd.InheritedFlags().VisitAll(collect)
	for _, group := range helpFlagGroups {
		p.rows(group, flags[group])
	}
	if hasChildren {
		p.line("")
		p.prose("Add --help to a command for its options and examples.", "", "")
	}
	return p.String()
}

type helpRow struct{ label, description string }

func (p *helpPage) line(s string) {
	p.WriteString(s)
	p.WriteByte('\n')
}

func (p *helpPage) heading(s string) {
	if p.Len() > 0 {
		p.WriteByte('\n')
	}
	p.line(strings.TrimSuffix(s, ":") + ":")
}

func (p *helpPage) rows(title string, rows []helpRow) {
	if len(rows) == 0 {
		return
	}
	p.heading(title)
	column := 0
	for _, row := range rows {
		column = max(column, utf8.RuneCountInString(row.label))
	}
	stack := p.width-(column+4) < 32
	for _, row := range rows {
		label := "  " + row.label
		if stack || row.description == "" {
			p.line(label)
			if row.description != "" {
				p.prose(row.description, "    ", "    ")
			}
		} else {
			p.prose(row.description, fmt.Sprintf("  %-*s  ", column, row.label), strings.Repeat(" ", column+4))
		}
	}
}

// wrap prose at word boundaries; a single flag name, URL or choice stays intact.
func (p *helpPage) prose(text, first, rest string) {
	prefix := first
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && utf8.RuneCountInString(prefix+line+" "+word) > p.width {
			p.line(prefix + line)
			prefix, line = rest, ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	p.line(prefix + line)
}

func inputHelp(name string, meta cliflags.Help) string {
	desc := meta.Usage
	if desc == "" {
		desc = missingInputHelp[name]
	}
	var notes []string
	if meta.Required {
		notes = append(notes, "Required.")
	}
	if desc != "" {
		notes = append(notes, desc)
	}
	for _, choice := range meta.Choices {
		if !strings.Contains(desc, choice) {
			notes = append(notes, "Choices: "+strings.Join(meta.Choices, ", ")+".")
			break
		}
	}
	switch meta.Default {
	case "", "false", "0", "0s", "[]", "map[]":
	default:
		if !strings.Contains(desc, meta.Default+" (default)") {
			notes = append(notes, "Default: "+meta.Default+".")
		}
	}
	return strings.Join(notes, " ")
}

var missingInputHelp = map[string]string{
	"output":                "Output format.",
	"state-dir":             "Client state directory.",
	"system-state-dir":      "Private supervisor state directory.",
	"email":                 "Recipient's verified sign-in email.",
	"expires-in":            "Invitation lifetime.",
	"url":                   "Service ID, public hostname, or HTTPS origin.",
	"invitation-id":         "Invitation ID to revoke.",
	"secret":                "One-use invitation secret.",
	"authors":               "Who can leave feedback.",
	"publisher-identity-id": "Saved publisher identity ID.",
	"grant-id":              "Publisher grant ID.",
}

func flagMetavar(f *pflag.Flag, meta cliflags.Help) string {
	name := f.Name
	switch {
	case meta.Path || strings.HasSuffix(name, "-dir"):
		return "PATH"
	case strings.HasSuffix(name, "-id") || name == "publisher-identity":
		return "ID"
	case f.Value.Type() == "duration":
		return "DURATION"
	}
	switch name {
	case "output":
		return "FORMAT"
	case "server", "url":
		return "URL"
	case "ip":
		return "IP/CIDR"
	case "rate-per", "expires-in":
		return "DURATION"
	case "team", "to-team":
		return "TEAM"
	case "after":
		return "CURSOR"
	case "since", "expires-at":
		return "TIME"
	case "manage", "connect", "publish":
		return "SERVICE"
	case "listen":
		return "IP:PORT"
	case "prefer-region":
		return "PROVIDER:REGION"
	case "access-token":
		return "TOKEN"
	case "enroll-key", "project-key", "idempotency-key":
		return "KEY"
	case "service-name", "namespace", "kube-user", "client":
		return "NAME"
	case "target-tls-name":
		return "HOSTNAME"
	case "inspection-mode", "temporary":
		return "MODE"
	case "status":
		return "CODE"
	case "relay-lease-revision":
		return "REVISION"
	case "requests", "rate-requests", "rate-burst", "concurrency", "limit", "members":
		return "COUNT"
	}
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

var helpFlagGroups = []string{
	"Flags", "Publication", "Connection", "Visitor access", "Traffic limits",
	"Target TLS", "Kubernetes", "Run mode", "Publisher credentials",
	"Server and team", "Output", "Global flags",
}

func flagGroup(cmd *cobra.Command, f *pflag.Flag) string {
	if f.Name == "help" || cmd.Root().PersistentFlags().Lookup(f.Name) == f {
		return "Global flags"
	}
	switch f.Name {
	case "server", "team", "state-dir", "access-token":
		return "Server and team"
	}
	switch cmd.CommandPath() {
	case "tnl publish", "tnl connect", "tnl connect start", "tnl publisher serve":
		switch f.Name {
		case "output":
			return "Output"
		case "foreground", "detach", "install", "system", "system-state-dir", "server-ca-file", "service-name":
			return "Run mode"
		case "enroll-key", "enrolled", "identity-file", "identity-dir", "binding-file", "publisher-credential-file", "publisher-identity":
			return "Publisher credentials"
		case "anonymous", "ip", "require-post-quantum":
			return "Visitor access"
		case "requests", "rate-requests", "rate-burst", "rate-per", "concurrency":
			return "Traffic limits"
		case "target-ca-file", "target-tls", "target-tls-name":
			return "Target TLS"
		case "namespace", "kubeconfig", "kube-token-file", "kube-user", "kube-user-config":
			return "Kubernetes"
		}
		if cmd.CommandPath() == "tnl connect" || cmd.CommandPath() == "tnl connect start" {
			return "Connection"
		}
		return "Publication"
	}
	return "Flags"
}
