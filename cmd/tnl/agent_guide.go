package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

func (a *commandApp) newAgentGuideCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "agent-guide", Short: "Print the automation guide for this binary.", GroupID: "tools", Args: cobra.NoArgs}
	skill := cmd.Flags().Bool("skill", false, "Print Markdown with skill front matter for a SKILL.md file.")
	cmd.RunE = func(*cobra.Command, []string) error {
		version := buildinfo.Line("tnl")
		sections := []struct{ command, use string }{
			{"tnl status --scope local --output json", "Read the recorded local snapshot. A saved ready state is not a fresh readiness check."},
			{"tnl wait --service NAME --output json", "Check readiness now. Replace NAME with a configured service name."},
			{"tnl watch --output ndjson --after CURSOR", "Resume after the last processed local event. Keep the cursor with its worktree and state directory. Omit --after on the first watch or if the cursor expired."},
			{"tnl feedback list --output json", "Read feedback from the publishing worktree. Feedback watch has its own numeric cursor."},
			{"tnl auth login start --output json", "Start login only when asked to sign in. Keep session credentials and one-time secrets out of logs."},
			{"tnl apply --deployment production --diff --output json", "Review the team, deployment and base revision. Ask before applying production changes. A diff does not reserve a revision."},
		}
		if *skill {
			var text strings.Builder
			fmt.Fprintf(&text, "---\nname: tnl\ndescription: Use the installed tnl CLI to check readiness, read feedback, and review deployments.\n---\n\n# tnl automation\n\n%s\n", version)
			for _, s := range sections {
				fmt.Fprintf(&text, "\n`%s`\n\n%s\n", s.command, s.use)
			}
			_, err := fmt.Fprint(a.out, text.String())
			return err
		}
		blocks := []clioutput.Block{clioutput.Text(version)}
		for _, s := range sections {
			blocks = append(blocks, clioutput.Text(s.use), clioutput.Literal(s.command))
		}
		return writeWithHint(a.out, "tnl agent-guide --skill prints an installable SKILL.md", blocks...)
	}
	return cmd
}
