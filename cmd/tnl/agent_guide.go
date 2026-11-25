package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type guideStep struct {
	example clientExample
	read    string
}

type guideRecipe struct {
	title string
	steps []guideStep
}

var guideRecipes = []guideRecipe{
	{"Sign in and resume", []guideStep{
		{loginStartExample, "Give the approval URL and code to the user. Keep operation_id for the wait. The start command exits without waiting. Never log the code."},
		{loginWaitExample, "Use the same server and state directory. This ends when the approved session is saved, or the wait fails."},
	}},
	{"Set up a checkout", []guideStep{
		{initPlanExample, "Read files and steps before making changes. Conditional steps need more facts; they did not run."},
		{initFilesExample, "Read the actual file changes and outstanding steps. No dependencies were installed. Start the app normally after setup."},
	}},
	{"Publish and stop one job", []guideStep{
		{publishReceiptExample, "Show url to the user. Keep job_id and the state directory. This exits after the tunnel is ready, not after an HTTP probe. It does not grant anonymous access."},
		{publishStreamExample, "Use this instead if you want a stream. Read url from the ready event and keep the process running. Ending it stops the tunnel."},
		{statusJobsExample, "Use this to find an ID you did not keep. This lists local jobs; it does not probe an app."},
		{stopJobExample, "Use the exact job_id. If state is stopping, the owner acknowledged the request but has not confirmed shutdown."},
	}},
	{"Check readiness", []guideStep{
		{statusSavedExample, "Read the saved evidence. It can include a URL and a last error even when current readiness is unknown."},
		{waitReadyExample, "Check the result for what was verified. Continue only if the command exits successfully."},
	}},
	{"Share one service", []guideStep{
		{shareReceiptExample, "Show entry_url to the reviewer. Keep share_id from this same result. Keep the link secret; a mistyped name must not create an all-service share."},
		{revokeShareExample, "Use the retained share_id to end this share without revoking any other share."},
	}},
	{"Run one private query", []guideStep{
		{queryExample, "Read psql stdout and its exit status directly. tnl joins the connector before returning. No listener stays running."},
	}},
	{"Watch a new event", []guideStep{
		{watchOneExample, "Read one matching new event, or handle a nonzero timeout. The initial snapshot does not count. Keep the last cursor with its worktree and state directory. Omit --after on the first watch or when resetting after expiry."},
	}},
	{"Read feedback", []guideStep{
		{feedbackListExample, "Read the feedback IDs in this checkout. Feedback watch uses its own numeric cursor, not the one from tnl watch."},
	}},
	{"Review a deployment", []guideStep{
		{applyPreviewExample, "Read team_id, deployment, base_revision, and changes. Nothing was applied or reserved. Review the selected team before applying."},
	}},
}

const guideInputs = "Use the same checkout, server, and state directory throughout. Replace example service names and ports with yours, and set each $VARIABLE from the earlier result."

func (a *commandApp) newAgentGuideCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "agent-guide", Short: "Print the automation guide for this binary.", GroupID: "tools", Args: cobra.NoArgs}
	skill := cmd.Flags().Bool("skill", false, "Print Markdown with skill front matter for a SKILL.md file.")
	cmd.RunE = func(*cobra.Command, []string) error {
		version := buildinfo.Line("tnl")
		if *skill {
			var text strings.Builder
			fmt.Fprintf(&text, "---\nname: tnl\ndescription: Use the installed tnl CLI to publish, check, share, connect, and stop the exact jobs you start.\n---\n\n# tnl automation\n\n%s\n", version)
			fmt.Fprintf(&text, "\n%s\n\nReview exact arguments and results with `tnl help COMMAND --output json`.\n", guideInputs)
			for _, recipe := range guideRecipes {
				fmt.Fprintf(&text, "\n## %s\n", recipe.title)
				for _, step := range recipe.steps {
					fmt.Fprintf(&text, "\n```sh\ntnl %s\n```\n\n%s\n", step.example.args, step.read)
				}
			}
			_, err := fmt.Fprint(a.out, text.String())
			return err
		}
		blocks := []clioutput.Block{clioutput.Text(version), clioutput.Text(guideInputs),
			clioutput.Text("Review exact arguments and results:"), clioutput.Literal("tnl help COMMAND --output json")}
		for _, recipe := range guideRecipes {
			var steps []clioutput.Block
			for _, step := range recipe.steps {
				steps = append(steps, clioutput.Literal("tnl "+step.example.args), clioutput.Text(step.read))
			}
			blocks = append(blocks, clioutput.Section(recipe.title, steps...))
		}
		return writeWithHint(a.out, "tnl agent-guide --skill prints an installable SKILL.md", blocks...)
	}
	return cmd
}
