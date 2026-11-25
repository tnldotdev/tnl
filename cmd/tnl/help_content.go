package main

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

func addClientHelpContent(cmd *cobra.Command) {
	path := cmd.CommandPath()
	if path == "tnl completion" {
		cmd.Short = "Generate a shell completion script."
		cmd.Long = "Choose your shell. Its help page shows how to load the script."
	}
	if examples := clientHelpExamples[path]; len(examples) != 0 {
		cmd.Example = formatExamples(examples)
	}
	if !cmd.Runnable() {
		cmd.Args = cobra.NoArgs
		cmd.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	}
	for _, sub := range cmd.Commands() {
		addClientHelpContent(sub)
	}
}

// reuse the same example on the command itself and on the pages where someone
// might first discover it. "." is the root help page.
type clientExample struct {
	pages, caption, args string
}

func examplePages(examples []clientExample) map[string][]clientExample {
	pages := make(map[string][]clientExample)
	for _, example := range examples {
		for page := range strings.SplitSeq(example.pages, ", ") {
			path := "tnl"
			if page != "." {
				path += " " + page
			}
			pages[path] = append(pages[path], example)
		}
	}
	return pages
}

func formatExamples(examples []clientExample) string {
	var text strings.Builder
	for i, example := range examples {
		if i != 0 {
			text.WriteString("\n\n")
		}
		text.WriteString("  # " + example.caption + "\n  tnl " + example.args)
	}
	return text.String()
}

func helpExamples(cmd *cobra.Command, view helpView) string {
	path := cmd.CommandPath()
	switch path {
	case "tnl":
		if view.audience == helpAgent {
			return formatExamples(leadHelpExample(clientHelpExamples[path], rootGuideExample))
		}
	case "tnl publish":
		examples := clientHelpExamples[path]
		if !view.reference {
			examples = publishStartExamples
		}
		if view.audience == helpAgent {
			examples = leadHelpExample(examples, publishStreamExample)
		}
		return formatExamples(examples)
	}
	return cmd.Example
}

func leadHelpExample(examples []clientExample, first clientExample) []clientExample {
	i := slices.Index(examples, first)
	if i <= 0 {
		return examples
	}
	return slices.Concat(examples[i:i+1], examples[:i], examples[i+1:])
}

var rootGuideExample = clientExample{".", "Get automation recipes for this version of tnl.", "agent-guide"}
var publishStreamExample = clientExample{"publish", "Read url from the ready event on stdout. Keep tnl running to serve the URL.", "publish 3000 --output ndjson"}

var publishStartExamples = []clientExample{
	{"., publish", "Give the app on port 3000 an HTTPS URL.", "publish 3000"},
	{"publish, detached", "Keep a tunnel running after the terminal closes.", "publish 3000 --detach"},
	publishStreamExample,
}

var clientHelpExamples = examplePages(slices.Concat(publishStartExamples, []clientExample{
	{"., init", "Set up this project, then start your app as usual.", "init"},
	{"., connect", "Connect to a private service.", "connect orders --deployment production"},
	rootGuideExample,

	{"init", "Preview what setup would change.", "init --dry-run"},
	{"init", "Set up the files, but run the dependency install yourself.", "init --no-install"},
	{"publish", "Try a tunnel without starting an app.", "publish --demo"},
	{"publish", "Reuse an exact hostname you manage.", "publish 3000 --hostname app.tnl.example.com"},
	{"publish", "Open a configured public service in your browser.", "publish app --open"},
	{"publish", "Remove the URL when this tunnel stops.", "publish 3000 --ephemeral"},
	{"publish", "Only admit visitors from your current public IP.", "publish 3000 --ip current"},
	{"publish", "Publish a local PostgreSQL server for connector access.", "publish 127.0.0.1:5432 --protocol postgres --name orders"},
	{"connect, connect available", "Find the services your account can reach.", "connect available"},
	{"connect, connect start", "Open psql for the orders service.", "connect orders --deployment production --client psql"},
	{"connect, connect start", "Pass a query to psql after the double dash.", `connect orders --deployment production --client psql -- -c "select 1"`},
	{"connect start", "Use an explicit local port for a configured service.", "connect start orders --listen 127.0.0.1:15432"},
	{"connect start", "Connect to a service whose name is also a command.", "connect start list"},
	{"connect list", "See installed connectors and their local ports.", "connect list"},
	{"connect stop", "Stop the installed orders connector.", "connect stop orders"},
	{"connect remove", "Remove the orders connector and its port assignment.", "connect remove orders"},

	{"auth, auth login", "Open the approval URL in your browser.", "auth login --open"},
	{"auth, auth status", "Check your credentials with the server.", "auth status --check"},
	{"auth login, auth login start", "Start a sign-in that a script can resume.", "auth login start --output json"},
	{"auth login, auth login wait", "Use the operation ID from tnl auth login start.", `auth login wait "$OPERATION_ID"`},
	{"auth login inspect", "Check the state of a login started earlier.", `auth login inspect "$OPERATION_ID"`},
	{"auth login cancel", "Cancel a pending login by its operation ID.", `auth login cancel "$OPERATION_ID"`},
	{"auth browser", "Visit a restricted URL with your CLI session.", "auth browser app.tnl.example.com"},
	{"auth logout", "Sign out of the selected server.", "auth logout"},
	{"auth credential, auth credential create", "Allow migrations to connect to orders in one deployment for an hour.", `auth credential create migrations --connect orders --deployment-id "$DEPLOYMENT_ID" --expires-in 1h --idempotency-key "$REQUEST_ID"`},

	{"status", "See tunnels for the current project.", "status"},
	{"status", "See the app's readiness, URL, and last error.", "status --service app"},
	{"status", "Read the saved local state for every project.", "status --scope local --all"},
	{"status", "Read the server's current deployment state as JSON.", "status --scope server --deployment production --output json"},
	{"wait", "Wait up to 30 seconds for the app service.", "wait --service app --timeout 30s"},
	{"wait", "Wait for both services before starting the next step.", "wait --service app --service api --output json"},
	{"watch", "Stream this worktree's events as newline-delimited JSON.", "watch --output ndjson"},
	{"watch", "Resume after the last local event cursor you saved.", `watch --output ndjson --after "$CURSOR"`},
	{"ping", "Check what a visitor sees at your public hostname.", "ping https://app.tnl.example.com"},
	{"ping", "Compare with a request straight to the local app.", "ping http://127.0.0.1:3000"},
	{"inspect, inspect list", "Find HTTP 500 responses from the last hour.", "inspect list --status 500 --since 1h"},
	{"inspect list", "Find failed PostgreSQL operations across linked worktrees.", "inspect list --protocol postgres --result error --all-worktrees"},
	{"inspect, inspect show", "Read record 42 from tnl inspect list.", "inspect show 42"},
	{"check", "Find and validate the config for this worktree.", "check"},
	{"check", "Validate a specific file.", "--config tnl.yml check"},
	{"generate", "Regenerate the project's declared artifacts.", "generate"},
	{"generate", "Fail if generated files are missing or out of date.", "generate --check"},
	{"alias, alias use", "Serve the configured staging alias from this worktree.", "alias use staging"},
	{"alias, alias release", "Return staging to the primary checkout.", "alias release staging"},
	{"webhook, webhook use", "Receive payments events in this ready worktree.", "webhook use payments"},
	{"webhook, webhook release", "Release this worktree's selection.", "webhook release payments"},

	{"share", "Share this checkout's preview for a week.", "share --expires-in 7d"},
	{"share, share create", "Share just the app service for four hours.", "share create --service app --expires-in 4h"},
	{"share, share list", "Find the ID of a link you created.", "share list"},
	{"share revoke", "End access for a share ID from tnl share list.", `share revoke "$SHARE_ID"`},
	{"share team, share team create", "Let current team members visit this preview.", "share team create"},
	{"share team, share team revoke", "End team access to this preview.", "share team revoke"},
	{"share invite, share invite create", "Invite one reviewer to a public URL.", "share invite create app.tnl.example.com --email reviewer@example.com"},
	{"share invite accept", "Accept while signed in with the invited email.", `share invite accept "$INVITATION_SECRET"`},
	{"share invite list", "See invitations for this hostname.", "share invite list app.tnl.example.com"},
	{"share invite revoke", "Use an invitation ID from tnl share invite list.", `share invite revoke app.tnl.example.com "$INVITATION_ID"`},
	{"share link, share link create", "Give a reviewer a one-hour browser link.", "share link create app.tnl.example.com --expires-in 1h"},
	{"share token, share token create", "Print a Tnl-Visitor-Token for an automated check.", `share token create app.tnl.example.com --name smoke --expires-in 5m`},
	{"share service, share service list", "See who can access orders in production.", "share service list orders --deployment production"},
	{"share service, share service invite, share service invite create", "Invite a reviewer to orders for one day.", "share service invite create orders --deployment production --email reviewer@example.com --expires-in 1d"},
	{"share service invite accept", "Redeem the invitation with the matching email account.", `share service invite accept "$INVITATION_SECRET"`},
	{"share service revoke", "Use the access ID from tnl share service list.", `share service revoke orders "$ACCESS_ID" --deployment production`},
	{"share service link, share service link create", "Create a two-hour link to the public HTTP service app.", "share service link create app --expires-in 2h"},
	{"share service token, share service token create", "Print a short-lived Tnl-Visitor-Token for app.", "share service token create app --expires-in 5m"},

	{"feedback, feedback list", "Find feedback IDs in the publishing worktree.", "feedback list"},
	{"feedback, feedback inspect", "Read a report and compare its source with this checkout.", `feedback inspect "$FEEDBACK_ID"`},
	{"feedback watch", "Follow new feedback after event 42.", "feedback watch --after 42 --output ndjson"},
	{"feedback reply", "Reply to the thread from tnl feedback list.", `feedback reply "$FEEDBACK_ID" --message "I can reproduce this."`},
	{"feedback update", "Record progress with the current source state.", `feedback update "$FEEDBACK_ID" --message "Ready for review."`},
	{"feedback resolve", "Mark the thread resolved.", `feedback resolve "$FEEDBACK_ID"`},
	{"feedback reopen", "Reopen the thread for follow-up.", `feedback reopen "$FEEDBACK_ID"`},
	{"feedback delete", "Permanently delete the local thread and its evidence.", `feedback delete "$FEEDBACK_ID"`},

	{"url, url list", "Find URLs you have access to.", "url list"},
	{"url, url inventory", "Find public endpoints your team owns.", "url inventory --team hooli"},
	{"url available", "Get the URLs you can visit as JSON.", "url available --output json"},
	{"url access, url access show", "Read the visitor policy before changing it.", "url access show app.tnl.example.com"},
	{"url access, url access set", "Require a visitor credential and allow only your IP.", "url access set app.tnl.example.com restricted --ip current"},
	{"url update", "Set the saved target for this HTTP service.", "url update app.tnl.example.com --target http://127.0.0.1:5173"},
	{"url delete", "Delete the service at its exact hostname.", "url delete app.tnl.example.com"},
	{"team, team list", "See which teams you belong to.", "team list"},
	{"team, team use", "Use hooli when a project doesn't name a team.", "team use hooli"},
	{"team current", "Show the team selected for this checkout.", "team current"},
	{"team create", "Create an organization team named hooli.", "team create hooli"},
	{"team members", "Find the membership IDs for a team.", "team members --team hooli"},
	{"team invite, team invite create", "Invite a member by email.", "team invite create --team hooli --email dev@example.com"},
	{"team invite list", "Look up an invitation ID.", "team invite list --team hooli"},
	{"team invite revoke", "Revoke the selected team's invitation.", `team invite revoke "$INVITATION_ID"`},
	{"team join", "Join with the secret from a team invitation.", `team join "$INVITATION_SECRET"`},
	{"team member, team member set-role", "Make a member an admin using the ID from tnl team members.", `team member set-role "$MEMBERSHIP_ID" --role admin`},
	{"team member remove", "Remove the membership selected by ID.", `team member remove "$MEMBERSHIP_ID"`},
	{"team feedback, team feedback get", "See who can write feedback for the team.", "team feedback get --team hooli"},
	{"team feedback, team feedback set", "Limit feedback authors to current team members.", "team feedback set team_members --team hooli"},
	{"domain, domain claim", "Claim your custom domain and get its DNS records.", "domain claim tnl.example.com --team hooli"},
	{"domain, domain status", "Check the DNS setup after adding the records.", "domain status tnl.example.com"},
	{"domain list", "Find domains available to the selected team.", "domain list"},
	{"domain default", "Use this ready domain for new service hostnames.", "domain default tnl.example.com"},
	{"domain transfer", "Offer the domain to another team.", "domain transfer tnl.example.com --to-team studio"},
	{"domain transfer", "Accept the offer as an owner of studio.", "domain transfer tnl.example.com --to-team studio --accept"},
	{"domain release", "Release an unused custom domain.", "domain release tnl.example.com"},

	{"apply", "Review the changes for production without applying them.", "apply --deployment production --diff"},
	{"apply", "Apply the configuration for production.", "apply --deployment production"},
	{"deployment, deployment list", "Find deployments for the current project.", "deployment list"},
	{"deployment, deployment show", "See the service targets saved for production.", "deployment show production"},
	{"deployment create", "Create staging for an existing orders declaration.", "deployment create staging --target orders=db.internal:5432"},
	{"deployment update", "Move the orders target in staging.", "deployment update staging --target orders=db2.internal:5432"},
	{"deployment delete", "Delete the saved staging deployment.", "deployment delete staging"},
	{"deployment rename", "Rename the deployment without changing its public addresses.", "deployment rename staging canary"},
	{"deployment namespace, deployment namespace rename", "Change hostnames using the current revision and a unique request ID.", `deployment namespace rename staging canary --expected-revision "$REVISION" --request-id "$REQUEST_ID"`},
	{"publisher, publisher setup", "Approve a publisher for orders in production.", "publisher setup --deployment production --service orders"},
	{"publisher, publisher serve", "On the publisher host, read the enrollment key from stdin.", "publisher serve --deployment production --enroll-key -"},
	{"publisher serve", "Restart a publisher that has already enrolled.", "publisher serve --deployment production"},
	{"publisher provision", "Create a private identity file for one replica.", "publisher provision --deployment production --service orders --instance replica-1 --output-file ./replica-1.json"},
	{"publisher current", "Check the grant for the local publisher identity.", "publisher current --check"},
	{"publisher enroll", "Issue an enrollment key for a single public service.", "publisher enroll app.tnl.example.com"},
	{"publisher list", "List publishers enrolled for production.", "publisher list --deployment production"},
	{"publisher revoke", "Revoke a publisher found by tnl publisher list.", `publisher revoke "$PUBLISHER_ID" --deployment production`},
	{"publisher grant, publisher grant add", "Let a publisher serve one exact hostname.", `publisher grant add "$PUBLISHER_ID" --url app.tnl.example.com`},
	{"publisher grant revoke", "Revoke one grant from tnl publisher list.", `publisher grant revoke "$PUBLISHER_ID" "$GRANT_ID"`},
	{"endpoint, endpoint release", "After disabling public access, release the reserved port.", `endpoint release "$SERVICE_ID" --port 15443`},
	{"service, service list", "Find the names and state of installed publications.", "service list"},
	{"service install", "Install the local supervisor for your user account.", "service install"},
	{"service start", "Start the installed publication named app.", "service start app"},
	{"service stop", "Stop app while keeping its installation.", "service stop app"},
	{"service remove", "Remove app after stopping it.", "service remove app"},
	{"service status", "Inspect the installed publication named app.", "service status app"},
	{"detached, detached list", "Find the ID of a detached tunnel.", "detached list"},
	{"detached stop", "Stop the tunnel with an ID from tnl detached list.", `detached stop "$DETACHED_ID"`},

	{"admin, admin server, admin server status", "See the server's service counts and process leases.", "admin server status"},
	{"admin, admin relays, admin relays list", "Find a relay's ID, run ID, and lease revision.", "admin relays list"},
	{"admin relays drain", "Use the exact run and revision from tnl admin relays list.", `admin relays drain "$RELAY_ID" --relay-run-id "$RUN_ID" --relay-lease-revision "$REVISION" --deadline 30s`},
	{"admin maintenance, admin maintenance list", "See which operations are currently blocked.", "admin maintenance list"},
	{"admin maintenance block", "Pause creation of new services.", "admin maintenance block service_creation"},
	{"admin maintenance allow", "Allow new services again.", "admin maintenance allow service_creation"},
	{"audit, audit list", "Read the last hour of service audit events as a team manager.", "audit list --since 1h"},
	{"agent-guide", "Print the guide as an installable Markdown skill.", "agent-guide --skill"},
	{"help", "Read help for a nested command.", "help share service"},
	{"help", "Read the publish reference with automation examples first.", "help publish --audience agent"},
	{"completion, completion zsh", "Print the completion script for zsh.", "completion zsh"},
	{"completion bash", "Print the completion script for bash.", "completion bash"},
	{"completion fish", "Print the completion script for fish.", "completion fish"},
	{"completion powershell", "Print the completion script for PowerShell.", "completion powershell"},
	{"telemetry, telemetry status", "Show your saved usage telemetry preference.", "telemetry status"},
	{"telemetry on", "Enable usage telemetry in this client state directory.", "telemetry on"},
	{"telemetry off", "Disable usage telemetry in this client state directory.", "telemetry off"},
	{"version", "Check the installed release.", "version"},
}))
