package main

import "github.com/spf13/cobra"

func commandHelpConstraints(cmd *cobra.Command) []string {
	if selectedPath(cmd) != "publish" {
		return nil
	}
	return []string{
		"Choose one of --foreground, --bg, or --install. --background is the same as --bg.",
		"Foreground supports human or NDJSON. Background supports human or JSON.",
		"--install requires a configured service and human output. It keeps its definition across restarts.",
		"--system, --service-name, --system-state-dir, and --server-ca-file require --install.",
		"--bg cannot read an enrollment key from stdin. Use --publisher-identity or --publisher-credential-file.",
	}
}

func commandResultHelp(cmd *cobra.Command) []helpResult {
	switch selectedPath(cmd) {
	case "publish":
		return []helpResult{
			{Mode: "foreground", Format: "human",
				Stderr: "Lifecycle messages, the address, and diagnostics.",
				Ends:   "When the foreground tunnel stops.", Proves: "Readiness is not an app response or a grant of anonymous access."},
			{Mode: "background, public HTTP", Format: "human",
				Stdout: "The address alone.", Stderr: "A command to stop this job, and any diagnostics.",
				Ends: "When the job reports readiness.", Proves: "The tunnel can accept visitors. The app's response and visitor permission are separate."},
			{Mode: "background", Format: "json",
				Stdout: "One ready receipt. Connector-only publication may have connect_command instead of url.",
				Fields: []string{"schema_version", "job_id", "mode", "target", "url", "tunnel_id", "service_id", "connect_command"}, Stderr: "Diagnostics.",
				Ends: "When the job reports readiness.", Proves: "The selected job was started. Use its exact job_id to stop it."},
			{Mode: "foreground HTTP tunnel", Format: "ndjson",
				Stdout: "One lifecycle event per line. Read url from the ready event.", Stderr: "Command errors before or outside the stream.",
				Fields: []string{"schema_version", "type", "cursor", "tunnel_id", "target", "url", "publish_run_number", "message", "code", "help_url", "retryable", "retry_at", "reason", "transport"},
				Events: []string{string(publishEventStarting), string(publishEventReady), string(publishEventWarning), string(publishEventError), string(publishEventStopped)},
				Ends:   "When the foreground tunnel stops.", Proves: "A ready event says the tunnel can accept visitors, not that an HTTP request succeeded."},
		}
	case "connect start":
		return []helpResult{
			{Mode: "client", Format: "raw",
				Stdout: "The client's own stdout.", Stderr: "The client's own stderr; tnl reports setup or cleanup failures.",
				Ends: "After the client and connector exit.", Proves: "The exit status reflects the client; the connector does not keep listening."},
			{Mode: "stdio", Format: "raw",
				Stdout: "The connection byte stream.", Stderr: "Diagnostics.",
				Ends: "When the stream closes.", Proves: "No local listener was opened."},
			{Mode: "background", Format: "json",
				Stdout: "One connection profile with the listener and, where available, client argv.", Stderr: "Diagnostics.",
				Fields: []string{"schema", "job_id", "service_id", "host", "port", "hostname", "protocol", "command"},
				Ends:   "When the connector is ready.", Proves: "The local connector is listening. Database or cluster sign-in is separate."},
		}
	case "status":
		return []helpResult{
			{Mode: "service", Format: "json", Stdout: "One report for the selected project or projects.",
				Stderr: "Diagnostics.", Fields: []string{"schema_version", "scope", "projects"}, Ends: "After reading the requested sources.", Proves: "Recorded or server evidence was read. No probe ran."},
			{Mode: "job inventory", Format: "json", Stdout: "One object containing jobs.",
				Stderr: "Diagnostics.", Fields: []string{"schema_version", "jobs"}, Ends: "After reading local owners.", Proves: "Local job observations were read. No app probe ran."},
		}
	case "stop":
		return []helpResult{{Mode: "job", Format: "json", Stdout: "One stop receipt.", Stderr: "Diagnostics.",
			Fields: []string{"schema_version", "job_id", "state"}, Ends: "After the stop request is acknowledged, or shutdown is confirmed.",
			Proves: "stopped confirms joined work; stopping does not. Installed definitions stay saved."}}
	case "wait":
		return []helpResult{{Format: "json", Stdout: "One observation with state and checked_by. A timeout can still include an observation.", Stderr: "Diagnostics.",
			Fields: []string{"schema_version", "state", "checked_by", "services"}, Ends: "When all selected services pass or the timeout expires.",
			Proves: "Exit zero means the configured checks passed now. checked_by distinguishes a target-only check from a public-path check."}}
	case "watch":
		return []helpResult{{Format: "ndjson", Stdout: "An initial snapshot unless --after is set, then matching new events.", Stderr: "Diagnostics.",
			Fields: []string{"type", "snapshot.cursor", "cursor"}, Ends: "On --count, --timeout, or interruption. The initial snapshot does not count.",
			Proves: "Received events describe this worktree. Save the cursor with its worktree and state directory."}}
	case "share create":
		return []helpResult{
			{Format: "human", Stdout: "The share link alone.", Stderr: "Diagnostics.", Ends: "After one share is created.", Proves: "Access was granted to the captured services until expiry or revocation."},
			{Format: "json", Stdout: "One receipt containing the link and its revocation ID from the same creation.", Stderr: "Diagnostics.",
				Fields: []string{"schema_version", "entry_url", "share_id", "service_ids", "expires_at"}, Ends: "After one share is created.",
				Proves: "Only service_ids are included. Keep entry_url private."},
		}
	case "share revoke":
		return []helpResult{{Format: "json", Stdout: "One revocation receipt.", Stderr: "Diagnostics.",
			Fields: []string{"schema_version", "share_id", "revoked"}, Ends: "After control confirms revocation.",
			Proves: "The exact share ID was revoked."}}
	case "auth login start":
		return []helpResult{{Format: "json", Stdout: "One approval operation.", Stderr: "Diagnostics.",
			Fields: []string{"schema_version", "operation_id", "approval_url", "user_code"}, Ends: "After saving the local login operation.",
			Proves: "The user can approve the operation. A session is not signed in yet."}}
	case "init":
		return []helpResult{{Format: "json", Stdout: "One plan with --dry-run or one report of actual edits.", Stderr: "Diagnostics.",
			Fields: []string{"schema_version", "project", "dry_run", "no_install", "files", "steps"},
			Ends:   "After planning or applying setup.", Proves: "A dry run wrote no files. For an actual run, read the outstanding steps before starting the app."}}
	case "apply":
		return []helpResult{{Mode: "preview", Format: "json", Stdout: "One comparison with a string base_revision.", Stderr: "Diagnostics.",
			Fields: []string{"team_id", "deployment", "base_revision", "changes"}, Ends: "After comparing against the saved deployment.",
			Proves: "No change was applied and no endpoint or revision was reserved."}}
	case "feedback list":
		return []helpResult{{Format: "json", Stdout: "One page of feedback for the publishing worktree.", Stderr: "Diagnostics.",
			Fields: []string{"threads"}, Ends: "After reading one page.", Proves: "This is not a team-wide feed."}}
	default:
		return nil
	}
}
