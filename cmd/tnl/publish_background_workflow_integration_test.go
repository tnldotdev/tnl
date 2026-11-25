package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationCLIPublishBackgroundJobsStopExactly(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	t.Setenv("AI_AGENT", "fixture-agent")
	f := newCLIWorkflow(t)
	state := f.state(t, "background-publish")
	f.loginPerson(t, state)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "shared target")
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { cleanupBackgroundJobs(t, state) })
	command := workflowBackgroundCLI(t, f)

	human := command(t.Context(), "publish", server.URL, "--name", "first", "--anonymous", "--background", "--server", f.url, "--state-dir", state)
	if human.err != nil {
		t.Fatalf("human launch: %v\n%s", human.err, human.stderr)
	}
	firstURL := strings.TrimSpace(string(human.stdout))
	hint := strings.Fields(string(human.stderr))
	if string(human.stdout) != firstURL+"\n" || !strings.HasPrefix(firstURL, "https://first.") ||
		len(hint) != 7 || strings.Join(hint[:4], " ") != "To stop: tnl stop" ||
		!opaqueid.Valid(hint[4], opaqueid.JobPrefix) || hint[5] != "--state-dir" || hint[6] != state {
		t.Fatalf("human stdout: %q; stderr: %q", human.stdout, human.stderr)
	}
	firstID := hint[4]
	machine := command(t.Context(), "publish", server.URL, "--name", "second", "--anonymous", "--bg", "--output=json", "--server", f.url, "--state-dir", state)
	var receipt struct {
		JobID    string `json:"job_id"`
		TunnelID string `json:"tunnel_id"`
		URL      string `json:"url"`
		Target   string `json:"target"`
		Mode     string `json:"mode"`
	}
	if machine.err != nil || len(machine.stderr) != 0 || json.Unmarshal(machine.stdout, &receipt) != nil ||
		receipt.JobID == firstID || !opaqueid.Valid(receipt.JobID, opaqueid.JobPrefix) || !opaqueid.Valid(receipt.TunnelID, opaqueid.TunnelPrefix) ||
		receipt.Target != server.URL || receipt.Mode != "background" || !strings.HasPrefix(receipt.URL, "https://second.") {
		t.Fatalf("machine launch: %v\nstdout: %q\nstderr: %q", machine.err, machine.stdout, machine.stderr)
	}
	check := func(address string) {
		t.Helper()
		httpClient := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
		workflowWait(t, 15*time.Second, func() bool {
			response, err := httpClient.Get(address)
			if err != nil {
				return false
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			return err == nil && response.StatusCode == http.StatusOK && string(body) == "shared target"
		})
	}
	check(firstURL)
	check(receipt.URL)

	firstStop := command(t.Context(), "stop", firstID, "--state-dir", state, "--output=json")
	var stop jobStatus
	if firstStop.err != nil || len(firstStop.stderr) != 0 || json.Unmarshal(firstStop.stdout, &stop) != nil ||
		stop.JobID != firstID || (stop.State != "stopping" && stop.State != "stopped") {
		t.Fatalf("stop: %v\nstdout: %q\nstderr: %q", firstStop.err, firstStop.stdout, firstStop.stderr)
	}
	waitBackgroundJobExit(t, t.Context(), state, firstID)
	check(receipt.URL)

	list := command(t.Context(), "status", "--bg", "--state-dir", state, "--output=json")
	var jobs struct {
		Jobs []jobStatus `json:"jobs"`
	}
	if list.err != nil || len(list.stderr) != 0 || json.Unmarshal(list.stdout, &jobs) != nil || len(jobs.Jobs) != 1 ||
		jobs.Jobs[0].JobID != receipt.JobID || jobs.Jobs[0].Address != receipt.URL || jobs.Jobs[0].Target != server.URL || jobs.Jobs[0].State != "ready" {
		t.Fatalf("list: %v\nstdout: %q\nstderr: %q", list.err, list.stdout, list.stderr)
	}
	t.Logf("human publish (exit 0)\nstdout:\n%sstderr:\n%s", human.stdout, human.stderr)
	t.Logf("machine publish (exit 0)\nstdout:\n%sstderr: empty", machine.stdout)
	t.Logf("stop first (exit 0)\nstdout:\n%sstderr: empty", firstStop.stdout)
	t.Logf("list after stop (exit 0)\nstdout:\n%sstderr: empty", list.stdout)
}
