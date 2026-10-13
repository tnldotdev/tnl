package stagingcheck

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type readyEvent struct {
	SchemaVersion    int    `json:"schema_version"`
	Type             string `json:"type"`
	Code             string `json:"code"`
	URL              string `json:"url"`
	TunnelID         string `json:"tunnel_id"`
	PublishRunNumber uint64 `json:"publish_run_number"`
}

func parseReady(line []byte) (readyEvent, error) {
	var event readyEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return event, fmt.Errorf("invalid tnl publish event: %w", err)
	}
	if event.SchemaVersion != 1 || event.Type == "" {
		return event, errors.New("invalid tnl publish event shape")
	}
	if event.Type == "error" {
		return event, fmt.Errorf("tnl publish: %s", event.Code)
	}
	if event.Type == "ready" && (event.URL == "" || event.TunnelID == "" || event.PublishRunNumber == 0) {
		return event, errors.New("incomplete tnl ready event")
	}
	return event, nil
}

type cliCheck struct {
	settings
	cwd, state string
}

func (c cliCheck) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.binary, append([]string{"--no-config", "--no-telemetry"}, args...)...)
	cmd.Dir = c.cwd
	cmd.Env = append(os.Environ(), "TNL_LOGIN_TOKEN="+c.token, "TNL_STATE_DIR="+c.state, "TNL_SERVER="+c.server)
	return cmd
}

func (c cliCheck) run(ctx context.Context, args ...string) (string, error) {
	command := c.command(ctx, args...)
	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("tnl %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(data)), nil
}

type cliPublisher struct {
	command *exec.Cmd
	ready   chan readyOutcome
	done    chan error
	stopped bool
}

type readyOutcome struct {
	event readyEvent
	err   error
}

func (c cliCheck) publish(ctx context.Context, target string, flags ...string) (*cliPublisher, error) {
	args := append([]string{"publish", target, "--server=" + c.server, "--state-dir=" + c.state, "--team=" + c.team, "--output=ndjson"}, flags...)
	cmd := c.command(ctx, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	process := &cliPublisher{command: cmd, ready: make(chan readyOutcome, 1), done: make(chan error, 1)}
	go func() {
		scanner := bufio.NewScanner(stdout)
		reported := false
		for scanner.Scan() {
			if reported {
				continue
			}
			event, err := parseReady(scanner.Bytes())
			if err != nil || event.Type == "ready" {
				process.ready <- readyOutcome{event, err}
				reported = true
			}
		}
		if !reported {
			process.ready <- readyOutcome{err: errors.Join(errors.New("tnl publish stopped before ready"), scanner.Err())}
		}
	}()
	go func() { process.done <- cmd.Wait() }()
	return process, nil
}

func (p *cliPublisher) waitReady(ctx context.Context) (readyEvent, error) {
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case ready := <-p.ready:
		return ready.event, ready.err
	case <-readyCtx.Done():
		return readyEvent{}, readyCtx.Err()
	}
}

func (p *cliPublisher) stop() error {
	if p.stopped {
		return nil
	}
	p.stopped = true
	_ = p.command.Process.Signal(os.Interrupt)
	select {
	case err := <-p.done:
		return err
	case <-time.After(20 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
		return errors.New("tnl publish did not stop after interrupt")
	}
}

func checkCLI(t *testing.T, ctx context.Context, config settings) {
	t.Helper()
	label := runLabel(t)
	t.Logf("cli check label=%s team=%s", label, config.team)
	c := cliCheck{settings: config, cwd: t.TempDir(), state: filepath.Join(t.TempDir(), "client-state")}
	savedStarted := false
	observed := map[string]string{}
	t.Cleanup(func() { cleanupCLI(t, config, label, savedStarted, observed) })
	if _, err := c.run(ctx, "auth", "login", "--server="+config.server, "--state-dir="+c.state, "--login-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.run(ctx, "team", "use", config.team, "--server="+config.server, "--state-dir="+c.state); err != nil {
		t.Fatal(err)
	}
	nonce := runLabel(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/release-check/"+nonce {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(struct{ Host, Nonce string }{r.Host, nonce})
	}))
	t.Cleanup(origin.Close)
	check := func(flags ...string) (readyEvent, string) {
		t.Helper()
		process, err := c.publish(ctx, origin.URL, flags...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := process.stop(); err != nil {
				t.Errorf("stop tnl publish: %v", err)
			}
		})
		ready, err := process.waitReady(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := visitCLI(ctx, ready.URL, nonce); err != nil {
			t.Fatal(err)
		}
		status, err := c.run(ctx, "status", "--all", "--output=json", "--state-dir="+c.state)
		if err != nil {
			t.Fatal(err)
		}
		id, err := statusPublicURLID([]byte(status), ready.TunnelID, c.server)
		if err != nil {
			t.Fatal(err)
		}
		observed[id] = ready.URL
		if err := process.stop(); err != nil {
			t.Fatal(err)
		}
		return ready, id
	}
	// the ephemeral check exercises automatic removal; the saved check asserts stable identity.
	check("--ephemeral")
	savedStarted = true
	first, firstID := check("--name=" + label)
	second, secondID := check("--name=" + label)
	if first.URL != second.URL || firstID != secondID || second.PublishRunNumber <= first.PublishRunNumber {
		t.Fatalf("saved URL was not reused: first=%+v/%s second=%+v/%s", first, firstID, second, secondID)
	}
	if config.customDomain != "" {
		shared := "https://" + label + "." + config.customDomain
		ready, _ := check("--ephemeral", "--public-url="+shared)
		if ready.URL != shared {
			t.Fatalf("shared URL = %s, want %s", ready.URL, shared)
		}
	}
}

func verifyBinary(t *testing.T, ctx context.Context, config settings) {
	t.Helper()
	c := cliCheck{settings: config, cwd: t.TempDir(), state: filepath.Join(t.TempDir(), "version-state")}
	version, err := c.run(ctx, "version", "--output=raw")
	if err != nil || !strings.HasPrefix(version, "tnl "+config.version+" (") {
		t.Fatalf("tnl binary version = %q: %v", version, err)
	}
	versionJSON, err := c.run(ctx, "version", "--output=json")
	if err != nil {
		t.Fatal(err)
	}
	var build struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal([]byte(versionJSON), &build); err != nil || build.Version != config.version || build.Commit != config.revision {
		t.Fatalf("tnl binary revision differs from selected deploy: version=%q commit=%q: %v", build.Version, build.Commit, err)
	}
}

func visitCLI(ctx context.Context, publicURL, nonce string) error {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return visitWithClient(ctx, client, publicURL, nonce)
}

func visitWithClient(ctx context.Context, client *http.Client, publicURL, nonce string) error {
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Path != "" {
		return fmt.Errorf("invalid public URL %q: %v", publicURL, err)
	}
	parsed.Path = "/release-check/" + nonce
	deadline, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		request, err := http.NewRequestWithContext(deadline, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			var body struct{ Host, Nonce string }
			readErr := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&body)
			closeErr := response.Body.Close()
			if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || body.Host != parsed.Host || body.Nonce != nonce || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				return fmt.Errorf("visitor reached the wrong local service or invalid response: status=%d, decode=%v, close=%v", response.StatusCode, readErr, closeErr)
			}
			return nil
		}
		if err := deadline.Err(); err != nil {
			return fmt.Errorf("visitor %s: %w", publicURL, err)
		}
		if err := timeUntil(deadline, 2*time.Second); err != nil {
			return fmt.Errorf("visitor %s: %w", publicURL, err)
		}
	}
}

func timeUntil(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func statusPublicURLID(data []byte, tunnelID, server string) (string, error) {
	var snapshot struct {
		Tunnels []struct {
			TunnelID    string `json:"tunnel_id"`
			Server      string `json:"server"`
			PublicURLID string `json:"public_url_id"`
		} `json:"tunnels"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return "", err
	}
	for _, tunnel := range snapshot.Tunnels {
		if tunnel.TunnelID == tunnelID && tunnel.Server == server && tunnel.PublicURLID != "" {
			return tunnel.PublicURLID, nil
		}
	}
	return "", errors.New("tnl status has no public URL ID for this tunnel on this server")
}

func cleanupCLI(t *testing.T, config settings, label string, savedStarted bool, observed map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	control, closeState, err := openControl(ctx, config, filepath.Join(t.TempDir(), "cli-cleanup"))
	if err != nil {
		t.Errorf("authenticate CLI cleanup: %v", err)
		return
	}
	defer func() {
		if err := closeState(); err != nil {
			t.Error(err)
		}
	}()
	urls, err := control.ListPublicURLs(ctx, config.team)
	if err != nil {
		t.Errorf("list test team URLs for cleanup: %v", err)
		return
	}
	saved := false
	for _, publicURL := range urls {
		address := observed[publicURL.Id]
		matched := address == "https://"+publicURL.CanonicalHostname
		if publicURL.PublicPort != nil {
			matched = address == fmt.Sprintf("%s:%d", publicURL.CanonicalHostname, *publicURL.PublicPort)
		}
		if publicURL.TeamId != config.team || !strings.HasPrefix(publicURL.CanonicalHostname, label+".") && !matched {
			continue
		}
		if publicURL.LifecycleState != controlv1.Enabled && publicURL.LifecycleState != controlv1.Suspended {
			continue
		}
		if !publicURL.Ephemeral {
			saved = true
		} else {
			t.Errorf("ephemeral CLI public URL %s remained after publisher stopped", publicURL.Id)
		}
		if err := control.DeletePublicURL(ctx, publicURL.Id); err != nil {
			t.Errorf("delete test-owned public URL %s: %v", publicURL.Id, err)
		}
	}
	if savedStarted && !saved {
		t.Error("saved CLI public URL was not found for cleanup")
	}
}
