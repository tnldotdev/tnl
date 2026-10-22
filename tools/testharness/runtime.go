package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

type runtimeHarness struct {
	stack         *compose.DockerCompose
	project       string
	file          string
	results       string
	endpoint      string
	token         string
	containers    map[string]*testcontainers.DockerContainer
	selected      string
	activePublish []string
	ingresses     []string
	intentional   atomic.Bool
	faultStarted  bool
	faultDone     chan error
	faultTasks    sync.WaitGroup
	eventsCancel  context.CancelFunc
	logsCancel    context.CancelFunc
	watchers      sync.WaitGroup
}

var runtimePublishers = []string{"publishers", "publishers-2", "publishers-3", "publishers-4"}
var runtimeApps = []string{"app", "app-2", "app-3", "app-4"}

func runRuntime(ctx context.Context, root string) (retErr error) {
	results := os.Getenv("RESULTS")
	if results == "" {
		return errors.New("RESULTS directory is required")
	}
	if !filepath.IsAbs(results) {
		results = filepath.Join(root, results)
	}
	results, err := filepath.Abs(results)
	if err != nil {
		return err
	}
	if files, err := os.ReadDir(results); err == nil && len(files) != 0 {
		return errors.New("RESULTS must be a fresh or empty directory")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(results, 0o755); err != nil {
		return fmt.Errorf("create runtime results directory: %w", err)
	}
	if err := os.Setenv("RESULTS", results); err != nil {
		return err
	}
	routes, err := strconv.Atoi(os.Getenv("PUBLIC_URLS"))
	if err != nil || routes < 4 || routes > 10000 {
		return errors.New("PUBLIC_URLS must be between 4 and 10000")
	}
	scenario := os.Getenv("SCENARIO")
	if scenario == "" {
		scenario = "relay-restart"
	}
	if scenario != "relay-restart" && scenario != "control-restart" && !runtimeExternalFault(scenario) {
		return fmt.Errorf("unknown runtime scenario %q", scenario)
	}
	if topology := os.Getenv("HA_TOPOLOGY"); topology != "0" && topology != "1" && topology != "" {
		return errors.New("HA_TOPOLOGY must be 0 or 1")
	}
	ha := os.Getenv("HA_TOPOLOGY") != "0"
	profiles := []string{}
	if ha {
		profiles = append(profiles, "ha")
	}
	if scenario == "control-restart" {
		profiles = append(profiles, "replicated-relays")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	project := "tnl-separated-load-" + hex.EncodeToString(random[:])
	file := filepath.Join(root, "internal/tnldruntime/testdata/separated-load.compose.yaml")
	stack, err := compose.NewDockerComposeWith(compose.StackIdentifier(project), compose.WithStackFiles(file), compose.WithProfiles(profiles...))
	if err != nil {
		return fmt.Errorf("configure runtime topology: %w", err)
	}
	stack.WithOsEnv()
	h := &runtimeHarness{stack: stack, file: file, project: project, results: results, selected: scenario,
		containers: make(map[string]*testcontainers.DockerContainer), faultDone: make(chan error, 1)}
	if ha {
		h.ingresses = []string{"ingress-a", "ingress-b"}
	} else {
		h.ingresses = []string{"ingress-a"}
	}
	for index, name := range runtimePublishers {
		if index*2 < routes {
			h.activePublish = append(h.activePublish, name)
		}
	}
	defer func() { retErr = errors.Join(retErr, h.close()) }()
	for _, volume := range []string{"tnl-load-go-build", "tnl-load-go-modules"} {
		if _, err := h.docker(ctx, "volume", "create", volume); err != nil {
			return err
		}
	}
	if err := stack.Up(ctx, compose.RunServices("build")); err != nil {
		return fmt.Errorf("build runtime test binary: %w", err)
	}
	if err := h.waitForExit(ctx, "build"); err != nil {
		return err
	}
	if err := stack.Up(ctx, compose.RunServices("postgres"), compose.Wait(true)); err != nil {
		return fmt.Errorf("start runtime PostgreSQL: %w", err)
	}
	if err := stack.Up(ctx, compose.RunServices("setup")); err != nil {
		return fmt.Errorf("set up runtime database: %w", err)
	}
	if err := h.waitForExit(ctx, "setup"); err != nil {
		return err
	}
	if err := h.startEventWatcher(ctx); err != nil {
		return err
	}
	services := []string{"control-a", "ingress-a", "relay-a", "relay-b"}
	if ha {
		services = append(services, "control-b", "ingress-b")
	}
	if scenario == "control-restart" {
		services = append(services, "relay-a-2", "relay-b-2")
	}
	services = append(services, runtimePublishers...)
	services = append(services, "visitor-1", "visitor-2", "visitor-3", "visitor-4")
	services = append(services, runtimeApps...)
	services = append(services, "dns", "pebble", "coordinator")
	if err := stack.Up(ctx, compose.RunServices(services...)); err != nil {
		return fmt.Errorf("start runtime components: %w", err)
	}
	if err := h.startLogWatcher(ctx); err != nil {
		return err
	}
	for _, name := range append([]string{"postgres"}, services...) {
		container, err := stack.ServiceContainer(ctx, name)
		if err != nil {
			return fmt.Errorf("inspect runtime component %s: %w", name, err)
		}
		h.containers[name] = container
	}
	coordinator := h.containers["coordinator"]
	h.endpoint, err = coordinator.PortEndpoint(ctx, "8080/tcp", "http")
	if err != nil {
		return fmt.Errorf("read runtime coordinator address: %w", err)
	}
	code, reader, err := coordinator.Exec(ctx, []string{"cat", "/load/coordinator-token"})
	if err != nil || code != 0 {
		return fmt.Errorf("read runtime coordinator token: exit %d: %v", code, err)
	}
	var token bytes.Buffer
	if _, err := stdcopy.StdCopy(&token, io.Discard, io.LimitReader(reader, 4096)); err != nil {
		return err
	}
	h.token = strings.TrimSpace(token.String())
	if h.token == "" {
		return errors.New("runtime coordinator token is missing")
	}
	return h.observe(ctx)
}

func (h *runtimeHarness) observe(ctx context.Context) error {
	maxDuration := 20 * time.Minute
	if os.Getenv("HELD_MEASURE") != "0s" {
		maxDuration = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-h.faultDone:
			if err != nil {
				return fmt.Errorf("runtime fault: %w", err)
			}
		default:
		}
		for name, container := range h.containers {
			if name == "postgres" {
				continue
			}
			state, err := container.State(ctx)
			if err != nil {
				return fmt.Errorf("inspect runtime %s: %w", name, err)
			}
			if name == "coordinator" && !state.Running {
				if state.ExitCode != 0 {
					return fmt.Errorf("runtime coordinator exited with status %d", state.ExitCode)
				}
				return nil
			}
			if !state.Running && !(name == "relay-a" && h.intentional.Load() && state.ExitCode == 137) {
				h.saveSnapshot("unexpected-component-exit.json")
				return fmt.Errorf("unexpected runtime component exit: %s (%d)", name, state.ExitCode)
			}
		}
		if runtimeExternalFault(h.selected) && !h.faultStarted {
			data, err := h.event(ctx, "fault.request", nil)
			if err != nil {
				return err
			}
			if len(data) != 0 {
				var requested string
				if err := json.Unmarshal(data, &requested); err != nil || requested != h.selected {
					return fmt.Errorf("unexpected runtime fault request: %s: %v", data, err)
				}
				h.faultStarted = true
				h.faultTasks.Go(func() { h.faultDone <- h.applyFault(ctx) })
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runtimeExternalFault(scenario string) bool {
	switch scenario {
	case "relay-kill", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss":
		return true
	default:
		return false
	}
}

func (h *runtimeHarness) startEventWatcher(ctx context.Context) error {
	eventFile, err := os.Create(filepath.Join(h.results, "docker-exit-events.log"))
	if err != nil {
		return err
	}
	eventsCtx, stopEvents := context.WithCancel(ctx)
	h.eventsCancel = stopEvents
	events := exec.CommandContext(eventsCtx, "docker", "events", "--filter", "type=container",
		"--filter", "label=com.docker.compose.project="+h.project, "--filter", "event=die",
		"--filter", "event=kill", "--filter", "event=oom", "--format",
		"{{.TimeNano}} {{.Action}} {{.Actor.Attributes.name}} exit={{.Actor.Attributes.exitCode}} signal={{.Actor.Attributes.signal}}")
	events.Stdout, events.Stderr = eventFile, os.Stderr
	if err := events.Start(); err != nil {
		_ = eventFile.Close()
		return err
	}
	h.watchers.Go(func() { _ = events.Wait(); _ = eventFile.Close() })
	return nil
}

func (h *runtimeHarness) startLogWatcher(ctx context.Context) error {
	logsCtx, stopLogs := context.WithCancel(ctx)
	h.logsCancel = stopLogs
	logs := exec.CommandContext(logsCtx, "docker", "compose", "--file", h.file,
		"--project-name", h.project, "logs", "--follow", "--no-color")
	logs.Stdout, logs.Stderr = os.Stdout, os.Stderr
	if err := logs.Start(); err != nil {
		stopLogs()
		return err
	}
	h.watchers.Go(func() { _ = logs.Wait() })
	return nil
}

func (h *runtimeHarness) saveSnapshot(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	data, err := h.compose(ctx, "ps", "--all", "--format", "json")
	if err != nil {
		fmt.Fprintln(os.Stderr, "capture runtime container snapshot:", err)
		return
	}
	if err := os.WriteFile(filepath.Join(h.results, name), []byte(data), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "save runtime container snapshot:", err)
	}
}

func (h *runtimeHarness) waitForExit(ctx context.Context, name string) error {
	container, err := h.stack.ServiceContainer(ctx, name)
	if err != nil {
		return err
	}
	for {
		state, err := container.State(ctx)
		if err != nil {
			return err
		}
		if !state.Running {
			if state.ExitCode != 0 {
				logs, err := container.Logs(ctx)
				if err == nil {
					defer logs.Close()
					_, _ = io.Copy(os.Stderr, io.LimitReader(logs, 1<<20))
				}
				return fmt.Errorf("runtime %s exited with status %d", name, state.ExitCode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (h *runtimeHarness) docker(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func (h *runtimeHarness) compose(ctx context.Context, args ...string) (string, error) {
	arguments := append([]string{"compose", "--ansi", "never", "--file", h.file, "--project-name", h.project}, args...)
	return h.docker(ctx, arguments...)
}

func (h *runtimeHarness) event(ctx context.Context, name string, body any) ([]byte, error) {
	var source io.Reader
	method := http.MethodGet
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		source, method = strings.NewReader(string(payload)), http.MethodPut
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, h.endpoint+"/v1/events/"+name, source)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+h.token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && body == nil {
		return nil, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("runtime event %s returned HTTP %d", name, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64<<10))
}

func (h *runtimeHarness) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	h.faultTasks.Wait()
	h.saveSnapshot("containers-before-cleanup.json")
	for _, group := range [][]string{
		{"visitor-1", "visitor-2", "visitor-3", "visitor-4"},
		append(runtimeApps, runtimePublishers...),
		{"ingress-a", "ingress-b", "relay-a", "relay-b"},
		{"control-a", "control-b", "pebble", "dns", "coordinator", "postgres"},
	} {
		var present []string
		for _, name := range group {
			if _, ok := h.containers[name]; ok {
				present = append(present, name)
			}
		}
		if len(present) != 0 {
			_, _ = h.compose(ctx, append([]string{"stop"}, present...)...)
		}
	}
	h.saveSnapshot("containers.json")
	if h.logsCancel != nil {
		h.logsCancel()
	}
	if h.eventsCancel != nil {
		h.eventsCancel()
	}
	h.watchers.Wait()
	err := h.stack.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
	return errors.Join(err, h.stack.Close())
}
