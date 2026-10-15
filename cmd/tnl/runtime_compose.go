package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

func init() {
	runtimeTargetResolver = publishertarget.Resolver{}
	runtimeOwnerTransport = composeOwnerTransport{}
}

type composeOwnerTransport struct{}

// app placement comes from the configured Compose service, never a listener's
// reported hostname, pid, directory, or a guessed generated container name.
var runtimeComposeApps func(projectconfig.Project) (map[string]localpublisher.ComposeApp, error)

func (composeOwnerTransport) OwnerEndpoint(ctx context.Context, project projectconfig.Project, root string) (privateprotocol.Endpoint, error) {
	compose := project.Config.Publisher != nil && project.Config.Publisher.Type == "compose"
	path, err := privateprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		return privateprotocol.Endpoint{}, err
	}
	if compose {
		owner, err := runtimeComposeOwner(ctx, project)
		if err != nil {
			return privateprotocol.Endpoint{}, err
		}
		setup, err := runtimeComposeHostSetup(ctx, project, owner)
		if err != nil {
			return privateprotocol.Endpoint{}, err
		}
		if err := owner.Configure(ctx, setup); err != nil {
			return privateprotocol.Endpoint{}, err
		}
		// setup may have just released the owner's startup wait. poll its real
		// API before considering a cached bridge or spawning a new bridge.
		if err := runtimeWaitComposeOwner(ctx, owner); err != nil {
			return privateprotocol.Endpoint{}, err
		}
	}
	if endpoint, err := privateprotocol.ReadEndpoint(path); err == nil && runtimeAvailable(ctx, endpoint) {
		return endpoint, nil
	}
	if compose {
		// the old bridge owns the descriptor lock until its container identity
		// check retires it. don't launch a replacement while it still holds it.
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			lock, err := filelock.Acquire(path+".lock", filelock.Nonblocking, os.Geteuid())
			if err == nil {
				_ = lock.Close()
				break
			}
			if !errors.Is(err, filelock.ErrLocked) {
				return privateprotocol.Endpoint{}, err
			}
			select {
			case <-ctx.Done():
				return privateprotocol.Endpoint{}, ctx.Err()
			case <-deadline.C:
				return privateprotocol.Endpoint{}, errors.New("previous compose owner bridge did not stop")
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return privateprotocol.Endpoint{}, err
	}
	args := []string{"runtime", "serve", "--directory", project.Root, "--state-dir", root}
	if compose {
		args = append(args, "--compose-proxy")
	}
	command := exec.Command(executable, args...)
	if err := command.Start(); err != nil {
		return privateprotocol.Endpoint{}, err
	}
	go func() { _ = command.Wait() }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if endpoint, err := privateprotocol.ReadEndpoint(path); err == nil && runtimeAvailable(ctx, endpoint) {
			return endpoint, nil
		}
		select {
		case <-ctx.Done():
			return privateprotocol.Endpoint{}, errors.New("local publisher did not become ready")
		case <-ticker.C:
		}
	}
}

func runtimeWaitComposeOwner(ctx context.Context, owner localpublisher.ComposeOwner) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if reply, err := owner.Call(ctx, localpublisher.ComposeQuery{Method: "GET", Path: "/v1/health"}); err == nil && reply.Status == 204 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func runtimeComposeOwner(ctx context.Context, project projectconfig.Project) (localpublisher.ComposeOwner, error) {
	p := project.Config.Publisher
	if p == nil || p.Type != "compose" {
		return localpublisher.ComposeOwner{}, errors.New("project does not select a compose publisher")
	}
	file, err := project.PublisherComposeFile()
	if err != nil {
		return localpublisher.ComposeOwner{}, err
	}
	// use the same worktree-scoped project name as implicit Compose targets.
	owner := localpublisher.ComposeOwner{HostRoot: project.Root, Project: project.Worktree.Label.FullLabel, File: file, Service: p.Service, Worktree: project.Worktree}
	container, err := publishertarget.ComposeContainer(ctx, publishertarget.CLI{}, owner.HostRoot, owner.File, owner.Project, owner.Service, owner.Worktree.Label.FullLabel)
	if err != nil {
		return owner, err
	}
	owner.ContainerID = container.ID
	if owner.ContainerRoot == "" {
		for _, mount := range container.Mounts {
			if composeProjectMount(mount, owner.HostRoot) {
				owner.ContainerRoot = mount.Destination
			}
		}
		if owner.ContainerRoot == "" {
			return owner, errors.New("compose publisher must mount the project root")
		}
	}
	return owner, nil
}

func composeProjectMount(mount publishertarget.Mount, root string) bool {
	if mount.Type != "bind" || !filepath.IsAbs(mount.Destination) || !filepath.IsAbs(root) {
		return false
	}
	// docker desktop can report host bind sources with a /host_mnt prefix.
	return mount.Source == root || runtime.GOOS == "darwin" && mount.Source == "/host_mnt"+root
}

// runRuntimeComposeProxy is a host control bridge, not a second publisher. all
// leases, app registrations, integrations, and publication workers live inside
// the configured Compose owner and use its one manager and client state.
func runRuntimeComposeProxy(ctx context.Context, options runtimeOptions) error {
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	owner, err := runtimeComposeOwner(ctx, project.Project)
	if err != nil {
		return err
	}
	path, err := privateprotocol.DescriptorPath(root, project.Root)
	if err != nil {
		return err
	}
	lock, err := filelock.Acquire(path+".lock", filelock.Nonblocking, os.Geteuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	endpoint, bridge, err := owner.Bridge(ctx)
	if err != nil {
		return err
	}
	defer bridge.Close()
	if err := privateprotocol.WriteEndpoint(path, endpoint); err != nil {
		return err
	}
	defer privateprotocol.RemoveEndpoint(path, endpoint.OwnerId)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := owner.Call(ctx, localpublisher.ComposeQuery{Method: "GET", Path: "/v1/health"}); err != nil {
				return err
			}
		}
	}
}

func runRuntimeComposeRequest(ctx context.Context, options runtimeOptions, input io.Reader, output io.Writer) error {
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(options.Directory)
	if err != nil {
		return err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	path, err := privateprotocol.DescriptorPath(root, directory)
	if err != nil {
		return err
	}
	endpoint, err := privateprotocol.ReadEndpoint(path)
	if err != nil {
		return err
	}
	return localpublisher.ServeComposeQuery(ctx, endpoint, input, output)
}

func runtimeComposeHostSetup(ctx context.Context, project projectconfig.Project, owner localpublisher.ComposeOwner) (localpublisher.ComposeSetup, error) {
	docker := publishertarget.CLI{}
	if err := publishertarget.Local(ctx, docker); err != nil {
		return localpublisher.ComposeSetup{}, err
	}
	container, err := publishertarget.ComposeContainer(ctx, docker, owner.HostRoot, owner.File, owner.Project, owner.Service, owner.Worktree.Label.FullLabel)
	if err != nil {
		return localpublisher.ComposeSetup{}, err
	}
	network, err := localpublisher.ComposeNetwork(ctx, docker, container, owner.Worktree.Label.FullLabel)
	if err != nil {
		return localpublisher.ComposeSetup{}, err
	}
	apps := map[string]localpublisher.ComposeApp{}
	for name, service := range project.Config.Services {
		if config.TargetType(service) == "app" {
			apps[name] = localpublisher.ComposeApp{Service: name, Endpoint: filepath.Join("/run/tnl/apps", name, "private", "endpoint.json")}
		}
	}
	if runtimeComposeApps != nil {
		overrides, err := runtimeComposeApps(project)
		if err != nil {
			return localpublisher.ComposeSetup{}, err
		}
		for name, app := range overrides {
			if _, ok := apps[name]; !ok {
				return localpublisher.ComposeSetup{}, errors.New("compose app mapping names a non-app service")
			}
			apps[name] = app
		}
	}
	return localpublisher.ComposeSetup{Placement: publishertarget.Placement{ProjectRoot: project.Root, Worktree: project.Worktree, PrimaryRoot: project.Worktree.PrimaryCheckoutRoot(), OwnerID: container.ID, NetworkID: network}, Project: owner.Project, File: owner.File, Service: owner.Service, Port: 8123, ProjectRoot: owner.ContainerRoot, Apps: apps}, nil
}

func runRuntimeComposeConfigure(ctx context.Context, options runtimeOptions, input io.Reader) error {
	setup, err := localpublisher.DecodeComposeSetup(input)
	if err != nil {
		return err
	}
	directory, err := filepath.EvalSymlinks(options.Directory)
	if err != nil || directory != setup.ProjectRoot {
		return errors.New("compose metadata does not match the owner project root")
	}
	if err := setup.Validate(ctx, publishertarget.Socket{}); err != nil {
		return err
	}
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return err
	}
	return localpublisher.WriteComposeSetup(root, setup)
}

type runtimeComposePlacement struct {
	Setup    localpublisher.ComposeSetup
	Resolver publishertarget.Resolver
	Boundary localpublisher.ComposeBoundary
}

// runtimePrepareComposePlacement is called before metadata generation, manager
// startup, or listener selection in runtime serve --compose. host setup arrives
// through compose exec and is validated before it affects owner identity.
func runtimePrepareComposePlacement(ctx context.Context, project projectConfiguration, root string) (projectConfiguration, *runtimeComposePlacement, error) {
	var setup localpublisher.ComposeSetup
	docker := publishertarget.Socket{}
	for {
		var err error
		setup, err = localpublisher.ReadComposeSetup(root)
		if err == nil {
			err = setup.Validate(ctx, docker)
			if err == nil {
				break
			}
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, localpublisher.ErrComposePlacementStale) {
			return project, nil, err
		}
		select {
		case <-ctx.Done():
			return project, nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	p := project.Config.Publisher
	if p == nil || p.Type != "compose" {
		return project, nil, errors.New("host compose placement does not match publisher configuration")
	}
	if p.Service != setup.Service || setup.Port != 8123 {
		return project, nil, errors.New("host compose placement does not match publisher configuration")
	}
	for name, service := range project.Config.Services {
		if config.TargetType(service) == "app" && setup.Apps[name].Service == "" {
			return project, nil, errors.New("host compose placement omitted an app service")
		}
	}
	relativeFile, err := filepath.Rel(setup.Placement.ProjectRoot, setup.File)
	if err != nil || relativeFile == ".." || filepath.IsAbs(relativeFile) || relativeFile == "." || len(relativeFile) >= 3 && relativeFile[:3] == ".."+string(filepath.Separator) {
		return project, nil, errors.New("compose file is outside the host project")
	}
	if p.File != nil {
		selected, err := publishertarget.ComposeFile(setup.Placement.ProjectRoot, *p.File)
		if err != nil || selected != setup.File {
			return project, nil, errors.New("host compose file does not match publisher configuration")
		}
	}
	updated, err := setup.Apply(project.Project)
	if err != nil {
		return project, nil, err
	}
	project.Project = updated
	placement := &runtimeComposePlacement{Setup: setup, Resolver: publishertarget.Resolver{Docker: docker, Placement: &setup.Placement}, Boundary: setup.Boundary(docker, root)}
	runtimeTargetResolver = placement.Resolver
	return project, placement, nil
}

func (p *runtimeComposePlacement) Listen() (net.Listener, *privateprotocol.Capabilities, error) {
	address, err := p.Boundary.ListenAddress()
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, nil, err
	}
	caps, err := privateprotocol.NewCapabilities("http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(p.Setup.Port)))
	if err != nil {
		listener.Close()
		return nil, nil, err
	}
	return listener, caps, nil
}

func (p *runtimeComposePlacement) Handler(caps *privateprotocol.Capabilities, handler http.Handler) http.Handler {
	return p.Boundary.Handler(caps, handler)
}

func (p *runtimeComposePlacement) PublishApps(ctx context.Context, root string, caps *privateprotocol.Capabilities) error {
	return p.Setup.WriteApps(ctx, p.Resolver.DockerCLI(), root, caps)
}

func (p *runtimeComposePlacement) AppTarget(ctx context.Context, project projectconfig.Project, name, reported string) (string, error) {
	app, found := p.Setup.Apps[name]
	if !found {
		return "", privateprotocol.ErrForbidden
	}
	return p.Resolver.ResolveApp(ctx, project, p.Setup.Project, p.Setup.File, app.Service, reported)
}
