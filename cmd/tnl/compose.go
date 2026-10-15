package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
	"go.yaml.in/yaml/v3"
)

type composeCommand struct {
	Prepare composePrepareCommand `cmd:"" help:"Generate isolated Compose publisher mounts for this worktree."`
	Login   composePrepareCommand `cmd:"" help:"Start and sign in the selected Compose publisher."`
	Up      composeUpCommand      `cmd:"" help:"Prepare and start the selected Compose project."`
}

type composePrepareCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
}

type composeUpCommand struct {
	composePrepareCommand `embed:""`
	Detach                bool `name:"detach" help:"Start Compose in the background."`
}

func selectedComposeProject(ctx context.Context, flags cli, stateDir string) (projectconfig.Project, string, error) {
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return projectconfig.Project{}, "", err
	}
	project, err := loadProjectConfiguration(ctx, flags, root)
	if err != nil {
		return projectconfig.Project{}, "", err
	}
	if !project.Found() || project.Config.Publisher == nil || project.Config.Publisher.Type != "compose" {
		return projectconfig.Project{}, "", errors.New("configure publisher: {type: compose, service: NAME} before starting Compose")
	}
	selected := os.Getenv("TNL_SERVER")
	if project.Config.Server != nil {
		selected = *project.Config.Server
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return projectconfig.Project{}, "", err
	}
	server, selectErr := clientserver.Select(ctx, state, selected)
	closeErr := state.Close()
	if selectErr != nil {
		return projectconfig.Project{}, "", selectErr
	}
	if closeErr != nil {
		return projectconfig.Project{}, "", closeErr
	}
	project.Config.Server = &server
	file, err := project.Project.PublisherComposeFile()
	return project.Project, file, err
}

// composeOverride is user-visible generated configuration. each app sees only
// its own descriptor; signing keys and owner state stay in the publisher volume.
func composeOverride(project projectconfig.Project, file string) ([]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var source struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &source); err != nil || len(source.Services) == 0 {
		return nil, errors.New("compose file needs a services mapping")
	}
	owner := project.Config.Publisher.Service
	if _, ok := source.Services[owner]; !ok {
		return nil, fmt.Errorf("compose publisher service %q is missing", owner)
	}
	label := project.Worktree.Label.FullLabel
	if label == "" {
		return nil, errors.New("resolve the worktree label before preparing Compose")
	}
	type serviceOverride struct {
		Labels      map[string]string `yaml:"labels"`
		Networks    []string          `yaml:"networks"`
		Command     []string          `yaml:"command,omitempty"`
		Environment map[string]string `yaml:"environment,omitempty"`
		Volumes     []string          `yaml:"volumes,omitempty"`
	}
	type volume struct{}
	result := struct {
		Services map[string]serviceOverride `yaml:"services"`
		Networks map[string]struct {
			Labels map[string]string `yaml:"labels"`
		} `yaml:"networks"`
		Volumes map[string]volume `yaml:"volumes"`
	}{
		Services: make(map[string]serviceOverride, len(source.Services)),
		Networks: map[string]struct {
			Labels map[string]string `yaml:"labels"`
		}{"tnl-private": {Labels: map[string]string{"tnl.worktree": label}}},
		Volumes: map[string]volume{"tnl-owner-state": {}},
	}
	for name := range source.Services {
		result.Services[name] = serviceOverride{Labels: map[string]string{"tnl.worktree": label}, Networks: []string{"tnl-private"}}
	}
	publisher := result.Services[owner]
	publisher.Command = []string{"tnl", "runtime", "serve", "--directory", "/workspace", "--compose-owner"}
	publisher.Environment = map[string]string{"TNL_STATE_DIR": "/run/tnl/state/owner-state"}
	snapshot, err := composeProjectSnapshot(project)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(snapshot)
	publisher.Environment["TNL_PROJECT_CONFIG_HASH"] = hex.EncodeToString(digest[:])
	if project.Config.Server != nil {
		publisher.Environment["TNL_SERVER"] = *project.Config.Server
	}
	publisher.Volumes = []string{
		project.Root + ":/workspace:ro", "/var/run/docker.sock:/var/run/docker.sock",
		"tnl-owner-state:/run/tnl/state",
	}
	names := make([]string, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service := project.Config.Services[name]
		composeName := name
		if service.Target != nil && service.Target.Type == "compose" && service.Target.Service != nil {
			composeName = *service.Target.Service
		}
		if _, ok := source.Services[composeName]; !ok {
			return nil, fmt.Errorf("configured service %q has no Compose service %q", name, composeName)
		}
		if config.TargetType(service) != "app" {
			continue
		}
		if name != composeName || name == owner {
			return nil, fmt.Errorf("app %q needs its own matching Compose service", name)
		}
		volumeName := "tnl-app-" + name
		result.Volumes[volumeName] = volume{}
		publisher.Volumes = append(publisher.Volumes, volumeName+":/run/tnl/apps/"+name)
		app := result.Services[name]
		app.Volumes = append(app.Volumes, volumeName+":/run/tnl/apps/"+name+":ro")
		app.Environment = map[string]string{"TNL_APP_ENDPOINT": "/run/tnl/apps/" + name + "/private/endpoint.json"}
		result.Services[name] = app
	}
	result.Services[owner] = publisher
	encoded, err := yaml.Marshal(result)
	if err != nil {
		return nil, err
	}
	return append([]byte("# generated by tnl compose prepare; run tnl compose up to use it\n"), encoded...), nil
}

func writeComposeOverride(project projectconfig.Project, file string) (string, error) {
	encoded, err := composeOverride(project, file)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(project.Root, ".tnl")
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("generated Compose directory must be a real directory")
	}
	snapshot, err := composeProjectSnapshot(project)
	if err != nil {
		return "", err
	}
	if err := writeComposeGenerated(filepath.Join(directory, "compose.project.json"), snapshot); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "compose.generated.yaml")
	if err := writeComposeGenerated(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func composeProjectSnapshot(project projectconfig.Project) ([]byte, error) {
	version := config.DocumentVersion
	return json.Marshal(config.Document{Version: &version, TNL: &project.Config})
}

// writeComposeGenerated replaces only files owned by this generator, using an
// atomic, mode-0600 write. a project cannot silently replace an unrelated file.
func writeComposeGenerated(path string, encoded []byte) error {
	if current, err := os.ReadFile(path); err == nil {
		managed := bytes.HasPrefix(current, []byte("# generated by tnl compose prepare;"))
		if filepath.Base(path) == "compose.project.json" {
			var document config.Document
			managed = json.Unmarshal(current, &document) == nil && document.Version != nil && *document.Version == config.DocumentVersion && document.TNL != nil && document.TNL.Publisher != nil && document.TNL.Publisher.Type == "compose"
		}
		if !managed {
			return errors.New("refusing to replace an unmanaged Compose artifact")
		}
		if stat, err := os.Lstat(path); err != nil || !stat.Mode().IsRegular() {
			return errors.New("generated Compose artifact is not a regular file")
		}
		if bytes.Equal(current, encoded) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".compose-generated-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	return nil
}

func runComposePrepare(ctx context.Context, flags cli, out io.Writer) error {
	project, base, err := selectedComposeProject(ctx, flags, flags.Compose.Prepare.StateDir)
	if err != nil {
		return err
	}
	generated, err := writeComposeOverride(project, base)
	if err != nil {
		return err
	}
	return writeHumanFrame(out, "tnl compose prepare", "ready", "run tnl compose up", clioutput.Fields(clioutput.Field{Label: "override", Value: generated}))
}

func runComposeUp(ctx context.Context, flags cli, out, diagnostics io.Writer) error {
	project, base, err := selectedComposeProject(ctx, flags, flags.Compose.Up.StateDir)
	if err != nil {
		return err
	}
	if _, err := writeComposeOverride(project, base); err != nil {
		return err
	}
	args := publishertarget.ComposeArgs(project.Root, base, project.Worktree.Label.FullLabel)
	args = append(args, "up")
	if flags.Compose.Up.Detach {
		args = append(args, "--detach")
	}
	command := exec.CommandContext(ctx, "docker", args...)
	command.Dir, command.Stdin, command.Stdout, command.Stderr = project.Root, os.Stdin, out, diagnostics
	return command.Run()
}

func runComposeLogin(ctx context.Context, flags cli, out, diagnostics io.Writer) error {
	project, base, err := selectedComposeProject(ctx, flags, flags.Compose.Login.StateDir)
	if err != nil {
		return err
	}
	if _, err := writeComposeOverride(project, base); err != nil {
		return err
	}
	args := publishertarget.ComposeArgs(project.Root, base, project.Worktree.Label.FullLabel)
	up := exec.CommandContext(ctx, "docker", append(append([]string{}, args...), "up", "--detach", project.Config.Publisher.Service)...)
	up.Dir, up.Stdout, up.Stderr = project.Root, out, diagnostics
	if err := up.Run(); err != nil {
		return err
	}
	args = append(args, "exec", "--workdir", "/workspace", project.Config.Publisher.Service, "tnl", "auth", "login")
	if project.Config.Server != nil {
		args = append(args, "--server", *project.Config.Server)
	}
	login := exec.CommandContext(ctx, "docker", args...)
	login.Dir, login.Stdin, login.Stdout, login.Stderr = project.Root, os.Stdin, out, diagnostics
	return login.Run()
}
