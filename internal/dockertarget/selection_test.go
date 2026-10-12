package dockertarget

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestComposeSelectionUsesTheRenderedWorktreeFileAndInspectedContainer(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(file, []byte("services:\n  db:\n    image: postgres:17\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commands := t.TempDir()
	log := filepath.Join(commands, "requests")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_ARGS"
case " $* " in
  *" config --format json "*) printf '{"services":{"db":{"ports":[{"target":5432,"protocol":"tcp"}]}}}\n' ;;
  *" ps -q db "*) printf 'aaaaaaaaaaaa\n' ;;
  " inspect aaaaaaaaaaaa ") printf '%s\n' "$DOCKER_INSPECT" ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(commands, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_ARGS", log)
	port := 5432
	for _, label := range []string{"shop-first-k7n2p9", "shop-second-m4q8s2"} {
		selection := config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: label, Service: "db"}, ContainerPort: &port}
		inspect := fmt.Sprintf(`[{"Name":"/%s-db-1","State":{"Running":true},"Config":{"Labels":{"com.docker.compose.project":%q,"com.docker.compose.service":"db","com.docker.compose.project.config_files":%q,"com.docker.compose.project.working_dir":%q}},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"49153"}]},"Networks":{%q:{}}}}]`, label, label, file, root, label+"_default")
		t.Setenv("DOCKER_INSPECT", inspect)
		container, err := SelectContainer(t.Context(), root, label, selection)
		if err != nil {
			t.Fatal(err)
		}
		address, err := HostPort(container, port, false)
		if err != nil || address != "127.0.0.1:49153" || container.Name != label+"-db-1" {
			t.Fatalf("%s selected %+v, %s, %v", label, container, address, err)
		}
		if _, err := SelectContainer(t.Context(), root, "another-worktree", selection); err == nil {
			t.Fatal("accepted another worktree's Compose project")
		}
	}
	contents, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(contents), "--file "+file+" --project-name shop-first-k7n2p9 config --format json") ||
		!strings.Contains(string(contents), "--project-name shop-second-m4q8s2 ps -q db") {
		t.Fatalf("Docker selected unexpected config or worktree: %s, %v", contents, err)
	}
}

func TestComposeSelectionRejectsFixedNamesMissingBindingsAndForeignFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(file, []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	port := 3781
	selection := config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "publisher"}, ContainerPort: &port}
	outside := filepath.Join(t.TempDir(), "compose.yaml")
	if err := os.WriteFile(outside, []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, file); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectContainer(t.Context(), root, "shop-k7n2p9", selection); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("followed Compose symlink outside project: %v", err)
	}
	if _, err := HostPort(Container{Bindings: map[string][]HostBinding{"3781/tcp": {{HostIP: "0.0.0.0", HostPort: "49153"}}}}, port, true); err == nil {
		t.Fatal("accepted public plaintext publisher API binding")
	}
	if _, err := HostPort(Container{}, port, false); err == nil {
		t.Fatal("accepted a missing private host binding")
	}
}

func TestPlainDockerSelectionNeedsAnExactWorktreeLabel(t *testing.T) {
	root := t.TempDir()
	commands := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = ps ]; then printf 'aaaaaaaaaaaa\n'; else printf '%s\n' "$DOCKER_INSPECT"; fi
`
	if err := os.WriteFile(filepath.Join(commands, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
	port := 5432
	name := "shop-db"
	selection := config.DockerSelection{Container: &name, ContainerPort: &port}
	inspect := `[{"Name":"/shop-db","State":{"Running":true},"Config":{"Labels":{"tnl.worktree":"another-worktree"}},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"49153"}]},"Networks":{}}}]`
	t.Setenv("DOCKER_INSPECT", inspect)
	if _, err := SelectContainer(t.Context(), root, "shop-k7n2p9", selection); err == nil {
		t.Fatal("selected a container belonging to another worktree")
	}
	inspect = strings.ReplaceAll(inspect, "another-worktree", "shop-k7n2p9")
	t.Setenv("DOCKER_INSPECT", inspect)
	container, err := SelectContainer(t.Context(), root, "shop-k7n2p9", selection)
	if err != nil || container.Name != name {
		t.Fatalf("selected explicit Docker container: %+v, %v", container, err)
	}
	selection = config.DockerSelection{Labels: map[string]string{"tnl.service": "orders"}, ContainerPort: &port}
	inspect = strings.ReplaceAll(inspect, `"tnl.worktree":"shop-k7n2p9"`, `"tnl.worktree":"shop-k7n2p9","tnl.service":"orders"`)
	t.Setenv("DOCKER_INSPECT", inspect)
	if _, err := SelectContainer(t.Context(), root, "shop-k7n2p9", selection); err != nil {
		t.Fatalf("selected one exact labeled container: %v", err)
	}
}

func TestComposeSelectionRejectsAFixedContainerNameBeforeStarting(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte("services:\n  db:\n    container_name: fixed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commands := t.TempDir()
	if err := os.WriteFile(filepath.Join(commands, "docker"), []byte("#!/bin/sh\nprintf '{\"services\":{\"db\":{\"container_name\":\"fixed\"}}}\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
	port := 5432
	selection := config.DockerSelection{Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "db"}, ContainerPort: &port}
	if _, err := SelectContainer(t.Context(), root, "shop-k7n2p9", selection); err == nil || !strings.Contains(err.Error(), "fixed container_name") {
		t.Fatalf("fixed Compose name accepted: %v", err)
	}
}
