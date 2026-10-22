package projectinit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const LocalIgnoreRule = "/.tnl/local/"

// projectGitignoreActions asks Git to evaluate its own patterns, including
// ancestor, global, and repository-local rules. probe paths need not exist.
func projectGitignoreActions(ctx context.Context, root string) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unverified := []string{"Check Git ignore rules: ignore only /.tnl/local/ at the project root and keep other .tnl files trackable."}
	command := func(arguments ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "git", arguments...)
		cmd.Dir = root
		return cmd
	}
	var prefix []string
	repository, err := command("rev-parse", "--show-toplevel").Output()
	ignoreRoot := strings.TrimSuffix(string(repository), "\n")
	if err != nil {
		// init also works before git init. evaluate the project's rules with
		// temporary Git state without creating a repository in the project.
		directory, err := os.MkdirTemp("", "tnl-init-ignore-*")
		if err != nil {
			return unverified
		}
		defer os.RemoveAll(directory)
		if err := command("init", "--bare", "--quiet", "--template=", directory).Run(); err != nil {
			return unverified
		}
		prefix = []string{"--git-dir=" + directory, "--work-tree=" + root, "-c", "core.bare=false"}
		ignoreRoot = root
	}
	paths := []string{
		".tnl/local/project.json", ".tnl/local/project.lock", ".tnl/local/.project-example",
		".tnl/generated/example.ts", ".tnl/config.json", ".tnl/tnl-ignore-probe",
	}
	cmd := command(append(prefix, "check-ignore", "--no-index", "--verbose", "--non-matching", "-z", "--stdin")...)
	cmd.Stdin = strings.NewReader(strings.Join(paths, "\x00") + "\x00")
	output, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return unverified
	}
	fields := strings.Split(string(output), "\x00")
	if len(fields) != 4*len(paths)+1 {
		return unverified
	}
	var actions []string
	seen := map[string]bool{}
	for i, path := range paths {
		source, line, pattern, checked := fields[4*i], fields[4*i+1], fields[4*i+2], fields[4*i+3]
		if checked != path {
			return unverified
		}
		ignored := pattern != "" && !strings.HasPrefix(pattern, "!")
		local := strings.HasPrefix(path, ".tnl/local/")
		if ignored == local {
			continue
		}
		if source != "" && !filepath.IsAbs(source) {
			source = filepath.Join(ignoreRoot, source)
		}
		location := source + ":" + line
		if seen[location] {
			continue
		}
		seen[location] = true
		if local {
			actions = append(actions, "Review Git ignore rules: .tnl/local files are not ignored. Keep /.tnl/local/ ignored at the project root.")
		} else {
			actions = append(actions, fmt.Sprintf("Review %s: this rule hides .tnl files outside local/. Narrow custom broad rules so .tnl/generated/ and other intentional .tnl files stay trackable.", location))
		}
	}
	return actions
}
