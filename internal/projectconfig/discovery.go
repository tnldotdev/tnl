package projectconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var ProjectConfigNames = []string{"tnl.yml", "tnl.yaml", "tnl.json", "tnl.config.ts"}

type Selection struct {
	Path     string
	Explicit bool
}

// SelectProjectConfig applies explicit selection before nearest-file discovery.
func SelectProjectConfig(cwd, flagPath, environmentPath string, disabled bool) (Selection, error) {
	if disabled && flagPath != "" {
		return Selection{}, errors.New("--config and --no-config are mutually exclusive")
	}
	if disabled {
		return Selection{}, nil
	}
	explicit := flagPath
	if explicit == "" {
		explicit = environmentPath
	}
	if explicit != "" {
		path, err := absolutePath(cwd, explicit)
		if err != nil {
			return Selection{}, err
		}
		if strings.EqualFold(filepath.Ext(path), ".ts") && filepath.Base(path) != "tnl.config.ts" {
			return Selection{}, errors.New("TypeScript project configuration must be named tnl.config.ts")
		}
		if info, err := os.Stat(path); err != nil {
			return Selection{}, fmt.Errorf("select config %s: %w", path, err)
		} else if info.IsDir() {
			return Selection{}, fmt.Errorf("select config %s: path is a directory", path)
		}
		return Selection{Path: path, Explicit: true}, nil
	}

	start, err := absolutePath("", cwd)
	if err != nil {
		return Selection{}, err
	}
	root := gitWorktreeRoot(start)
	if root == "" {
		root = start
	}
	for directory := start; ; directory = filepath.Dir(directory) {
		matches := existingConfigFiles(directory)
		if len(matches) > 1 {
			return Selection{}, fmt.Errorf("multiple project configuration files found: %s", strings.Join(matches, ", "))
		}
		if len(matches) == 1 {
			return Selection{Path: matches[0]}, nil
		}
		if samePath(directory, root) {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory || !pathWithin(parent, root) {
			break
		}
	}
	return Selection{}, nil
}

func existingConfigFiles(directory string) []string {
	result := make([]string, 0, len(ProjectConfigNames))
	for _, name := range ProjectConfigNames {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			result = append(result, path)
		}
	}
	slices.Sort(result)
	return result
}

func gitWorktreeRoot(cwd string) string {
	worktree, err := ResolveWorktree(context.Background(), cwd)
	if err != nil || !worktree.IsGit {
		return ""
	}
	return worktree.Root
}

func absolutePath(cwd, path string) (string, error) {
	if path == "" {
		path = "."
	}
	if !filepath.IsAbs(path) && cwd != "" {
		path = filepath.Join(cwd, path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %s: %w", path, err)
	}
	return filepath.Clean(absolute), nil
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
