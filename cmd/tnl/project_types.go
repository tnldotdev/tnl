package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func projectTypeIncludeActions(project projectConfiguration) ([]string, error) {
	directories := project.directories
	if len(directories) == 0 {
		directories = map[string]string{"": project.root}
	}
	names := make([]string, 0, len(directories))
	for name := range directories {
		names = append(names, name)
	}
	slices.Sort(names)
	seen := make(map[string]struct{}, len(names))
	var actions []string
	for _, name := range names {
		directory := directories[name]
		if _, found := seen[directory]; found {
			continue
		}
		seen[directory] = struct{}{}
		path := filepath.Join(directory, "tsconfig.json")
		declarations := filepath.Join(project.root, ".tnl", "project.d.ts")
		relative, err := filepath.Rel(directory, declarations)
		if err != nil {
			return nil, fmt.Errorf("resolve generated declaration path for service %q: %w", name, err)
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s when creating it.", relative, path))
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		data, err := readInitFile(path)
		if err != nil {
			return nil, err
		}
		var document struct {
			Include []string `json:"include"`
		}
		if jsonv2.Unmarshal(data, &document) != nil || document.Include == nil {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		if slices.Contains(document.Include, relative) {
			continue
		}
		actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
	}
	return actions, nil
}
