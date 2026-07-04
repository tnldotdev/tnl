package main

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func ensureProjectTypeIncludes(project projectConfiguration) ([]string, []string, error) {
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
	var updatedPaths []string
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
			return nil, nil, fmt.Errorf("resolve generated declaration path for service %q: %w", name, err)
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s when creating it.", relative, path))
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		data, err := readInitFile(path)
		if err != nil {
			return nil, nil, err
		}
		var validated any
		if jsonv2.Unmarshal(data, &validated) != nil {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(data, &document) != nil {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		var include []string
		raw, found := document["include"]
		if !found || json.Unmarshal(raw, &include) != nil {
			actions = append(actions, fmt.Sprintf("Add %q to the include array in %s.", relative, path))
			continue
		}
		if slices.Contains(include, relative) {
			continue
		}
		include = append(include, relative)
		document["include"], err = json.Marshal(include)
		if err != nil {
			return nil, nil, err
		}
		updated, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("encode %s: %w", path, err)
		}
		updated = append(updated, '\n')
		if err := replaceRecognizedInitFile(path, data, updated); err != nil {
			return nil, nil, err
		}
		updatedPaths = append(updatedPaths, path)
	}
	return actions, updatedPaths, nil
}
