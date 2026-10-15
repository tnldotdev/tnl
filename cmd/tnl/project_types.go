package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

func projectTypeIncludeActions(project projectConfiguration) ([]string, error) {
	path := filepath.Join(project.Root, "tsconfig.json")
	relative := ".tnl/project.d.ts"
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return []string{fmt.Sprintf("Add %q to the include array in %s when creating it.", relative, path)}, nil
	}
	if err != nil {
		return nil, err
	}
	action := fmt.Sprintf("Add %q to the include array in %s.", relative, path)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return []string{action}, nil
	}
	data, err := readInitFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Include []string `json:"include"`
	}
	if jsonv2.Unmarshal(data, &document) != nil || document.Include == nil {
		return []string{action}, nil
	}
	if slices.Contains(document.Include, relative) {
		return nil, nil
	}
	return []string{action}, nil
}
