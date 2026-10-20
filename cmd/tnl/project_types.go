package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func projectTypeIncludeActions(project projectConfiguration) ([]string, error) {
	return projectTypeIncludeActionsAt(project.Root, filepath.Join(project.Root, "tsconfig.json"), map[string]bool{})
}

// keep JSONC, references, and custom compiler options byte-identical. report an
// exact project-relative include for each referenced compilation that needs it.
func projectTypeIncludeActionsAt(root, path string, visited map[string]bool) ([]string, error) {
	if visited[path] || len(visited) >= 32 {
		return nil, nil
	}
	visited[path] = true
	relative, err := filepath.Rel(filepath.Dir(path), filepath.Join(root, projectmeta.GeneratedDirectoryName, projectmeta.DeclarationsName))
	if err != nil {
		return nil, err
	}
	relative = filepath.ToSlash(relative)
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
		Include    []string `json:"include"`
		Files      []string `json:"files"`
		References []struct {
			Path string `json:"path"`
		} `json:"references"`
	}
	if jsonv2.Unmarshal(stripJSONC(data), &document) != nil {
		return []string{action}, nil
	}
	if len(document.References) != 0 {
		var actions []string
		for _, reference := range document.References {
			selected := filepath.Clean(filepath.Join(filepath.Dir(path), reference.Path))
			within, err := filepath.Rel(root, selected)
			if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
				actions = append(actions, action)
				continue
			}
			if !strings.HasSuffix(selected, ".json") {
				selected = filepath.Join(selected, "tsconfig.json")
			}
			additional, err := projectTypeIncludeActionsAt(root, selected, visited)
			if err != nil {
				return nil, err
			}
			actions = append(actions, additional...)
		}
		if len(document.Include) == 0 && len(document.Files) == 0 {
			return actions, nil
		}
		if !slices.Contains(document.Include, relative) && !slices.Contains(document.Files, relative) {
			actions = append(actions, action)
		}
		return actions, nil
	}
	if slices.Contains(document.Include, relative) || slices.Contains(document.Files, relative) {
		return nil, nil
	}
	return []string{action}, nil
}

func stripJSONC(source []byte) []byte {
	data := append([]byte(nil), source...)
	quoted, escaped := false, false
	for index := 0; index < len(data); index++ {
		if quoted {
			if escaped {
				escaped = false
			} else if data[index] == '\\' {
				escaped = true
			} else if data[index] == '"' {
				quoted = false
			}
			continue
		}
		if data[index] == '"' {
			quoted = true
			continue
		}
		if data[index] != '/' || index+1 >= len(data) {
			continue
		}
		if data[index+1] == '/' {
			for index < len(data) && data[index] != '\n' {
				data[index] = ' '
				index++
			}
		} else if data[index+1] == '*' {
			data[index], data[index+1] = ' ', ' '
			index += 2
			for index+1 < len(data) && !(data[index] == '*' && data[index+1] == '/') {
				data[index] = ' '
				index++
			}
			if index+1 >= len(data) {
				return source
			}
			data[index], data[index+1] = ' ', ' '
			index++
		}
	}
	quoted, escaped = false, false
	for index, character := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == '"' {
				quoted = false
			}
			continue
		}
		if character == '"' {
			quoted = true
			continue
		}
		if character != ',' {
			continue
		}
		next := index + 1
		for next < len(data) && strings.ContainsRune(" \t\r\n", rune(data[next])) {
			next++
		}
		if next < len(data) && (data[next] == ']' || data[next] == '}') {
			data[index] = ' '
		}
	}
	return data
}
