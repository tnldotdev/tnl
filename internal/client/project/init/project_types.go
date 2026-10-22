package init

import (
	"bytes"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tailscale/hujson"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

type projectTypeIncludeResult struct {
	actions []string
	updated []string
}

type projectTSConfig struct {
	Include    []string `json:"include"`
	Files      []string `json:"files"`
	References []struct {
		Path string `json:"path"`
	} `json:"references"`
}

func wireProjectTypeIncludes(root string) (projectTypeIncludeResult, error) {
	return projectTypeIncludesAt(root, filepath.Join(root, "tsconfig.json"), map[string]bool{})
}

// use the jsonc syntax tree for edits; preserve every existing comment and byte.
// solution-only roots keep their references and defer includes to their leaves.
func projectTypeIncludesAt(root, path string, visited map[string]bool) (projectTypeIncludeResult, error) {
	var result projectTypeIncludeResult
	if visited[path] {
		return result, nil
	}
	relative, err := filepath.Rel(filepath.Dir(path), filepath.Join(root, meta.GeneratedDirectoryName, meta.DeclarationsName))
	if err != nil {
		return result, err
	}
	relative = filepath.ToSlash(relative)
	action := fmt.Sprintf("add %q to the include array in %s.", relative, path)
	manual := func() (projectTypeIncludeResult, error) {
		result.actions = append(result.actions, action)
		return result, nil
	}
	if len(visited) >= 32 || !safeProjectTypeParents(root, path) {
		return manual()
	}
	visited[path] = true
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		result.actions = append(result.actions, fmt.Sprintf("add %q to the include array in %s when creating it.", relative, path))
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return manual()
	}
	data, err := readInitFile(path)
	if err != nil {
		return result, err
	}
	ast, err := hujson.Parse(data)
	if err != nil || ast.Value.Kind() != '{' {
		return manual()
	}
	standard := ast.Clone()
	standard.Standardize()
	var document projectTSConfig
	if json.Unmarshal(standard.Pack(), &document) != nil {
		return manual()
	}
	for _, field := range []string{"include", "files", "references"} {
		if node := ast.Find("/" + field); node != nil && node.Value.Kind() != '[' {
			return manual()
		}
	}
	for _, reference := range document.References {
		selected := filepath.Clean(filepath.Join(filepath.Dir(path), reference.Path))
		within, err := filepath.Rel(root, selected)
		if reference.Path == "" || err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
			result.actions = append(result.actions, action)
			continue
		}
		if !strings.HasSuffix(selected, ".json") {
			selected = filepath.Join(selected, "tsconfig.json")
		}
		additional, err := projectTypeIncludesAt(root, selected, visited)
		if err != nil {
			return result, err
		}
		result.actions = append(result.actions, additional.actions...)
		result.updated = append(result.updated, additional.updated...)
	}
	if len(document.References) != 0 && document.Files != nil && len(document.Files) == 0 && document.Include == nil {
		return result, nil
	}
	if slices.Contains(document.Include, relative) || slices.Contains(document.Files, relative) {
		return result, nil
	}
	var replacement []byte
	if include := ast.Find("/include"); include != nil {
		replacement = appendJSONCValue(data, include, hujson.String(relative))
	} else if files := ast.Find("/files"); files != nil {
		replacement = appendJSONCValue(data, files, hujson.String(relative))
	} else {
		// an inherited include cannot be narrowed safely. with no inheritance,
		// retain typescript's default source glob when adding the explicit file.
		if ast.Find("/extends") != nil {
			action = fmt.Sprintf("retain the inherited source include patterns in %s and append %q to an explicit include array.", path, relative)
			return manual()
		}
		includes, err := json.Marshal([]string{"**/*", relative})
		if err != nil {
			return result, err
		}
		replacement = appendJSONCValue(data, &ast, append([]byte(`"include": `), includes...))
	}
	checked, err := hujson.Parse(replacement)
	if err != nil {
		return result, fmt.Errorf("wire project declarations: %w", err)
	}
	checked = checked.Clone()
	checked.Standardize()
	var updated projectTSConfig
	if err := json.Unmarshal(checked.Pack(), &updated); err != nil {
		return result, err
	}
	if !slices.Contains(updated.Include, relative) && !slices.Contains(updated.Files, relative) {
		return result, fmt.Errorf("project declarations were not included")
	}
	if err := replaceRecognizedInitFile(path, data, replacement); err != nil {
		return result, err
	}
	result.updated = append(result.updated, path)
	return result, nil
}

func safeProjectTypeParents(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	parent := root
	parts := strings.Split(relative, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// offsets and trailing commas come from the parsed syntax tree.
// insert new syntax around existing trivia without reformatting unrelated nodes.
func appendJSONCValue(source []byte, container *hujson.Value, fragment []byte) []byte {
	var first, last *hujson.Value
	switch value := container.Value.(type) {
	case *hujson.Array:
		if len(value.Elements) != 0 {
			first, last = &value.Elements[0], &value.Elements[len(value.Elements)-1]
		}
	case *hujson.Object:
		if len(value.Members) != 0 {
			first, last = &value.Members[0].Name, &value.Members[len(value.Members)-1].Value
		}
	}
	close := container.EndOffset - 1
	var insertion []byte
	if bytes.IndexByte(source[container.StartOffset:close], '\n') >= 0 {
		newline := "\n"
		if bytes.Contains(source, []byte("\r\n")) {
			newline = "\r\n"
		}
		closingIndent := jsoncIndent(source, close)
		childIndent := closingIndent + "  "
		if first != nil {
			if indent := jsoncIndent(source, first.StartOffset); strings.HasPrefix(indent, closingIndent) && len(indent) > len(closingIndent) {
				childIndent = indent
			}
		}
		insertion = append(insertion, strings.TrimPrefix(childIndent, closingIndent)...)
		insertion = append(insertion, fragment...)
		if last != nil && last.AfterExtra != nil {
			insertion = append(insertion, ',')
		}
		insertion = append(insertion, newline...)
		insertion = append(insertion, closingIndent...)
	} else {
		if close > container.StartOffset+1 && !strings.ContainsRune(" \t\r\n", rune(source[close-1])) {
			insertion = append(insertion, ' ')
		}
		insertion = append(insertion, fragment...)
		if last != nil && last.AfterExtra != nil {
			insertion = append(insertion, ',')
		}
	}
	result := make([]byte, 0, len(source)+len(insertion)+1)
	if last != nil && last.AfterExtra == nil {
		result = append(result, source[:last.EndOffset]...)
		result = append(result, ',')
		result = append(result, source[last.EndOffset:close]...)
	} else {
		result = append(result, source[:close]...)
	}
	result = append(result, insertion...)
	return append(result, source[close:]...)
}

func jsoncIndent(source []byte, offset int) string {
	line := source[bytes.LastIndexByte(source[:offset], '\n')+1 : offset]
	if len(bytes.TrimSpace(line)) != 0 {
		return ""
	}
	return string(line)
}
