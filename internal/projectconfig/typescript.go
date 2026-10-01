package projectconfig

import (
	"context"
	_ "embed"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

const (
	loadTimeout       = 10 * time.Second
	maxResultBytes    = config.MaxDocumentBytes
	maxDiagnosticByte = 16 << 10
)

//go:generate node ../../scripts/generate-projectconfig-loader.ts
//go:embed loader.mjs
var loaderSource string

// loadTypeScript evaluates trusted project-local TypeScript configuration. the
// returned object is implicitly configuration version 1 and contains only tnl
// fields.
func loadTypeScript(ctx context.Context, path, cwd string, worktree Worktree) (config.TNL, error) {
	if err := ctx.Err(); err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", err)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return config.TNL{}, errors.New("load TypeScript config: Node.js 22.18 or newer is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: resolve path: %w", err)
	}
	absoluteCWD, err := filepath.Abs(cwd)
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: resolve cwd: %w", err)
	}
	loadCtx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: create result pipe: %w", err)
	}
	defer reader.Close()
	errorReader, errorWriter, err := os.Pipe()
	if err != nil {
		writer.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: create error pipe: %w", err)
	}
	defer errorReader.Close()
	command := exec.CommandContext(loadCtx, node, "--input-type=module", "--eval", loaderSource, absolutePath, absoluteCWD)
	command.Dir = filepath.Dir(absolutePath)
	environment, contextEnvironment := sanitizedEnvironment(os.Environ())
	command.Env = environment
	contextReader, contextWriter, err := os.Pipe()
	if err != nil {
		writer.Close()
		errorWriter.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: create context pipe: %w", err)
	}
	defer contextWriter.Close()
	contextData, err := json.Marshal(loaderContext{CWD: absoluteCWD, Env: contextEnvironment, Worktree: worktree})
	if err != nil {
		writer.Close()
		errorWriter.Close()
		contextReader.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: encode context: %w", err)
	}
	command.ExtraFiles = []*os.File{writer, contextReader, errorWriter}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		writer.Close()
		errorWriter.Close()
		contextReader.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return config.TNL{}, fmt.Errorf("load TypeScript config: %w", contextErr)
		}
		return config.TNL{}, fmt.Errorf("load TypeScript config: start Node.js: %w", err)
	}
	writer.Close()
	errorWriter.Close()
	contextReader.Close()
	if _, err := contextWriter.Write(contextData); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		if contextErr := ctx.Err(); contextErr != nil {
			return config.TNL{}, fmt.Errorf("load TypeScript config: %w", contextErr)
		}
		if loadCtx.Err() != nil {
			return config.TNL{}, errors.New("load TypeScript config: evaluation timed out")
		}
		return config.TNL{}, fmt.Errorf("load TypeScript config: send context: %w", err)
	}
	contextWriter.Close()
	resultChannel := readBoundedPipe(reader, maxResultBytes)
	errorChannel := readBoundedPipe(errorReader, maxDiagnosticByte)
	waitErr := command.Wait()
	result := <-resultChannel
	loaderError := <-errorChannel
	if contextErr := ctx.Err(); contextErr != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", contextErr)
	}
	if loadCtx.Err() != nil {
		return config.TNL{}, errors.New("load TypeScript config: evaluation timed out")
	}
	if waitErr != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %s", loaderErrorMessage(loaderError))
	}
	if result.err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: read result: %w", result.err)
	}
	if result.overflow {
		return config.TNL{}, errors.New("load TypeScript config: result is too large")
	}
	value, err := unmarshalTypeScriptTNL(result.data)
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: invalid result: %w", err)
	}
	if err := config.ValidateTNL(value); err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", err)
	}
	return value, nil
}

type result struct {
	data     []byte
	err      error
	overflow bool
}

func readBoundedPipe(reader io.Reader, limit int) <-chan result {
	channel := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
		overflow := len(data) > limit
		if err == nil && overflow {
			// keep draining so the loader's synchronous write can finish before
			// command.Wait without retaining oversized project-controlled data.
			_, err = io.Copy(io.Discard, reader)
		}
		channel <- result{data: data, err: err, overflow: overflow}
	}()
	return channel
}

type loaderError struct {
	Error string `json:"error"`
}

func loaderErrorMessage(result result) string {
	const fallback = "failed to evaluate tnl.config.ts"
	if result.err != nil || result.overflow {
		return fallback
	}
	var value loaderError
	if err := json.Unmarshal(result.data, &value); err != nil {
		return fallback
	}
	messages := map[string]string{
		"evaluation_failed":      fallback,
		"import_failed":          "failed to import tnl.config.ts",
		"invalid_arguments":      "the TypeScript loader received invalid arguments",
		"invalid_export":         "tnl.config.ts must export a configuration object or factory",
		"missing_default_export": "tnl.config.ts must have a default export",
		"unsupported_node":       "Node.js 22.18 or newer is required to load tnl.config.ts",
	}
	if message, ok := messages[value.Error]; ok {
		return message
	}
	return fallback
}

type loaderContext struct {
	CWD      string            `json:"cwd"`
	Env      map[string]string `json:"env"`
	Worktree Worktree          `json:"worktree"`
}

var typeScriptKeyMappings = map[string]string{
	"allow_ip":        "allowIP",
	"allow_providers": "allowProviders",
	"allow_all_ips":   "allowAllIPs",
	"startup_timeout": "startupTimeout",
	"request_limit":   "requestLimit",
	"public_url":      "publicURL",
}

// TypeScriptKeyMappings returns the static-to-TypeScript property mappings
// used by evaluation and declaration generation.
func TypeScriptKeyMappings() map[string]string {
	result := make(map[string]string, len(typeScriptKeyMappings))
	for staticName, typeScriptName := range typeScriptKeyMappings {
		result[staticName] = typeScriptName
	}
	return result
}

func unmarshalTypeScriptTNL(data []byte) (config.TNL, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return config.TNL{}, err
	}
	if err := normalizeTypeScriptObject(raw, reflect.TypeOf(config.TNL{})); err != nil {
		return config.TNL{}, err
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return config.TNL{}, err
	}
	var result config.TNL
	if err := json.Unmarshal(encoded, &result, json.RejectUnknownMembers(true)); err != nil {
		return config.TNL{}, err
	}
	return result, nil
}

func normalizeTypeScriptObject(object map[string]any, objectType reflect.Type) error {
	fields := make(map[string]reflect.StructField, objectType.NumField())
	for index := 0; index < objectType.NumField(); index++ {
		field := objectType.Field(index)
		staticName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if staticName == "" || staticName == "-" {
			continue
		}
		typeScriptName := typeScriptKeyMappings[staticName]
		if typeScriptName == "" {
			typeScriptName = staticName
		}
		fields[typeScriptName] = field
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("unknown TypeScript configuration field %q", name)
		}
	}
	for _, typeScriptName := range names {
		field := fields[typeScriptName]
		value := object[typeScriptName]
		staticName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if typeScriptName != staticName {
			delete(object, typeScriptName)
			object[staticName] = value
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			if child, ok := value.(map[string]any); ok {
				if err := normalizeTypeScriptObject(child, fieldType); err != nil {
					return err
				}
			}
		} else if fieldType.Kind() == reflect.Map {
			elementType := fieldType.Elem()
			if elementType.Kind() == reflect.Pointer {
				elementType = elementType.Elem()
			}
			if elementType.Kind() == reflect.Struct {
				if children, ok := value.(map[string]any); ok {
					childNames := make([]string, 0, len(children))
					for childName := range children {
						childNames = append(childNames, childName)
					}
					slices.Sort(childNames)
					for _, childName := range childNames {
						childValue := children[childName]
						if child, ok := childValue.(map[string]any); ok {
							if err := normalizeTypeScriptObject(child, elementType); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func sanitizedEnvironment(environment []string) ([]string, map[string]string) {
	result := make([]string, 0, len(environment))
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "TNL_") || strings.HasPrefix(name, "TNLD_") {
			continue
		}
		result = append(result, entry)
		values[name] = value
	}
	return result, values
}
