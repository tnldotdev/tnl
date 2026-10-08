package projectconfig

import (
	"bytes"
	"context"
	_ "embed"
	stdjson "encoding/json"
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

	"github.com/evanw/esbuild/pkg/api"
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
	bundledPath, cleanup, err := bundleTypeScript(loadCtx, absolutePath)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return config.TNL{}, fmt.Errorf("load TypeScript config: %w", contextErr)
		}
		if loadCtx.Err() != nil {
			return config.TNL{}, errors.New("load TypeScript config: evaluation timed out")
		}
		return config.TNL{}, err
	}
	defer cleanup()
	command := exec.CommandContext(loadCtx, node, "--input-type=module", "--eval", loaderSource, bundledPath, absoluteCWD)
	command.Dir = filepath.Dir(absolutePath)
	environment, contextEnvironment := sanitizedEnvironment(os.Environ())
	command.Env = environment
	contextData, err := json.Marshal(loaderContext{CWD: absoluteCWD, Env: contextEnvironment, Worktree: worktree})
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: encode context: %w", err)
	}
	command.Stdin = bytes.NewReader(contextData)
	output := &boundedOutput{limit: maxResultBytes + 1}
	command.Stdout = output
	command.Stderr = io.Discard
	waitErr := command.Run()
	if contextErr := ctx.Err(); contextErr != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", contextErr)
	}
	if loadCtx.Err() != nil {
		return config.TNL{}, errors.New("load TypeScript config: evaluation timed out")
	}
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); !ok {
			return config.TNL{}, fmt.Errorf("load TypeScript config: start Node.js: %w", waitErr)
		}
		return config.TNL{}, fmt.Errorf("load TypeScript config: %s", loaderErrorMessage(output))
	}
	if output.overflow {
		return config.TNL{}, errors.New("load TypeScript config: result is too large")
	}
	data := output.Bytes()
	if len(data) == 0 || data[0] != 'R' || !stdjson.Valid(data[1:]) {
		return config.TNL{}, errors.New("load TypeScript config: invalid result from loader")
	}
	value, err := unmarshalTypeScriptTNL(data[1:])
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: invalid result: %w", err)
	}
	if err := config.ValidateTNL(value); err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", err)
	}
	return value, nil
}

func bundleTypeScript(ctx context.Context, path string) (string, func(), error) {
	directory := filepath.Dir(path)
	buildContext, contextErr := api.Context(api.BuildOptions{
		EntryPoints: []string{path},
		Outfile:     filepath.Join(directory, ".tnl-config.mjs"),
		Bundle:      true,
		Platform:    api.PlatformNode,
		Format:      api.FormatESModule,
		LogLevel:    api.LogLevelSilent,
		Write:       false,
		Plugins: []api.Plugin{{
			Name: "external-project-packages",
			Setup: func(build api.PluginBuild) {
				build.OnResolve(api.OnResolveOptions{Filter: `^[^./]`}, func(args api.OnResolveArgs) (api.OnResolveResult, error) {
					if args.PluginData == true {
						return api.OnResolveResult{}, nil
					}
					options := api.ResolveOptions{ResolveDir: args.ResolveDir, Kind: args.Kind, PluginData: true}
					resolved := build.Resolve(args.Path, options)
					if resolved.Path == "" || resolved.External || !strings.Contains(filepath.ToSlash(resolved.Path), "/node_modules/") {
						return api.OnResolveResult{}, nil
					}
					// a dependency reachable from the bundle's directory can stay a
					// package import; imports private to a nested package are bundled.
					options.ResolveDir = directory
					fromConfig := build.Resolve(args.Path, options)
					if fromConfig.Path == resolved.Path {
						return api.OnResolveResult{Path: args.Path, External: true}, nil
					}
					return api.OnResolveResult{}, nil
				})
			},
		}},
	})
	if contextErr != nil {
		return "", nil, errors.New("load TypeScript config: failed to import tnl.config.ts")
	}
	defer buildContext.Dispose()
	built := make(chan api.BuildResult, 1)
	go func() { built <- buildContext.Rebuild() }()
	var build api.BuildResult
	select {
	case build = <-built:
	case <-ctx.Done():
		buildContext.Cancel()
		<-built
		return "", nil, context.Cause(ctx)
	}
	if err := ctx.Err(); err != nil {
		return "", nil, context.Cause(ctx)
	}
	if len(build.Errors) != 0 || len(build.OutputFiles) != 1 {
		return "", nil, errors.New("load TypeScript config: failed to import tnl.config.ts")
	}
	file, err := os.CreateTemp(directory, ".tnl-config-*.mjs")
	if err != nil {
		return "", nil, fmt.Errorf("load TypeScript config: create temporary config: %w", err)
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if _, err := file.Write(build.OutputFiles[0].Contents); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("load TypeScript config: write temporary config: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("load TypeScript config: close temporary config: %w", err)
	}
	return file.Name(), cleanup, nil
}

type boundedOutput struct {
	data     bytes.Buffer
	limit    int
	overflow bool
}

func (o *boundedOutput) Write(data []byte) (int, error) {
	size := len(data)
	remaining := o.limit - o.data.Len()
	if remaining > 0 {
		_, _ = o.data.Write(data[:min(size, remaining)])
	}
	if size > remaining {
		// the writer must keep accepting bytes so the subprocess cannot block.
		o.overflow = true
	}
	return size, nil
}

func (o *boundedOutput) Bytes() []byte { return o.data.Bytes() }

type loaderError struct {
	Error string `json:"error"`
}

func loaderErrorMessage(output *boundedOutput) string {
	const fallback = "failed to evaluate tnl.config.ts"
	if output.overflow {
		return fallback
	}
	data := output.Bytes()
	if len(data) < 2 || data[0] != 'E' || len(data)-1 > maxDiagnosticByte {
		return fallback
	}
	var value loaderError
	if err := json.Unmarshal(data[1:], &value); err != nil {
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
	"allow_ip":           "allowIP",
	"allow_from":         "allowFrom",
	"allow_all_ips":      "allowAllIPs",
	"startup_timeout":    "startupTimeout",
	"request_limit":      "requestLimit",
	"request_inspection": "requestInspection",
	"strip_prefix":       "stripPrefix",
	"public_url":         "publicURL",
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
