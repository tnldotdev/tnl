package tnlts

import (
	"bytes"
	"context"
	_ "embed"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

const (
	loadTimeout       = 10 * time.Second
	maxResultBytes    = config.MaxDocumentBytes
	maxDiagnosticByte = 16 << 10
)

//go:embed loader.mjs
var loaderSource string

// Load evaluates trusted project-local TypeScript configuration. The returned
// object is implicitly configuration version 1 and contains only tnl fields.
func Load(ctx context.Context, path, cwd string) (config.TNL, error) {
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
	command := exec.CommandContext(loadCtx, node, "--input-type=module", "--eval", loaderSource, absolutePath, absoluteCWD)
	command.Dir = filepath.Dir(absolutePath)
	environment, contextEnvironment := sanitizedEnvironment(os.Environ())
	command.Env = environment
	contextReader, contextWriter, err := os.Pipe()
	if err != nil {
		writer.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: create context pipe: %w", err)
	}
	defer contextWriter.Close()
	worktree, err := config.ResolveWorktree(loadCtx, absoluteCWD)
	if err != nil {
		writer.Close()
		contextReader.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: resolve worktree: %w", err)
	}
	contextData, err := json.Marshal(loaderContext{CWD: absoluteCWD, Env: contextEnvironment, Worktree: worktree})
	if err != nil {
		writer.Close()
		contextReader.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: encode context: %w", err)
	}
	command.ExtraFiles = []*os.File{writer, contextReader}
	diagnostics := newLimitedBuffer(maxDiagnosticByte)
	command.Stdout = diagnostics
	command.Stderr = diagnostics
	if err := command.Start(); err != nil {
		writer.Close()
		contextReader.Close()
		return config.TNL{}, fmt.Errorf("load TypeScript config: start Node.js: %w", err)
	}
	writer.Close()
	contextReader.Close()
	if _, err := contextWriter.Write(contextData); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return config.TNL{}, fmt.Errorf("load TypeScript config: send context: %w", err)
	}
	contextWriter.Close()
	resultChannel := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(reader, maxResultBytes+1))
		resultChannel <- result{data: data, err: err}
	}()
	waitErr := command.Wait()
	result := <-resultChannel
	if loadCtx.Err() != nil {
		return config.TNL{}, errors.New("load TypeScript config: evaluation timed out")
	}
	if waitErr != nil {
		message := strings.TrimSpace(diagnostics.String())
		if message == "" {
			return config.TNL{}, fmt.Errorf("load TypeScript config: %w", waitErr)
		}
		return config.TNL{}, fmt.Errorf("load TypeScript config: %s", message)
	}
	if result.err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: read result: %w", result.err)
	}
	if len(result.data) > maxResultBytes {
		return config.TNL{}, errors.New("load TypeScript config: result is too large")
	}
	value, err := config.UnmarshalTypeScriptTNL(result.data)
	if err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: invalid result: %w", err)
	}
	if err := config.ValidateTNL(value); err != nil {
		return config.TNL{}, fmt.Errorf("load TypeScript config: %w", err)
	}
	return value, nil
}

type result struct {
	data []byte
	err  error
}

type loaderContext struct {
	CWD      string            `json:"cwd"`
	Env      map[string]string `json:"env"`
	Worktree config.Worktree   `json:"worktree"`
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

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func newLimitedBuffer(limit int) *limitedBuffer { return &limitedBuffer{remaining: limit} }

func (b *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	if len(data) > b.remaining {
		data = data[:b.remaining]
	}
	_, _ = b.Buffer.Write(data)
	b.remaining -= len(data)
	return original, nil
}
