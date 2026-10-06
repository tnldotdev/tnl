// package sourcestate records bounded Git identifiers without saving source files.
package sourcestate

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maximumFiles       = 64
	maximumFileBytes   = 1 << 20
	maximumOutputBytes = 1 << 20
	maximumStateBytes  = 16384
	captureTimeout     = 5 * time.Second
)

type headFile struct {
	blobID string
	mode   string
}

// Capture reads HEAD and Git-visible changes beneath the project directory.
// file IDs are reproducible with git hash-object --no-filters -- path/to/file.
// branch and staging are context only; incomplete captures cannot prove a match.
func Capture(ctx context.Context, projectRoot string) (controlv1.SourceState, error) {
	state := controlv1.SourceState{SchemaVersion: 1, ChangedFiles: []controlv1.SourceFileState{}}
	if !filepath.IsAbs(projectRoot) {
		return state, errors.New("source state requires an absolute project directory")
	}
	root, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		return state, fmt.Errorf("resolve project directory for source state: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, captureTimeout)
	defer cancel()
	repository, err := gitOutput(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		return state, nil
	}
	repositoryRoot, err := filepath.EvalSymlinks(strings.TrimSpace(string(repository)))
	if err != nil {
		return state, nil
	}
	projectPath, err := filepath.Rel(repositoryRoot, root)
	if err != nil || !filepath.IsLocal(projectPath) {
		return state, nil
	}
	if projectPath != "." {
		state.ProjectPath = filepath.ToSlash(projectPath)
		if !validPath(state.ProjectPath) {
			state.ProjectPath = ""
			return state, nil
		}
	}
	head, err := gitOutput(ctx, root, "rev-parse", "--verify", "HEAD")
	if err == nil && validObjectID(strings.TrimSpace(string(head))) {
		state.HeadCommit = strings.TrimSpace(string(head))
		state.Complete = true
	}
	branch, err := gitOutput(ctx, root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil {
		name := strings.TrimSpace(string(branch))
		if len(name) <= 128 {
			state.Branch = name
		}
	}
	status, err := gitOutput(ctx, root, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--no-renames", "--ignore-submodules=none", "--", ".")
	if err != nil {
		state.Complete = false
		return state, nil
	}
	files, complete := changedPaths(status, state.ProjectPath)
	state.Complete = state.Complete && complete
	directory, err := os.OpenRoot(root)
	if err != nil {
		return state, fmt.Errorf("open project directory for source state: %w", err)
	}
	defer directory.Close()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		file, changed, complete := captureFile(ctx, root, directory, path, files[path])
		state.Complete = state.Complete && complete
		if changed {
			state.ChangedFiles = append(state.ChangedFiles, file)
		}
	}
	// HEAD may move while files are read; an incomplete result is preferable to
	// attributing that mixed observation to either commit.
	currentHead, err := gitOutput(ctx, root, "rev-parse", "--verify", "HEAD")
	if err != nil || strings.TrimSpace(string(currentHead)) != state.HeadCommit {
		state.Complete = false
	}
	for {
		encoded, err := json.Marshal(state)
		if err != nil {
			return state, fmt.Errorf("encode source state: %w", err)
		}
		if len(encoded) <= maximumStateBytes {
			return state, nil
		}
		state.Complete = false
		state.ChangedFiles = state.ChangedFiles[:len(state.ChangedFiles)-1]
	}
}

// changedPaths retains HEAD information even when a staged deletion also
// appears as an untracked file. index-only changes disappear during capture.
func changedPaths(status []byte, projectPath string) (map[string]headFile, bool) {
	files := make(map[string]headFile)
	complete := len(status) == 0 || status[len(status)-1] == 0
	for _, record := range bytes.Split(status, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		var path string
		var head headFile
		switch record[0] {
		case '1':
			fields := strings.SplitN(string(record), " ", 9)
			if len(fields) != 9 {
				complete = false
				continue
			}
			path = fields[8]
			if fields[3] != "000000" {
				head = headFile{mode: fields[3], blobID: fields[6]}
			}
		case '?':
			if len(record) < 3 || record[1] != ' ' {
				complete = false
				continue
			}
			path = string(record[2:])
		default:
			// unresolved merges and unsupported records cannot prove equivalence.
			complete = false
			continue
		}
		if projectPath != "" {
			var found bool
			path, found = strings.CutPrefix(path, projectPath+"/")
			if !found {
				complete = false
				continue
			}
		}
		if !validPath(path) {
			complete = false
			continue
		}
		previous, exists := files[path]
		if !exists && len(files) == maximumFiles {
			complete = false
			continue
		}
		if !exists || previous.blobID == "" {
			files[path] = head
		}
	}
	return files, complete
}

func captureFile(ctx context.Context, root string, directory *os.Root, path string, head headFile) (controlv1.SourceFileState, bool, bool) {
	file := controlv1.SourceFileState{Path: path, Status: controlv1.Added}
	if head.blobID != "" {
		file.Status = controlv1.Modified
	}
	info, err := directory.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file.Status = controlv1.Deleted
		return file, head.blobID != "", true
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumFileBytes {
		return file, true, false
	}
	input, err := directory.Open(path)
	if err != nil {
		return file, true, false
	}
	contents, readErr := io.ReadAll(io.LimitReader(input, maximumFileBytes+1))
	after, statErr := input.Stat()
	closeErr := input.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(contents) > maximumFileBytes ||
		!os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || info.Mode() != after.Mode() {
		return file, true, false
	}
	// --stdin implies --no-filters; the bounded bytes come from the confined
	// project handle. omit -w so Git does not store an object or modify the index.
	output, err := runGit(ctx, root, contents, "hash-object", "--no-filters", "--stdin")
	blobID := strings.TrimSpace(string(output))
	if err != nil || !validObjectID(blobID) {
		return file, true, false
	}
	mode := "100644"
	if info.Mode().Perm()&0o111 != 0 {
		mode = "100755"
	}
	file.BlobId, file.Mode = &blobID, &mode
	return file, blobID != head.blobID || mode != head.mode, true
}

func validPath(path string) bool {
	return path != "" && path != "." && len(path) <= 512 && utf8.ValidString(path) && filepath.IsLocal(path) && filepath.ToSlash(filepath.Clean(path)) == path && !strings.ContainsAny(path, "\x00\\")
}

func validObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && hex.EncodeToString(decoded) == id
}

func gitOutput(ctx context.Context, root string, arguments ...string) ([]byte, error) {
	return runGit(ctx, root, nil, arguments...)
}

type boundedOutput struct{ bytes.Buffer }

func (output *boundedOutput) Write(value []byte) (int, error) {
	if output.Len()+len(value) > maximumOutputBytes {
		return 0, errors.New("git output exceeds source state bound")
	}
	return output.Buffer.Write(value)
}

func runGit(ctx context.Context, root string, input []byte, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"--no-optional-locks", "-c", "core.fsmonitor=false"}, arguments...)...)
	command.Dir = root
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	var output boundedOutput
	command.Stdout = &output
	command.WaitDelay = time.Second
	err := command.Run()
	return output.Bytes(), err
}
