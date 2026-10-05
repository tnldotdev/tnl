// Package checkoutmarker records bounded, project-relative Git identifiers without saving source bytes.
package checkoutmarker

import (
	"context"
	"crypto/sha256"
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

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maximumFiles       = 64
	maximumFileBytes   = 1 << 20
	maximumStatusBytes = 1 << 20
)

type changedFile struct {
	Path          string  `json:"path"`
	Status        string  `json:"status"`
	ContentSHA256 *string `json:"content_sha256,omitempty"`
}

type checkoutState struct {
	SchemaVersion int           `json:"schema_version"`
	HeadCommit    string        `json:"head_commit"`
	Branch        string        `json:"branch"`
	ChangedFiles  []changedFile `json:"changed_files"`
	Fingerprint   string        `json:"fingerprint"`
	Complete      bool          `json:"complete"`
}

// Capture records the current project checkout's Git state. a partial marker
// makes a later comparison inconclusive rather than claiming an exact match.
func Capture(ctx context.Context, root string) (controlv1.CheckoutMarker, error) {
	if !filepath.IsAbs(root) {
		return controlv1.CheckoutMarker{}, errors.New("checkout marker requires an absolute project directory")
	}
	state := checkoutState{SchemaVersion: 1, ChangedFiles: []changedFile{}, Complete: true}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return controlv1.CheckoutMarker{}, fmt.Errorf("resolve project directory for checkout marker: %w", err)
	}
	head, err := gitOutput(ctx, root, "rev-parse", "--verify", "HEAD")
	if err != nil {
		state.Complete = false
	} else {
		state.HeadCommit = strings.TrimSpace(string(head))
		if len(state.HeadCommit) != 40 && len(state.HeadCommit) != 64 {
			state.HeadCommit, state.Complete = "", false
		}
	}
	branch, err := gitOutput(ctx, root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil {
		state.Branch = strings.TrimSpace(string(branch))
		if len(state.Branch) > 128 {
			state.Branch, state.Complete = state.Branch[:128], false
		}
	}
	status, err := gitOutput(ctx, root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".")
	if err != nil || len(status) > maximumStatusBytes {
		state.Complete = false
		status = nil
	}
	fingerprint := sha256.New()
	_, _ = fingerprint.Write([]byte(state.HeadCommit + "\x00" + state.Branch + "\x00"))
	_, _ = fingerprint.Write(status)
	for index := 0; index < len(status); {
		end := index
		for end < len(status) && status[end] != 0 {
			end++
		}
		if end == len(status) || end-index < 4 || status[index+2] != ' ' {
			state.Complete = false
			break
		}
		flags := string(status[index : index+2])
		path := string(status[index+3 : end])
		index = end + 1
		name := "modified"
		switch {
		case flags == "??":
			name = "untracked"
		case strings.Contains(flags, "D"):
			name = "deleted"
		case strings.Contains(flags, "R"):
			name = "renamed"
			if next := slices.Index(status[index:], byte(0)); next >= 0 {
				index += next + 1
			} else {
				state.Complete = false
			}
		case strings.Contains(flags, "A"):
			name = "added"
		}
		if len(state.ChangedFiles) == maximumFiles {
			state.Complete = false
			continue
		}
		if path == "" || len(path) > 512 || filepath.IsAbs(path) || !filepath.IsLocal(path) || strings.Contains(path, "\\") {
			state.Complete = false
			continue
		}
		file := changedFile{Path: filepath.ToSlash(path), Status: name}
		if name != "deleted" {
			fullPath := filepath.Join(root, path)
			resolved, pathErr := filepath.EvalSymlinks(fullPath)
			relative, relErr := filepath.Rel(resolvedRoot, resolved)
			info, statErr := os.Lstat(fullPath)
			if pathErr != nil || relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
				statErr != nil || !info.Mode().IsRegular() || info.Size() > maximumFileBytes {
				state.Complete = false
			} else if digest, hashErr := hashFile(fullPath); hashErr != nil {
				state.Complete = false
			} else {
				value := "sha256:" + digest
				file.ContentSHA256 = &value
				_, _ = fingerprint.Write([]byte(digest))
			}
		}
		state.ChangedFiles = append(state.ChangedFiles, file)
	}
	state.Fingerprint = "sha256:" + hex.EncodeToString(fingerprint.Sum(nil))
	encoded, err := json.Marshal(state)
	if err != nil {
		return controlv1.CheckoutMarker{}, fmt.Errorf("encode checkout marker: %w", err)
	}
	var result controlv1.CheckoutMarker
	if err := json.Unmarshal(encoded, &result); err != nil {
		return controlv1.CheckoutMarker{}, fmt.Errorf("decode checkout marker: %w", err)
	}
	return result, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	count, err := io.Copy(hasher, io.LimitReader(file, maximumFileBytes+1))
	if err != nil {
		return "", err
	}
	if count > maximumFileBytes {
		return "", errors.New("changed file exceeds checkout marker bound")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func gitOutput(ctx context.Context, root string, arguments ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, "git", arguments...)
	command.Dir = root
	return command.Output()
}
