package connectionruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"golang.org/x/sys/unix"
)

// Handle is a private capability, not a PID file. it contains no workload or
// human credential and cannot survive its exact owner process's lifetime.
type Handle struct {
	Schema       int       `json:"schema"`
	URL          string    `json:"url"`
	Key          string    `json:"key"`
	Directory    string    `json:"directory"`
	ConfigDigest string    `json:"config_digest"`
	ExpiresAt    time.Time `json:"expires_at"`
	Executable   string    `json:"executable"`
	Workload     string    `json:"workload,omitempty"`
	TeamID       string    `json:"team_id,omitempty"`
}

func (Handle) String() string   { return "private connection handle" }
func (Handle) GoString() string { return "private connection handle" }

func NewDirectory(parent string) (string, error) {
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil || !filepath.IsAbs(parent) {
		return "", ErrUnauthorized
	}
	if err := safeAncestors(parent); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "tnl-connections-")
}

func safeAncestors(path string) error {
	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrUnauthorized
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func WriteHandle(path string, h Handle) error {
	if VerifyDirectory(filepath.Dir(path)) != nil {
		return ErrUnauthorized
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func VerifyDirectory(path string) error {
	if !filepath.IsAbs(path) || safeAncestors(path) != nil {
		return ErrUnauthorized
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ErrUnauthorized
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0o700 {
		return ErrUnauthorized
	}
	return nil
}

func ReadHandle(path string) (Handle, error) {
	var h Handle
	if !filepath.IsAbs(path) || safeAncestors(filepath.Dir(path)) != nil {
		return h, ErrUnauthorized
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode().Perm() != 0o700 {
		return h, ErrUnauthorized
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return h, ErrUnauthorized
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return h, ErrUnauthorized
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return h, ErrUnauthorized
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > MaxBytes {
		return h, ErrUnauthorized
	}
	if ReadJSON(f, &h) != nil || h.Schema != Schema || len(h.Key) != 64 || !filepath.IsAbs(h.Directory) || len(h.ConfigDigest) != 64 {
		return Handle{}, ErrUnauthorized
	}
	if _, err := hex.DecodeString(h.Key); err != nil {
		return Handle{}, ErrUnauthorized
	}
	u, err := url.Parse(h.URL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Handle{}, ErrUnauthorized
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || h.URL != "http://127.0.0.1:"+strconv.Itoa(port) {
		return Handle{}, ErrUnauthorized
	}
	if !h.ExpiresAt.After(time.Now()) {
		return Handle{}, ErrExpired
	}
	return h, nil
}

func randomKey() (string, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	return hex.EncodeToString(key[:]), err
}

func ReadStopResult(handlePath string) error {
	path := filepath.Join(filepath.Dir(handlePath), "stopped.json")
	if safeAncestors(filepath.Dir(path)) != nil {
		return ErrUnauthorized
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrCleanup
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ErrCleanup
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 1024 {
		return ErrUnauthorized
	}
	var result struct {
		Schema int  `json:"schema"`
		Clean  bool `json:"clean"`
	}
	if ReadJSON(f, &result) != nil || result.Schema != 1 || !result.Clean {
		return ErrCleanup
	}
	return nil
}

// Call uses the exact private handle and capability. stop never inspects or
// signals a PID and never resolves a replacement binary through PATH.
func Call(ctx context.Context, path, operation string, request Request, result any) error {
	h, err := ReadHandle(path)
	if err != nil {
		return err
	}
	if request.Schema != Schema || request.Directory != h.Directory || request.ConfigDigest != h.ConfigDigest {
		return ErrUnauthorized
	}
	if operation != "status" && operation != "connect" && operation != "prepare" && operation != "prepared" && operation != "stop" && operation != "kube-credential" && operation != "attach" {
		return ErrInvalid
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", h.URL+"/v1/connections/"+operation, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.Key)
	req.Header.Set("Content-Type", "application/json")
	observability.InjectLocalTrace(ctx, req.Header)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxBytes))
		if response.StatusCode == 401 {
			return ErrUnauthorized
		}
		if response.StatusCode == 410 {
			return ErrExpired
		}
		if response.StatusCode == 425 {
			return ErrUnprepared
		}
		return ErrUnavailable
	}
	if strings.Split(response.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return ErrInvalid
	}
	if result == nil {
		result = new(map[string]any)
	}
	if err := ReadJSON(response.Body, result); err != nil {
		return fmt.Errorf("read connection response: %w", err)
	}
	return nil
}
