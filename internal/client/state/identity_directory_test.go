package state

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/failure"
)

const durableTestPublisher = "pub_0123456789ABCDEFGHIJKL"

func durableTestProfile(t *testing.T, runtime, identity string) *Store {
	t.Helper()
	database, err := OpenWithOptions(t.Context(), runtime, OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	profile, err := database.Server(t.Context(), "https://control.example")
	if err == nil {
		profile, err = profile.WithIdentityDirectory(identity)
	}
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestDurablePublisherCertificatesSurviveRuntimeDeletion(t *testing.T) {
	runtime, identity := filepath.Join(t.TempDir(), "runtime"), filepath.Join(t.TempDir(), "identity")
	profile := durableTestProfile(t, runtime, identity)
	plan, hostname := exactCertificateTestPlan(), "route.example"
	cache, err := profile.CertificatesForPublisher("team", durableTestPublisher, plan)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.Pending(t.Context(), hostname)
	if err != nil {
		t.Fatal(err)
	}
	var installed Material
	for _, phase := range []string{"pending", "staged", "current", "renewal"} {
		switch phase {
		case "staged":
			installed, err = cache.Stage(t.Context(), hostname, first, signedCertificate(t, first.Key, hostname), time.Now().Add(time.Hour), "original-issuance")
		case "current":
			err = cache.Promote(t.Context(), hostname, installed.IssuanceID)
		case "renewal":
			first, err = cache.NewPending(t.Context(), hostname)
		}
		if err != nil {
			t.Fatal(phase, err)
		}
		if err := profile.database.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(runtime); err != nil {
			t.Fatal(err)
		}
		profile = durableTestProfile(t, runtime, identity)
		cache, err = profile.CertificatesForPublisher("team", durableTestPublisher, plan)
		if err != nil {
			t.Fatal(err)
		}
		if phase != "current" {
			loaded, err := cache.Pending(t.Context(), hostname)
			if err != nil || !bytes.Equal(loaded.CSRDER, first.CSRDER) || !loaded.Key.Equal(first.Key) {
				t.Fatal("runtime deletion changed pending key", phase, err)
			}
		}
		if phase == "staged" {
			loaded, found, err := cache.Staged(t.Context(), hostname)
			if err != nil || !found || loaded.IssuanceID != installed.IssuanceID {
				t.Fatal("staged issuance was lost", err)
			}
		}
		if phase == "current" || phase == "renewal" {
			loaded, found, err := cache.Current(t.Context(), hostname)
			if err != nil || !found || !bytes.Equal(loaded.Certificate.Certificate[0], installed.Certificate.Certificate[0]) {
				t.Fatal("current certificate was lost", phase, err)
			}
		}
	}
}

func TestCertificateFilesDoNotReleaseUndurableKeysOrStagedMaterial(t *testing.T) {
	profile := durableTestProfile(t, filepath.Join(t.TempDir(), "runtime"), filepath.Join(t.TempDir(), "identity"))
	cache, err := profile.CertificatesForPublisher("team", durableTestPublisher, exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	// establish a complete current plan before testing uncertain renewal writes.
	// a partial first checkpoint is invalid state, not a source for reconstruction.
	if _, err := cache.Pending(t.Context(), "route.example"); err != nil {
		t.Fatal(err)
	}
	failing := true
	cache.files.syncFile = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() && failing {
			return syscall.EIO
		}
		return file.Sync()
	}
	if pending, err := cache.NewPending(t.Context(), "route.example"); !errors.Is(err, syscall.EIO) || pending.Key != nil {
		t.Fatal("unsynced renewal key reached issuance", err)
	}
	for range 2 {
		pending, err := cache.Pending(t.Context(), "route.example")
		if reason, _ := failure.ReasonOf(err); reason != failure.PublisherIdentityStateUnavailable || pending.Key != nil {
			t.Fatal("unsynced key reached issuance", err)
		}
	}
	saved, err := cache.read()
	if err != nil {
		t.Fatal(err)
	}
	defer saved.destroy()
	failing = false
	pending, err := cache.Pending(t.Context(), "route.example")
	if err != nil || saved.Pending == nil || !bytes.Equal(pending.CSRDER, saved.Pending.CSRDER) {
		t.Fatal("uncertain write regenerated a key", err)
	}
	failing = true
	staged, err := cache.Stage(t.Context(), "route.example", pending, signedCertificate(t, pending.Key, "route.example"), time.Now().Add(time.Hour), "staged-issuance")
	if !errors.Is(err, syscall.EIO) || staged.Certificate.PrivateKey != nil {
		t.Fatal("unsynced certificate reached installation", err)
	}
	if staged, found, err := cache.Staged(t.Context(), "route.example"); !errors.Is(err, syscall.EIO) || !found || staged.Certificate.PrivateKey != nil {
		t.Fatal("recovery skipped staged durability", err)
	}
	failing = false
	if _, found, err := cache.Staged(t.Context(), "route.example"); err != nil || !found {
		t.Fatal(err)
	}
	failing = true
	for range 2 {
		if err := cache.Promote(t.Context(), "route.example", "staged-issuance"); !errors.Is(err, syscall.EIO) {
			t.Fatal("promotion skipped durability retry", err)
		}
	}
	failing = false
	if err := cache.Promote(t.Context(), "route.example", "staged-issuance"); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateFilesRejectMissingScopeAndUnsafePaths(t *testing.T) {
	profile := durableTestProfile(t, filepath.Join(t.TempDir(), "runtime"), filepath.Join(t.TempDir(), "identity"))
	cache, err := profile.CertificatesForPublisher("team", durableTestPublisher, exactCertificateTestPlan())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Pending(t.Context(), "route.example"); err != nil {
		t.Fatal(err)
	}
	name := certificateFilename(cache.planJSON)
	data, _, err := cache.files.Read(name, maxCertificateFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	for _, field := range []string{"version", "server", "team_id", "publisher_identity_id", "plan"} {
		var document map[string]jsontext.Value
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		delete(document, field)
		invalid, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.files.Write(name, invalid); err != nil {
			t.Fatal(err)
		}
		clear(invalid)
		if pending, err := cache.Pending(t.Context(), "route.example"); err == nil || pending.Key != nil {
			t.Fatal("incomplete scope accepted", field)
		}
	}
	if err := cache.files.Write(name, data); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache.files.Path(), name)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Pending(t.Context(), "route.example"); err == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Pending(t.Context(), "route.example"); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := cache.files.Write(name, data); err == nil {
		t.Fatal("symlink overwritten")
	}
}

func TestPrivateDirectoryAtomicSnapshotsAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	files, err := OpenPrivateDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	first, second := bytes.Repeat([]byte("a"), 16384), bytes.Repeat([]byte("b"), 32768)
	if err := files.Write("state.json", first); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	readers.Go(func() {
		for range 100 {
			data, found, err := files.Read("state.json", 32768)
			if err != nil || !found || !bytes.Equal(data, first) && !bytes.Equal(data, second) {
				t.Error("reader saw an incomplete atomic snapshot", err)
				return
			}
		}
	})
	for range 50 {
		if err := files.Write("state.json", second); err != nil {
			t.Fatal(err)
		}
		if err := files.Write("state.json", first); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := files.Write("state.json", second); err == nil {
		t.Fatal("stale owner wrote into a replaced directory")
	}
	if _, err := os.Stat(filepath.Join(path, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement directory was mutated", err)
	}
}

var privateDirectoryChild = flag.String("tnl-private-directory-child", "", "private directory for the file-lock child fixture")

func TestPrivateDirectoryChildLock(t *testing.T) {
	if *privateDirectoryChild == "" {
		t.Skip("child fixture")
	}
	files, err := OpenPrivateDirectory(*privateDirectoryChild)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := files.Lock(t.Context(), "publisher.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, _ = fmt.Fprintln(os.Stdout, "locked")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func TestPrivateDirectoryLockSurvivesIndependentRuntimeAndCrash(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "identity")
	profile := durableTestProfile(t, filepath.Join(t.TempDir(), "runtime-a"), identity)
	other := durableTestProfile(t, filepath.Join(t.TempDir(), "runtime-b"), identity)
	files, err := profile.PublisherIdentityFiles("team", durableTestPublisher)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := other.PublisherIdentityFiles("team", durableTestPublisher)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPrivateDirectoryChildLock$", "-tnl-private-directory-child="+files.Path())
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatal("child failed to acquire directory", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if lock, err := peer.Lock(ctx, "publisher.lock"); !errors.Is(err, context.DeadlineExceeded) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatal("independent runtime bypassed the durable lock", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	lock, err := peer.Lock(t.Context(), "publisher.lock")
	if err != nil {
		t.Fatal("process crash retained writer ownership", err)
	}
	_ = lock.Close()
}
