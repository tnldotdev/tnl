package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const maxSSHHostInstallPayload = 64 << 10

var errSSHEnrollmentRefresh = errors.New("SSH enrollment expired before root redemption started")

type sshInstallResponse struct {
	State string `json:"state"`
}

type sshInstallResponseBuffer struct{ bytes.Buffer }

func (b *sshInstallResponseBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 2048 {
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(data)
}

type sshInstallerRunner func(context.Context, string, []string, io.Reader, io.Writer) error

func executeSSHInstaller(ctx context.Context, program string, args []string, input io.Reader, diagnostics io.Writer) error {
	return executeSSHInstallerOutput(ctx, program, args, input, io.Discard, diagnostics)
}

func executeSSHInstallerOutput(ctx context.Context, program string, args []string, input io.Reader, output, diagnostics io.Writer) error {
	cmd := exec.CommandContext(ctx, program, args...)
	// neither the sudo process nor the root installer receives operator session
	// credentials, client-state selection, publisher files, or loader settings.
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, diagnostics
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func prepareSSHHostInstall(ctx context.Context, diagnostics io.Writer) error {
	if os.Getuid() == 0 && os.Geteuid() == 0 {
		return nil
	}
	args := []string{"-v"}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		args = []string{"-n", "-v"}
	}
	if err := executeSSHInstaller(ctx, "/usr/bin/sudo", args, os.Stdin, diagnostics); err != nil {
		return &sshCommandError{message: "SSH host setup needs root service installation", action: "run sudo -v from a terminal, then retry tnl service ssh enable", reason: failure.InvalidSetupInput, cause: err}
	}
	return nil
}

func installSSHHost(ctx context.Context, payload sshHostInstallPayload, diagnostics io.Writer) error {
	binary, err := os.Executable()
	if err != nil {
		return failure.Wrap("locate SSH installer", failure.ClientStateUnavailable, err)
	}
	var response sshInstallResponseBuffer
	err = invokeSSHHostInstall(ctx, payload, binary, os.Getuid() == 0 && os.Geteuid() == 0, diagnostics, func(ctx context.Context, program string, args []string, input io.Reader, diagnostics io.Writer) error {
		return executeSSHInstallerOutput(ctx, program, args, input, &response, diagnostics)
	})
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// the root command already rendered its safe failure on stderr.
		return &reportedError{err: err}
	}
	if err != nil {
		return err
	}
	return readSSHInstallResponse(response.Bytes())
}

func readSSHInstallResponse(data []byte) error {
	var response sshInstallResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return failure.Wrap("read SSH installer result", failure.ServerResponseInvalid, err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return failure.Wrap("read SSH installer result", failure.ServerResponseInvalid, errors.New("invalid installer result"))
	}
	switch response.State {
	case "installed":
		return nil
	case "enrollment_required":
		return errSSHEnrollmentRefresh
	default:
		return failure.Wrap("read SSH installer result", failure.ServerResponseInvalid, errors.New("invalid installer result"))
	}
}

func invokeSSHHostInstall(ctx context.Context, payload sshHostInstallPayload, binary string, root bool, diagnostics io.Writer, run sshInstallerRunner) error {
	if !filepath.IsAbs(binary) || strings.ContainsAny(binary, "\x00\r\n") || run == nil {
		return publisherjob.ErrUnsafeState
	}
	data, err := json.Marshal(payload)
	if err != nil || len(data) > maxSSHHostInstallPayload {
		return invalidSSHInstallPayload(err)
	}
	program, args := binary, []string{"service", "ssh", "install"}
	if !root {
		program, args = "/usr/bin/sudo", []string{"-n", "--", binary, "service", "ssh", "install"}
	}
	return run(ctx, program, args, bytes.NewReader(data), diagnostics)
}

func invalidSSHInstallPayload(cause error) error {
	if cause == nil {
		cause = errors.New("invalid SSH installer payload")
	}
	return failure.Wrap("read private SSH installer input", failure.InvalidSetupInput, cause)
}

func decodeSSHHostInstallPayload(input io.Reader) (sshHostInstallPayload, error) {
	var payload sshHostInstallPayload
	data, err := io.ReadAll(io.LimitReader(input, maxSSHHostInstallPayload+1))
	if err != nil || len(data) > maxSSHHostInstallPayload {
		return payload, invalidSSHInstallPayload(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return sshHostInstallPayload{}, invalidSSHInstallPayload(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return sshHostInstallPayload{}, invalidSSHInstallPayload(err)
	}
	if err := validateSSHHostInstallPayload(payload); err != nil {
		return sshHostInstallPayload{}, err
	}
	return payload, nil
}

func validateSSHHostInstallPayload(payload sshHostInstallPayload) error {
	if !validSSHHostPublicPort(payload.PublicPort) {
		return invalidSSHInstallPayload(nil)
	}
	server, err := naming.CanonicalControlURL(payload.Server)
	hostname, hostErr := naming.CanonicalizeHostname(payload.Hostname)
	parts := strings.Split(payload.EnrollmentKey, ".")
	if payload.Version != 1 || !naming.ValidServiceName(payload.Name) || err != nil || server != payload.Server || hostErr != nil || hostname != payload.Hostname || !opaqueid.Valid(payload.TeamID, opaqueid.TeamPrefix) || !opaqueid.Valid(payload.PublicURLID, opaqueid.PublicURLPrefix) || len(payload.Users) == 0 || len(payload.Users) > 64 || len(payload.HostPrivateKey) > 8192 || len(payload.EnrollmentKey) > 256 || len(parts) != 2 || !opaqueid.Valid(parts[0], opaqueid.PublisherEnrollmentPrefix) || parts[1] == "" || strings.ContainsAny(payload.EnrollmentKey, "\x00\r\n \t") {
		return invalidSSHInstallPayload(nil)
	}
	seen := map[string]bool{}
	for _, account := range payload.Users {
		if !validSSHAccount(account) || seen[account] {
			return invalidSSHInstallPayload(nil)
		}
		seen[account] = true
	}
	signer, err := managedssh.ParseHostKey(payload.HostPrivateKey)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return invalidSSHInstallPayload(err)
	}
	return nil
}

func validSSHHostPublicPort(port int) bool { return port >= 1024 && port <= 65535 }

func runSSHInstall(ctx context.Context, input io.Reader) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return &sshCommandError{message: "the SSH installer must run as root", action: "run tnl service ssh enable from your signed-in account", reason: failure.InvalidSetupInput}
	}
	payload, err := decodeSSHHostInstallPayload(input)
	if err != nil {
		return err
	}
	if err := validateSSHEnable(sshEnableCommand{Name: payload.Name, Users: payload.Users}, user.Lookup); err != nil {
		return err
	}
	if err := managedssh.ValidateUsers(payload.Users); err != nil {
		return invalidSSHInstallPayload(err)
	}
	root := publisherjob.DefaultRoot(runtime.GOOS)
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: root})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := installSSHHostJob(ctx, registry, payload, publisherjob.Clients); err != nil {
		if errors.Is(err, errSSHEnrollmentRefresh) {
			return json.NewEncoder(os.Stdout).Encode(sshInstallResponse{State: "enrollment_required"})
		}
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if err := publisherjob.InstallService(ctx, publisherjob.ServiceOptions{Root: root, BinarySource: binary}, publisherjob.HostExecutor{}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(sshInstallResponse{State: "installed"})
}

func installSSHHostJob(ctx context.Context, registry *publisherjob.Registry, payload sshHostInstallPayload, clients publisherjob.ClientFactory) error {
	if err := validateSSHHostInstallPayload(payload); err != nil {
		return err
	}
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	for _, existing := range jobs {
		if existing.ID != payload.Name && (existing.Server != payload.Server || existing.PublicURLID != payload.PublicURLID) {
			continue
		}
		before, after := slices.Clone(existing.SSHUsers), slices.Clone(payload.Users)
		slices.Sort(before)
		slices.Sort(after)
		if existing.ID != payload.Name || existing.Server != payload.Server || existing.PublicURLID != payload.PublicURLID || existing.Protocol != controlv1.Ssh || existing.Target != "" || !slices.Equal(before, after) || !bytes.Equal(existing.SSHHostKey, payload.HostPrivateKey) {
			return &sshCommandError{message: "a different SSH host setup is already installed", action: "inspect it with sudo tnl service status " + payload.Name + "; enable cannot take over or change its accounts", reason: failure.ServerConflict}
		}
		if !existing.Enabled {
			return &sshCommandError{message: "this SSH host is installed but stopped", action: "start it with sudo tnl service start " + payload.Name, reason: failure.ServerConflict}
		}
		if existing.PublicHostname != payload.Hostname || existing.PublicPort != payload.PublicPort {
			return publisherjob.ErrScope
		}
		return nil
	}
	job := publisherjob.Job{ID: payload.Name, Server: payload.Server, PublicURLID: payload.PublicURLID, PublicHostname: payload.Hostname, PublicPort: payload.PublicPort, Protocol: controlv1.Ssh, Target: "", SSHUsers: payload.Users, SSHHostKey: payload.HostPrivateKey}
	control, authority, err := clients(job)
	if err != nil {
		return err
	}
	profile, err := registry.Profile(ctx, payload.Server)
	if err != nil {
		return err
	}
	checkpoint, err := profile.LockSSHHostSetup(ctx, payload.TeamID, payload.Hostname)
	if err != nil {
		return err
	}
	defer checkpoint.Close()
	data, attempted, err := checkpoint.Read(ctx)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(payload.EnrollmentKey))
	hostDigest := sha256.Sum256(payload.HostPrivateKey)
	expected := sshRootEnrollmentAttempt{PublicURLID: payload.PublicURLID, Name: payload.Name, HostKeyDigest: hex.EncodeToString(hostDigest[:]), EnrollmentDigest: hex.EncodeToString(digest[:]), Users: slices.Clone(payload.Users)}
	slices.Sort(expected.Users)
	if attempted {
		var prior sshRootEnrollmentAttempt
		if json.Unmarshal(data, &prior) != nil {
			return invalidSSHSetupState()
		}
		before, _ := json.Marshal(prior)
		after, _ := json.Marshal(expected)
		if !bytes.Equal(before, after) {
			return &sshCommandError{message: "a previous root enrollment needs recovery", action: "retry the original SSH setup and enrollment; enable cannot replace an uncertain publisher identity", reason: failure.ServerConflict}
		}
	} else {
		if !payload.EnrollmentExpiresAt.IsZero() && !payload.EnrollmentExpiresAt.After(time.Now()) {
			return errSSHEnrollmentRefresh
		}
		data, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		if err := checkpoint.Save(ctx, data); err != nil {
			return err
		}
	}
	native, identity, err := nativeauth.EnrollNative(ctx, profile, control, authority, payload.EnrollmentKey)
	if err != nil {
		return err
	}
	if identity.Kind != "saved_url" || identity.PublicUrlId == nil || *identity.PublicUrlId != payload.PublicURLID || identity.TeamId != payload.TeamID || identity.DomainId != nil || identity.Namespace != nil {
		return publisherjob.ErrScope
	}
	saved, err := native.SavedURL(ctx)
	if err != nil {
		return err
	}
	if saved.Id != payload.PublicURLID || saved.TeamId != payload.TeamID || saved.CanonicalHostname != payload.Hostname || saved.PublicPort == nil || !validSSHHostPublicPort(*saved.PublicPort) || *saved.PublicPort != payload.PublicPort || saved.ServiceProtocol != controlv1.Ssh || saved.Target != "" || saved.AccessMode != controlv1.Restricted || saved.LifecycleState != controlv1.Enabled || saved.Purpose != controlv1.App || saved.Ephemeral || saved.SshHostKey == nil {
		return publisherjob.ErrScope
	}
	signer, err := managedssh.ParseHostKey(payload.HostPrivateKey)
	if err != nil {
		return invalidSSHInstallPayload(err)
	}
	public, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(*saved.SshHostKey))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(public.Marshal(), signer.PublicKey().Marshal()) {
		return publisherjob.ErrScope
	}
	signing, found, err := profile.PublisherSigningIdentity(ctx, "publisher:"+identity.ClientId)
	if err != nil {
		return err
	}
	if !found {
		return publisherjob.ErrScope
	}
	job.PublisherID, job.GrantID = identity.ClientId, identity.GrantId
	return registry.Install(ctx, job, identity, ed25519.PrivateKey(signing.PrivateValue))
}

// this durable marker outlives native enrollment pruning. expiry cannot turn an
// uncertain redemption into permission to create another publisher identity.
type sshRootEnrollmentAttempt struct {
	PublicURLID, Name, HostKeyDigest, EnrollmentDigest string
	Users                                              []string
}
