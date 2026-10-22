package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestNamedPrivatePublishDispatchesPublisherFileBeforeOwnerOrPersonState(t *testing.T) {
	root := t.TempDir()
	server := "https://control.example.test"
	address := config.Target("127.0.0.1:4000")
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}}
	flags := publishCommand{Target: "api", PublisherFile: filepath.Join(root, "missing-publisher.json"), Output: publishOutputHuman,
		remoteFlags: remoteFlags{ServerURL: server, StateDir: filepath.Join(root, "state")}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t.Context(), flags, io.Discard, io.Discard); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("named private credential dispatch = %v", err)
	}
	if _, err := os.Stat(flags.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid scoped credential opened person or owner state: %v", err)
	}
}

func TestNamedPublisherFileRejectsAnotherServerWithoutPersonFallback(t *testing.T) {
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	serviceID, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: keyID, GrantId: grant, TeamId: "team", Kind: "private_service", PrivateServiceId: &serviceID}
	file, err := credentialfile.New("https://credential.example.test", identity, private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "publisher.json")
	if err := credentialfile.Write(path, file); err != nil {
		t.Fatal(err)
	}
	address := config.Target("127.0.0.1:4000")
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}}
	flags := publishCommand{Target: "api", PublisherFile: path, Output: publishOutputHuman, remoteFlags: remoteFlags{ServerURL: "https://other.example.test", StateDir: filepath.Join(root, "state")}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t.Context(), flags, io.Discard, io.Discard); !errors.Is(err, nativeauth.ErrScope) {
		t.Fatalf("publisher file changed control server: %v", err)
	}
	if _, err := os.Stat(flags.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched scoped credential opened person state: %v", err)
	}
}

func TestNamedServerOverrideRequiresAnExplicitReplacementTeam(t *testing.T) {
	server, team := "https://configured.example.test", "configured"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &server, Team: &team, Services: config.Services{"api": {}}}}}
	flags := publishCommand{Target: "api", remoteFlags: remoteFlags{ServerURL: "https://other.example.test"}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveNamedPrivate(flags); err == nil {
		t.Fatal("changing server silently selected that server's default team")
	}
}

func TestNamedPublishRejectsUnsupportedPolicyBeforeOwnerState(t *testing.T) {
	root := t.TempDir()
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Config: config.TNL{Services: config.Services{
		"web": {Tunnel: &config.Tunnel{}},
	}}}}
	flags := publishCommand{Target: "web", Output: publishOutputHuman, tunnelFlags: tunnelFlags{Anonymous: true}, remoteFlags: remoteFlags{StateDir: filepath.Join(root, "state")}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	err := runPublish(t.Context(), flags, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.NamedPublishOverrides {
		t.Fatalf("unsupported named policy = %v", err)
	}
	if _, err := os.Stat(flags.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported policy acquired owner state: %v", err)
	}
}

func TestNamedLeasePinsServerTeamConfigAndTargetAtOwnerBoundary(t *testing.T) {
	configuredServer, configuredTeam := "https://configured.example.test", "configured"
	selectedServer, selectedTeam := "https://selected.example.test", "selected"
	address := config.Target("127.0.0.1:4100")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: projectconfig.Project{Root: root}}
	project.Selection = projectconfig.Selection{Path: filepath.Join(project.Root, "development.json")}
	project.Config = config.TNL{Server: &configuredServer, Team: &configuredTeam, Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}
	flags := publishCommand{Target: "api", remoteFlags: remoteFlags{ServerURL: selectedServer}, tunnelFlags: tunnelFlags{teamSelectionFlags: teamSelectionFlags{Team: selectedTeam}}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	invocation, err := resolveNamedPrivate(flags)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, digest, err := invocation.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := projectconfig.ReadSnapshot(strings.NewReader(string(snapshot)))
	if err != nil {
		t.Fatal(err)
	}
	if *transferred.Config.Server != selectedServer || *transferred.Config.Team != selectedTeam || transferred.Selection.Path != project.Selection.Path {
		t.Fatalf("lost resolved invocation: %+v", transferred)
	}
	if digest == "" {
		t.Fatal("resolved invocation omitted its configuration digest")
	}
}
