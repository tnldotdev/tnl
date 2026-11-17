package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestNamedPrivatePublishDispatchesPublisherCredentialFileBeforeOwnerOrPersonState(t *testing.T) {
	root := t.TempDir()
	server := "https://control.example.test"
	address := config.Target("127.0.0.1:4000")
	project := projectConfiguration{Project: clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}}
	flags := publishCommand{Target: "api", PublisherCredentialFile: filepath.Join(root, "missing-publisher.json"), Output: publishOutputHuman,
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

func TestNamedPublisherCredentialFileRejectsAnotherServerWithoutPersonFallback(t *testing.T) {
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	serviceID, _ := opaqueid.New(opaqueid.ServicePrefix)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: keyID, GrantId: grant, TeamId: "team", Kind: "service", ServiceId: &serviceID}
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
	project := projectConfiguration{Project: clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}}}
	flags := publishCommand{Target: "api", PublisherCredentialFile: path, Output: publishOutputHuman, remoteFlags: remoteFlags{ServerURL: "https://other.example.test", StateDir: filepath.Join(root, "state")}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t.Context(), flags, io.Discard, io.Discard); !errors.Is(err, publisheridentity.ErrScope) {
		t.Fatalf("publisher file changed control server: %v", err)
	}
	if _, err := os.Stat(flags.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched scoped credential opened person state: %v", err)
	}
}

func TestNamedServerOverrideRequiresAnExplicitReplacementTeam(t *testing.T) {
	server, team := "https://configured.example.test", "configured"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &server, Team: &team, Services: config.Services{"api": {}}}}}
	flags := publishCommand{Target: "api", remoteFlags: remoteFlags{ServerURL: "https://other.example.test"}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	if _, err := namedInvocation(flags); err == nil {
		t.Fatal("changing server silently selected that server's default team")
	}
}

func TestNamedPublishRejectsUnsupportedPolicyBeforeOwnerState(t *testing.T) {
	root := t.TempDir()
	project := projectConfiguration{Project: clientproject.Project{Root: root, Config: config.TNL{Services: config.Services{
		"web": {Public: new(true)},
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
	project := projectConfiguration{Project: clientproject.Project{Root: root}}
	project.Selection = clientproject.Selection{Path: filepath.Join(project.Root, "development.json")}
	project.Config = config.TNL{Server: &configuredServer, Team: &configuredTeam, Services: config.Services{
		"api": {Target: &config.ServiceTarget{Type: "address", Address: &address}},
	}}
	flags := publishCommand{Target: "api", remoteFlags: remoteFlags{ServerURL: selectedServer}, tunnelFlags: tunnelFlags{teamSelectionFlags: teamSelectionFlags{Team: selectedTeam}}}
	if err := project.applyPublish(&flags); err != nil {
		t.Fatal(err)
	}
	invocation, err := namedInvocation(flags)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, digest, err := invocation.project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := clientproject.ReadSnapshot(strings.NewReader(string(snapshot)))
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

func TestNamedInvocationUsesOneSelectionForProtocolAndReachability(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "mysql", "postgres", "kubernetes"} {
		for _, public := range []bool{false, true} {
			t.Run(protocol+"/"+strconv.FormatBool(public), func(t *testing.T) {
				binding := config.Service{Protocol: &protocol, Public: &public}
				project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"app": binding}}}}
				flags := publishCommand{Service: "app", Protocol: protocol, project: project}
				selected, err := namedInvocation(flags)
				if err != nil || selected.service != "app" || !reflect.DeepEqual(selected.project, project) {
					t.Fatalf("named service selection changed: %+v %v", selected, err)
				}
				flags.Protocol = "other"
				if _, err := namedInvocation(flags); err == nil {
					t.Fatal("named service accepted another protocol")
				}
				flags.Protocol, flags.Service = protocol, "missing"
				if _, err := namedInvocation(flags); err == nil {
					t.Fatal("named service accepted a missing declaration")
				}
			})
		}
	}
}

func TestNamedPublishRejectsUnsupportedProcessOptionsBeforeOwnerState(t *testing.T) {
	for _, test := range []struct {
		name, protocol string
		public         bool
		flags          publishCommand
	}{
		{name: "public browser requires HTTP", protocol: "tcp", public: true, flags: publishCommand{openOptions: openOptions{Open: true}}},
		{name: "connector-only browser", protocol: "http", flags: publishCommand{openOptions: openOptions{Open: true}}},
		{name: "public system without install", protocol: "http", public: true, flags: publishCommand{backgroundPublishFlags: backgroundPublishFlags{System: true}}},
		{name: "connector-only system without install", protocol: "http", flags: publishCommand{backgroundPublishFlags: backgroundPublishFlags{System: true}}},
		{name: "service name without install", protocol: "tcp", public: true, flags: publishCommand{backgroundPublishFlags: backgroundPublishFlags{ServiceName: "app"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			flags := test.flags
			flags.Service, flags.Protocol, flags.Output = "app", test.protocol, publishOutputHuman
			flags.StateDir = filepath.Join(t.TempDir(), "state")
			flags.project.Config.Services = config.Services{"app": {Protocol: &test.protocol, Public: &test.public}}
			err := runPublish(t.Context(), flags, io.Discard, io.Discard)
			if reason, _ := failure.ReasonOf(err); reason != failure.InvalidTunnelFlags {
				t.Fatalf("unsupported process options reached publication: %v", err)
			}
			if _, err := os.Stat(flags.StateDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsupported process options opened owner state: %v", err)
			}
		})
	}
}
