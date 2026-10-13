package stagingcheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

var (
	serverFlag   = flag.String("tnl-server", "", "explicit deployed control URL")
	teamFlag     = flag.String("tnl-team", "", "explicit test team ID")
	binaryFlag   = flag.String("tnl-binary", "", "absolute path to the tnl binary")
	versionFlag  = flag.String("tnl-version", "", "expected tnl version")
	revisionFlag = flag.String("tnl-revision", "", "expected tnl binary Git commit")
	tokenFlag    = flag.String("tnl-login-token-file", "", "path to a private login token file")
	customFlag   = flag.String("tnl-custom-domain", "", "ready custom domain for shared URL coverage")
)

type settings struct {
	server, team, binary, version, revision, token, customDomain string
}

func deployedSettings(t *testing.T) settings {
	t.Helper()
	if *serverFlag == "" || *teamFlag == "" || *binaryFlag == "" || *versionFlag == "" || *revisionFlag == "" || *tokenFlag == "" {
		t.Fatal("deployed checks require -tnl-server, -tnl-team, -tnl-binary, -tnl-version, -tnl-revision, and -tnl-login-token-file")
	}
	server, err := clientstate.CanonicalServer(*serverFlag)
	if err != nil || server != *serverFlag {
		t.Fatalf("-tnl-server must be a canonical HTTPS control URL: %v", err)
	}
	if !filepath.IsAbs(*binaryFlag) || !filepath.IsAbs(*tokenFlag) {
		t.Fatal("-tnl-binary and -tnl-login-token-file must be absolute paths")
	}
	info, err := os.Stat(*tokenFlag)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("-tnl-login-token-file must be a private regular file: %v", err)
	}
	data, err := os.ReadFile(*tokenFlag)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		t.Fatalf("read private login token file: %v", err)
	}
	return settings{server: server, team: *teamFlag, binary: *binaryFlag, version: *versionFlag, revision: *revisionFlag,
		token: strings.TrimSpace(string(data)), customDomain: *customFlag}
}

func TestDeployedSmoke(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierDeployed)
	config := deployedSettings(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	verifyBinary(t, ctx, config)
	verifyTeam(t, ctx, config)
	checkHTTP(t, ctx, config, benchworkload.TransportAuto)
	checkCLI(t, ctx, config)
}

func TestDeployedFull(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierDeployed)
	config := deployedSettings(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	verifyBinary(t, ctx, config)
	verifyTeam(t, ctx, config)
	for _, transport := range []benchworkload.TransportChoice{benchworkload.TransportQUIC, benchworkload.TransportTCP} {
		t.Run(string(transport), func(t *testing.T) {
			checkHTTP(t, ctx, config, transport)
		})
	}
	checkCLI(t, ctx, config)
}

func runLabel(t *testing.T) string {
	t.Helper()
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	return "tnlcheck" + hex.EncodeToString(bytes)
}

// openControl uses independent client state so cleanup can still run after a publisher group closes.
func openControl(ctx context.Context, config settings, stateRoot string) (*controlclient.Client, func() error, error) {
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return nil, nil, err
	}
	auth, err := clientauth.Login(ctx, clientauth.Config{ServerEndpoint: config.server, State: state, Diagnostics: io.Discard,
		ForceLoginToken: true, LoginToken: func() (credentials.LoginToken, error) { return credentials.LoginToken(config.token), nil }})
	if err != nil {
		return nil, nil, errors.Join(err, state.Close())
	}
	identity, err := auth.Authority.IdentityContext(ctx)
	if err != nil {
		return nil, nil, errors.Join(err, state.Close())
	}
	found := false
	for _, membership := range identity.Memberships {
		if membership.TeamId == config.team && membership.Id != "" {
			found = true
		}
	}
	if !found {
		return nil, nil, errors.Join(fmt.Errorf("identity is not a member of team %s", config.team), state.Close())
	}
	team, err := auth.Authority.GetTeam(ctx, config.team)
	if err != nil {
		return nil, nil, errors.Join(err, state.Close())
	}
	if team.Kind != authorityv1.Organization {
		return nil, nil, errors.Join(errors.New("deployed checks require a dedicated organization team"), state.Close())
	}
	domains, err := auth.Authority.ListTeamDomains(ctx, config.team)
	if err != nil {
		return nil, nil, errors.Join(err, state.Close())
	}
	ready := false
	for _, domain := range domains.Domains {
		if domain.Kind == authorityv1.Managed && domain.State == authorityv1.DomainStateReady && domain.CanonicalDomain == auth.Discovery.ManagedDomain {
			ready = true
		}
	}
	if !ready {
		return nil, nil, errors.Join(errors.New("test team's managed domain is not ready"), state.Close())
	}
	return auth.Control, state.Close, nil
}

func verifyTeam(t *testing.T, ctx context.Context, config settings) {
	t.Helper()
	_, closeState, err := openControl(ctx, config, filepath.Join(t.TempDir(), "team-check"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closeState(); err != nil {
		t.Fatal(err)
	}
}

func checkHTTP(t *testing.T, ctx context.Context, config settings, transport benchworkload.TransportChoice) {
	t.Helper()
	const bytes = 127
	origin := httptest.NewServer(benchworkload.Origin(bytes))
	t.Cleanup(origin.Close)
	label := runLabel(t)
	t.Logf("http check label=%s team=%s transport=%s", label, config.team, transport)
	var mu sync.Mutex
	owned := make(map[string]string)
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: config.server, Team: config.team, LoginToken: config.token, StateRoot: filepath.Join(t.TempDir(), "publisher"),
		Target: origin.URL, HostnamePrefix: label, Ephemeral: true, Transport: transport,
		Parallel: 1, ReadyTimeout: 5 * time.Minute, StopTimeout: 20 * time.Second,
		Observe: func(_ int, event publisher.Event) error {
			if event.PublicURLID != "" && event.Hostname != "" {
				mu.Lock()
				owned[event.PublicURLID] = event.Hostname
				mu.Unlock()
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if _, err := group.Close(cleanup); err != nil {
			t.Errorf("stop publisher: %v", err)
		}
		mu.Lock()
		urls := make(map[string]string, len(owned))
		for id, hostname := range owned {
			urls[id] = hostname
		}
		mu.Unlock()
		verifyCleanup(t, cleanup, config, urls)
	})
	ready, err := group.Start(ctx, []int{0})
	if err != nil || len(ready) != 1 {
		t.Fatalf("publish %s: ready=%+v: %v", transport, ready, err)
	}
	if err := visitHTTP(ctx, ready[0].Ready.PublicURL, bytes); err != nil {
		t.Fatal(err)
	}
	if transport != benchworkload.TransportAuto {
		stream, err := (benchworkload.Visitor{}).Hold(ctx, ready[0].Ready.PublicURL)
		if err != nil {
			t.Fatal(err)
		}
		before := stream.BytesReceived()
		if err := benchworkload.WaitUntil(ctx, time.Now().Add(400*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if !stream.Alive() || stream.BytesReceived() <= before {
			t.Error("held visitor stream stopped delivering bytes")
		}
		if err := stream.Close(); err != nil {
			t.Error(err)
		}
	}
	select {
	case err := <-group.Failures():
		t.Fatalf("publisher exited before visitor check: %v", err)
	default:
	}
}

func visitHTTP(ctx context.Context, publicURL string, size int) error {
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Path != "" {
		return fmt.Errorf("invalid public URL %q: %v", publicURL, err)
	}
	visitor := benchworkload.Visitor{PayloadBytes: size}
	deadline, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		result := visitor.Request(deadline, publicURL, time.Now())
		if result.Error == "" && result.Bytes == int64(size) {
			return nil
		}
		if strings.Contains(result.Error, "wrong host") || strings.Contains(result.Error, "payload mismatch") {
			return fmt.Errorf("visitor %s: %s", publicURL, result.Error)
		}
		if err := benchworkload.WaitUntil(deadline, time.Now().Add(2*time.Second)); err != nil {
			return fmt.Errorf("visitor %s: %s: %w", publicURL, result.Error, err)
		}
	}
}

func verifyCleanup(t *testing.T, ctx context.Context, config settings, urls map[string]string) {
	t.Helper()
	if len(urls) == 0 {
		t.Error("no public URL IDs were observed for cleanup")
		return
	}
	control, closeState, err := openControl(ctx, config, filepath.Join(t.TempDir(), "cleanup"))
	if err != nil {
		t.Errorf("authenticate cleanup: %v", err)
		return
	}
	defer func() {
		if err := closeState(); err != nil {
			t.Error(err)
		}
	}()
	for id, hostname := range urls {
		publicURL, err := control.GetPublicURL(ctx, id)
		if errors.Is(err, controlclient.ErrNotFound) {
			continue
		}
		if err != nil {
			t.Errorf("check public URL %s cleanup: %v", id, err)
			continue
		}
		if publicURL.TeamId != config.team || publicURL.CanonicalHostname != hostname || !strings.HasPrefix(hostname, "tnlcheck") {
			t.Errorf("refusing to remove mismatched public URL %s (%s)", id, hostname)
			continue
		}
		t.Errorf("publisher left public URL %s (%s); removing it", id, hostname)
		if err := control.DeletePublicURL(ctx, id); err != nil {
			t.Errorf("remove leftover public URL %s: %v", id, err)
		}
	}
}
