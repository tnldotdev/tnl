package invocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type TeamSelection struct {
	team       authorityv1.Team
	membership authorityv1.Membership
	domains    []authorityv1.Domain
	mode       naming.ManagedURLMode
}

func NewTeamSelection(team authorityv1.Team, membership authorityv1.Membership, domains []authorityv1.Domain, mode naming.ManagedURLMode) TeamSelection {
	return TeamSelection{team: team, membership: membership, domains: domains, mode: mode}
}

// FromTeamContext adapts shared client selection to publication inputs.
func FromTeamContext(current clientteam.Context) TeamSelection {
	return NewTeamSelection(current.Team(), current.Membership(), current.Domains(), current.Mode())
}

func (current TeamSelection) Context() clientteam.Context {
	return clientteam.NewContext(current.team, current.membership, current.domains, current.mode)
}

func authenticateRuntime(ctx context.Context, state *clientstate.Database, server string) (*clientauth.Client, error) {
	if os.Getenv("TNL_ACCESS_TOKEN") != "" && os.Getenv("TNL_SERVER") == "" {
		return nil, failure.Wrap("select credential server", failure.InvalidTunnelFlags, errors.New("an explicit access token requires TNL_SERVER"))
	}
	return clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: server, State: state, AccessToken: os.Getenv("TNL_ACCESS_TOKEN"), Diagnostics: io.Discard})
}

func publisherCLIError(message string) error {
	return failure.Wrap("select publisher identity", failure.InvalidTunnelFlags, errors.New(message))
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}

func resolveServer(ctx context.Context, root, selected string) (string, *clientstate.Database, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return "", nil, err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return "", nil, err
	}
	server, err := clientserver.Select(ctx, state, selected)
	if err != nil {
		state.Close()
		return "", nil, err
	}
	return server, state, nil
}

func currentProjectRoot(ctx context.Context) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
	if err != nil {
		return "", err
	}
	return worktree.Root, nil
}

func RetainedScope(target string) string {
	digest := sha256.Sum256([]byte(target))
	return "foreground:" + hex.EncodeToString(digest[:])
}
