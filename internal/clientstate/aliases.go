package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrAliasNotFound            = errors.New("alias has no local declaration")
	ErrAliasPolicyConflict      = errors.New("another worktree declares a different alias or uses its hostname")
	ErrAliasOwned               = errors.New("another live worktree owns this alias")
	ErrAliasReceiverUnavailable = errors.New("selected alias service is not ready")
	ErrAliasNotSelected         = errors.New("this worktree is not selected for the alias")
	ErrAliasSelectionStale      = errors.New("alias selection changed")
)

// AliasScope identifies a project alias in one member/domain context. ProjectKey
// is the primary checkout's corresponding project directory, not a branch name.
type AliasScope struct {
	Server, ProjectKey, TeamID, MembershipID, Namespace, Name string
}

type AliasRegistration struct {
	Scope                                         AliasScope
	Hostname, Service, TunnelID, IntegrationGroup string
	Fingerprint                                   [32]byte
}

type AliasSelection struct {
	ID                         string
	Scope                      AliasScope
	Hostname, Service, Project string
	Revision                   uint64
	Fingerprint                [32]byte
}

func (s AliasScope) validate() error {
	server, err := CanonicalServer(s.Server)
	namespace, hostErr := naming.CanonicalizeHostname(s.Namespace)
	if err != nil || server != s.Server || hostErr != nil || namespace != s.Namespace ||
		!filepath.IsAbs(s.ProjectKey) || filepath.Clean(s.ProjectKey) != s.ProjectKey || strings.ContainsRune(s.ProjectKey, '\x00') ||
		s.TeamID == "" || s.MembershipID == "" || !naming.ValidServiceName(s.Name) {
		return errors.New("invalid alias scope")
	}
	return nil
}

// RegisterAlias defaults ownership to the primary checkout. registration never
// takes an explicit selection from another worktree, even after it stops.
func (d *Database) RegisterAlias(ctx context.Context, registration AliasRegistration) (AliasSelection, error) {
	scope := registration.Scope
	if err := scope.validate(); err != nil {
		return AliasSelection{}, err
	}
	hostname, err := naming.CanonicalizeHostname(registration.Hostname)
	groupProject, _, validGroup := strings.Cut(registration.IntegrationGroup, "\x00")
	if err != nil || hostname != registration.Hostname || !naming.ValidServiceName(registration.Service) || !validGroup || groupProject != scope.ProjectKey {
		return AliasSelection{}, errors.New("invalid alias declaration")
	}
	id, err := opaqueid.New(opaqueid.AliasPrefix)
	if err != nil {
		return AliasSelection{}, err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return AliasSelection{}, err
	}
	defer tx.Rollback()
	queries, now := clientstatedb.New(tx), d.now().UTC().UnixNano()
	// this first write serializes declaration checks and selection with other
	// connections; do not establish a read snapshot before acquiring it.
	err = queries.InitializeProjectAlias(ctx, clientstatedb.InitializeProjectAliasParams{
		AliasID: id, ServerOrigin: scope.Server, ProjectKey: scope.ProjectKey, TeamID: scope.TeamID,
		MembershipID: scope.MembershipID, Namespace: scope.Namespace, Name: scope.Name,
		Hostname: hostname, Service: registration.Service, Fingerprint: registration.Fingerprint[:],
		TunnelID: registration.TunnelID, IntegrationGroup: registration.IntegrationGroup, Now: now,
	})
	if err != nil {
		return AliasSelection{}, err
	}
	row, err := queries.ProjectAliasByScope(ctx, scope.query())
	if errors.Is(err, sql.ErrNoRows) {
		return AliasSelection{}, ErrAliasPolicyConflict
	}
	if err != nil {
		return AliasSelection{}, err
	}
	conflicts, err := queries.AliasDefinitionConflicts(ctx, clientstatedb.AliasDefinitionConflictsParams{AliasID: row.ID, Fingerprint: registration.Fingerprint[:], Now: now})
	if err != nil {
		return AliasSelection{}, err
	}
	if conflicts != 0 {
		return AliasSelection{}, ErrAliasPolicyConflict
	}
	updated, err := queries.UpdateAliasDefinition(ctx, clientstatedb.UpdateAliasDefinitionParams{
		AliasID: row.ID, Hostname: hostname, Service: registration.Service, Fingerprint: registration.Fingerprint[:],
	})
	if err != nil {
		return AliasSelection{}, err
	}
	if updated != 1 {
		return AliasSelection{}, ErrAliasSelectionStale
	}
	count, err := queries.RegisterAliasDeclaration(ctx, clientstatedb.RegisterAliasDeclarationParams{
		AliasID: row.ID, TunnelID: registration.TunnelID, Fingerprint: registration.Fingerprint[:],
		ServerOrigin: scope.Server, Service: registration.Service, IntegrationGroup: registration.IntegrationGroup, Now: now,
	})
	if err != nil {
		return AliasSelection{}, err
	}
	if count != 1 {
		return AliasSelection{}, ErrAliasReceiverUnavailable
	}
	row, err = queries.ProjectAliasByID(ctx, row.ID)
	if err != nil {
		return AliasSelection{}, err
	}
	if err := tx.Commit(); err != nil {
		return AliasSelection{}, err
	}
	return aliasSelection(row), nil
}

func (s AliasScope) query() clientstatedb.ProjectAliasByScopeParams {
	return clientstatedb.ProjectAliasByScopeParams{ServerOrigin: s.Server, ProjectKey: s.ProjectKey,
		TeamID: s.TeamID, MembershipID: s.MembershipID, Namespace: s.Namespace, Name: s.Name}
}

func (d *Database) AliasSelection(ctx context.Context, scope AliasScope) (AliasSelection, error) {
	if err := scope.validate(); err != nil {
		return AliasSelection{}, err
	}
	row, err := d.queries.ProjectAliasByScope(ctx, scope.query())
	if errors.Is(err, sql.ErrNoRows) {
		return AliasSelection{}, ErrAliasNotFound
	}
	return aliasSelection(row), err
}

// AliasCandidate reads selection and its current ready receiver in one snapshot.
// a caller must compare its captured revision and tunnel/run identity before
// admitting a request; election alone does not fence a changed selection.
func (d *Database) AliasCandidate(ctx context.Context, id string) (AliasSelection, TunnelInfo, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AliasSelection{}, TunnelInfo{}, err
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	row, err := queries.ProjectAliasByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return AliasSelection{}, TunnelInfo{}, ErrAliasNotFound
	}
	if err != nil {
		return AliasSelection{}, TunnelInfo{}, err
	}
	selection := aliasSelection(row)
	tunnel, err := queries.ReadyAliasReceiver(ctx, clientstatedb.ReadyAliasReceiverParams{
		AliasID: id, ProjectRoot: row.SelectedProject, Now: d.now().UTC().UnixNano(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return selection, TunnelInfo{}, ErrAliasReceiverUnavailable
	}
	if err != nil {
		return selection, TunnelInfo{}, err
	}
	if err := tx.Commit(); err != nil {
		return selection, TunnelInfo{}, err
	}
	return selection, TunnelInfo{ID: tunnel.ID, Server: tunnel.ServerOrigin, Project: tunnel.ProjectRoot,
		Service: tunnel.Service, IntegrationGroup: tunnel.IntegrationGroup, State: TunnelState(tunnel.State),
		Target: tunnel.Target, Hostname: tunnel.Hostname, PublicURL: "https://" + tunnel.Hostname,
		PublicURLID: tunnel.PublicURLID, PublishRunNumber: uint64(tunnel.PublishRunNumber)}, nil
}

// SelectAlias requires a ready caller service. without force, another selected
// live tunnel retains ownership through reprovisioning. stopping it permits an
// explicit selection change, but never causes automatic reassignment.
func (d *Database) SelectAlias(ctx context.Context, scope AliasScope, project string, force bool) (AliasSelection, error) {
	return d.changeAliasSelection(ctx, scope, project, force, false)
}

// ReleaseAlias returns an override to the primary checkout, even if its service
// is stopped. only the selected worktree may release its selection.
func (d *Database) ReleaseAlias(ctx context.Context, scope AliasScope, project string) (AliasSelection, error) {
	return d.changeAliasSelection(ctx, scope, project, false, true)
}

func (d *Database) changeAliasSelection(ctx context.Context, scope AliasScope, project string, force, release bool) (AliasSelection, error) {
	if err := scope.validate(); err != nil {
		return AliasSelection{}, err
	}
	if !filepath.IsAbs(project) || filepath.Clean(project) != project || strings.ContainsRune(project, '\x00') {
		return AliasSelection{}, errors.New("invalid selected worktree project")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return AliasSelection{}, err
	}
	defer tx.Rollback()
	queries, now := clientstatedb.New(tx), d.now().UTC().UnixNano()
	key := scope.query()
	row, err := queries.LockAliasSelection(ctx, clientstatedb.LockAliasSelectionParams(key))
	if errors.Is(err, sql.ErrNoRows) {
		return AliasSelection{}, ErrAliasNotFound
	}
	if err != nil {
		return AliasSelection{}, err
	}
	if release {
		if row.SelectedProject != project {
			return AliasSelection{}, ErrAliasNotSelected
		}
		project = row.ProjectKey
	} else {
		if _, err := queries.ReadyAliasReceiver(ctx, clientstatedb.ReadyAliasReceiverParams{AliasID: row.ID, ProjectRoot: project, Now: now}); errors.Is(err, sql.ErrNoRows) {
			return AliasSelection{}, ErrAliasReceiverUnavailable
		} else if err != nil {
			return AliasSelection{}, err
		}
		if row.SelectedProject != project && !force {
			live, err := queries.LiveAliasOwner(ctx, clientstatedb.LiveAliasOwnerParams{AliasID: row.ID, Now: now})
			if err != nil {
				return AliasSelection{}, err
			}
			if live != 0 {
				return AliasSelection{}, ErrAliasOwned
			}
		}
	}
	if project != row.SelectedProject {
		count, err := queries.SetAliasSelectedProject(ctx, clientstatedb.SetAliasSelectedProjectParams{
			AliasID: row.ID, ProjectRoot: project, ExpectedRevision: row.SelectionRevision,
		})
		if err != nil {
			return AliasSelection{}, err
		}
		if count != 1 {
			return AliasSelection{}, ErrAliasSelectionStale
		}
		row.SelectedProject, row.SelectionRevision = project, row.SelectionRevision+1
	}
	if err := tx.Commit(); err != nil {
		return AliasSelection{}, err
	}
	return aliasSelection(row), nil
}

func aliasSelection(row clientstatedb.ProjectAlias) AliasSelection {
	var fingerprint [32]byte
	copy(fingerprint[:], row.Fingerprint)
	return AliasSelection{ID: row.ID, Scope: AliasScope{Server: row.ServerOrigin, ProjectKey: row.ProjectKey,
		TeamID: row.TeamID, MembershipID: row.MembershipID, Namespace: row.Namespace, Name: row.Name},
		Hostname: row.Hostname, Service: row.Service, Project: row.SelectedProject,
		Revision: uint64(row.SelectionRevision), Fingerprint: fingerprint}
}
