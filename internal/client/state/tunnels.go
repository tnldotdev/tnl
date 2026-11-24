package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const tunnelSnapshotSchemaVersion = 1

const (
	tunnelLeaseDuration     = 20 * time.Second
	tunnelHeartbeatInterval = 5 * time.Second
	tunnelTerminalRetention = 24 * time.Hour
	tunnelStaleRetention    = 7 * 24 * time.Hour
)

type TunnelCommand string

const TunnelCommandPublish TunnelCommand = "publish"

type TunnelState string

const (
	TunnelStateStarting     TunnelState = "starting"
	TunnelStateProvisioning TunnelState = "provisioning"
	TunnelStateReady        TunnelState = "ready"
	TunnelStateDraining     TunnelState = "draining"
	TunnelStateStopped      TunnelState = "stopped"
	TunnelStateFailed       TunnelState = "failed"
	TunnelStateStale        TunnelState = "stale"
)

type BeginTunnelOptions struct {
	Command          TunnelCommand
	Server           string
	Target           string
	ServiceProtocol  controlv1.ServiceProtocol
	Project          string
	Service          string
	ServiceID        string
	IntegrationScope IntegrationScope
}

// Tunnel is the write handle for one local publication.
type Tunnel struct {
	database *Database
	id       string
	ctx      context.Context
	cancel   context.CancelCauseFunc
	done     chan struct{}

	finishOnce sync.Once
	finishErr  error
}

type TunnelSnapshot struct {
	SchemaVersion   int                  `json:"schema_version"`
	ObservedAt      time.Time            `json:"observed_at"`
	Summary         TunnelSummary        `json:"summary"`
	Tunnels         []TunnelInfo         `json:"tunnels"`
	IntegrationURLs []IntegrationURLInfo `json:"integration_urls"`
	Aliases         []AliasInfo          `json:"aliases"`
}

type TunnelSummary struct {
	Total        int `json:"total"`
	Starting     int `json:"starting"`
	Provisioning int `json:"provisioning"`
	Ready        int `json:"ready"`
	Draining     int `json:"draining"`
	Stale        int `json:"stale"`
}

type TunnelInfo struct {
	ID               string                    `json:"tunnel_id"`
	Command          TunnelCommand             `json:"command"`
	State            TunnelState               `json:"state"`
	ProcessID        int                       `json:"process_id"`
	Server           string                    `json:"server"`
	Project          string                    `json:"project"`
	Service          string                    `json:"service,omitempty"`
	ServiceProtocol  controlv1.ServiceProtocol `json:"service_protocol,omitempty"`
	ServiceID        string                    `json:"service_id,omitempty"`
	PublishRunNumber uint64                    `json:"publish_run_number,omitempty"`
	ServiceRunID     string                    `json:"service_run_id,omitempty"`
	RunHostname      string                    `json:"run_hostname,omitempty"`
	Hostname         string                    `json:"hostname,omitempty"`
	PublicURL        string                    `json:"public_url,omitempty"`
	Target           string                    `json:"target,omitempty"`
	Framework        string                    `json:"framework,omitempty"`
	IntegrationScope IntegrationScope          `json:"-"`
	StartedAt        time.Time                 `json:"started_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
	HeartbeatAt      time.Time                 `json:"heartbeat_at"`
	LeaseExpiresAt   time.Time                 `json:"lease_expires_at"`
	Failure          string                    `json:"failure,omitempty"`
}

// BeginTunnel registers a local tunnel and maintains its liveness lease until
// Finish joins the heartbeat worker.
func (d *Database) BeginTunnel(ctx context.Context, options BeginTunnelOptions) (*Tunnel, error) {
	if options.Command != TunnelCommandPublish {
		return nil, errors.New("clientstate: invalid tunnel command")
	}
	server, err := CanonicalServer(options.Server)
	if err != nil {
		return nil, err
	}
	protocol := options.ServiceProtocol
	if protocol == "" {
		protocol = controlv1.ServiceProtocolHTTP
	}
	if !protocol.Valid() {
		return nil, errors.New("clientstate: invalid tunnel service protocol")
	}
	if options.ServiceID != "" && !opaqueid.Valid(options.ServiceID, opaqueid.ServicePrefix) {
		return nil, errors.New("clientstate: invalid publication service ID")
	}
	options.ServiceProtocol = protocol
	if options.Target != "" {
		if protocol == controlv1.ServiceProtocolHTTP || protocol == controlv1.Kubernetes {
			options.Target, err = targetsyntax.NormalizeTarget(options.Target)
		} else {
			options.Target, err = tcptarget.Normalize(options.Target)
		}
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("clientstate: publish tunnel target is required")
	}
	if options.Project == "" || !filepath.IsAbs(options.Project) {
		return nil, errors.New("clientstate: absolute tunnel project path is required")
	}
	options.Project = filepath.Clean(options.Project)
	if options.Service != "" && !naming.ValidServiceName(options.Service) {
		return nil, errors.New("clientstate: invalid tunnel service")
	}
	if !options.IntegrationScope.IsZero() {
		if err := options.IntegrationScope.Validate(); err != nil {
			return nil, err
		}
	}
	if _, err := d.Server(ctx, server); err != nil {
		return nil, err
	}
	now := d.now().UTC()
	if err := d.queries.DeleteOldTunnels(ctx, clientstatedb.DeleteOldTunnelsParams{
		TerminalBefore: sql.NullInt64{Int64: now.Add(-tunnelTerminalRetention).UnixNano(), Valid: true},
		StaleBefore:    now.Add(-tunnelStaleRetention).UnixNano(),
	}); err != nil {
		return nil, fmt.Errorf("clientstate: clean old tunnels: %w", err)
	}
	id, err := newTunnelID()
	if err != nil {
		return nil, err
	}
	if err := d.queries.InsertTunnel(ctx, clientstatedb.InsertTunnelParams{
		ID: id, Command: string(options.Command), ProcessID: int64(os.Getpid()), ServerOrigin: server,
		ProjectRoot: options.Project, Service: options.Service, ServiceProtocol: string(options.ServiceProtocol), Target: options.Target,
		ServiceID: sql.NullString{String: options.ServiceID, Valid: options.ServiceID != ""},
		Now:       now.UnixNano(), LeaseExpiresAt: now.Add(tunnelLeaseDuration).UnixNano(),
		PrimaryProjectRoot: options.IntegrationScope.primaryProjectRoot(), IntegrationNamespace: options.IntegrationScope.namespace(),
	}); err != nil {
		return nil, fmt.Errorf("clientstate: begin tunnel: %w", err)
	}
	leaseCtx, cancel := context.WithCancelCause(ctx)
	tunnel := &Tunnel{database: d, id: id, ctx: leaseCtx, cancel: cancel, done: make(chan struct{})}
	go tunnel.heartbeat(leaseCtx)
	return tunnel, nil
}

func (t *Tunnel) ID() string { return t.id }

// SetIntegrationScope joins this tunnel to its machine-local project scope.
func (t *Tunnel) SetIntegrationScope(ctx context.Context, scope IntegrationScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	count, err := t.database.queries.SetTunnelIntegrationScope(ctx, clientstatedb.SetTunnelIntegrationScopeParams{
		PrimaryProjectRoot: scope.primaryProjectRoot(), IntegrationNamespace: scope.namespace(), TunnelID: t.id,
	})
	if err != nil {
		return failure.Wrap("register integration URL scope", failure.ClientStateUnavailable, err)
	}
	if count != 1 {
		return failure.Wrap("register integration URL scope", failure.ClientStateUnavailable, errors.New("tunnel stopped before registration"))
	}
	return nil
}

// Context is canceled if the parent ends or a failed heartbeat leaves the
// tunnel's local lease unmaintained.
func (t *Tunnel) Context() context.Context { return t.ctx }

// CancelWithCause stops this tunnel when a local reporting boundary fails.
// Finish records the original cause after joining lease maintenance.
func (t *Tunnel) CancelWithCause(err error) { t.cancel(err) }

func (t *Tunnel) SetProvisioning(ctx context.Context, publishRunNumber uint64) error {
	versionValue, err := databaseVersion(publishRunNumber)
	if err != nil || publishRunNumber == 0 {
		return errors.New("clientstate: invalid tunnel publish run number")
	}
	rows, err := t.database.queries.SetTunnelProvisioning(ctx, clientstatedb.SetTunnelProvisioningParams{
		PublishRunNumber: sql.NullInt64{Int64: versionValue, Valid: true}, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

// SetServiceRun records public run metadata after its provisioning transition.
// the same run number cannot be rebound, and a later run clears the old alias.
func (t *Tunnel) SetServiceRun(ctx context.Context, id string, number uint64, hostname string) error {
	version, err := databaseVersion(number)
	if err != nil || number == 0 || !opaqueid.Valid(id, opaqueid.ServiceRunPrefix) {
		return errors.New("clientstate: invalid service run identity")
	}
	if hostname != "" {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != hostname {
			return errors.New("clientstate: invalid service run hostname")
		}
	}
	rows, err := t.database.queries.SetTunnelServiceRun(ctx, clientstatedb.SetTunnelServiceRunParams{
		ID: t.id, ServiceRunID: sql.NullString{String: id, Valid: true},
		PublishRunNumber: sql.NullInt64{Int64: version, Valid: true},
		RunHostname:      sql.NullString{String: hostname, Valid: hostname != ""},
		Now:              t.database.now().UTC().UnixNano(),
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetReady(ctx context.Context, publicURL string, publishRunNumber uint64) error {
	hostname := ""
	if publicURL != "" {
		var err error
		hostname, err = parsePublicTunnelAddress(publicURL)
		if err != nil {
			return err
		}
	}
	versionValue, err := databaseVersion(publishRunNumber)
	if err != nil || publishRunNumber == 0 {
		return errors.New("clientstate: invalid tunnel publish run number")
	}
	rows, err := t.database.queries.SetTunnelReady(ctx, clientstatedb.SetTunnelReadyParams{
		Hostname:         sql.NullString{String: hostname, Valid: hostname != ""},
		PublishRunNumber: sql.NullInt64{Int64: versionValue, Valid: true},
		Now:              t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func parsePublicTunnelAddress(address string) (string, error) {
	invalid := errors.New("clientstate: invalid tunnel public address")
	if !strings.HasPrefix(address, "https://") {
		return "", invalid
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", invalid
	}
	hostname, err := naming.CanonicalizeHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Host {
		return "", invalid
	}
	return hostname, nil
}

func (t *Tunnel) SetDraining(ctx context.Context) error {
	rows, err := t.database.queries.SetTunnelDraining(ctx, clientstatedb.SetTunnelDrainingParams{
		Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

// Finish cancels and joins lease maintenance before recording the terminal
// state so a late heartbeat cannot overwrite it.
func (t *Tunnel) Finish(ctx context.Context, runErr error) error {
	t.finishOnce.Do(func() {
		t.cancel(nil)
		<-t.done
		state, message := TunnelStateStopped, ""
		if runErr != nil && !failure.Only(runErr, context.Canceled) {
			state, message = TunnelStateFailed, string(failure.Unexpected)
			if reason, _, ok := failure.Describe(runErr); ok {
				message = string(reason)
			}
		}
		now := t.database.now().UTC().UnixNano()
		rows, err := t.database.queries.FinishTunnel(ctx, clientstatedb.FinishTunnelParams{
			State: string(state), FailureCode: message, Now: now, ID: t.id,
		})
		t.finishErr = tunnelUpdateResult(rows, err)
	})
	return t.finishErr
}

// Snapshot returns one consistent view of all nonterminal local tunnels.
func (d *Database) Snapshot(ctx context.Context) (TunnelSnapshot, error) {
	return d.snapshot(ctx, "")
}

// SnapshotProject returns one consistent view of a project's nonterminal tunnels.
func (d *Database) SnapshotProject(ctx context.Context, projectRoot string) (TunnelSnapshot, error) {
	if projectRoot == "" || !filepath.IsAbs(projectRoot) {
		return TunnelSnapshot{}, errors.New("clientstate: absolute tunnel project path is required")
	}
	return d.snapshot(ctx, filepath.Clean(projectRoot))
}

func (d *Database) snapshot(ctx context.Context, projectRoot string) (TunnelSnapshot, error) {
	observedAt := d.now().UTC()
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: begin tunnel snapshot: %w", err)
	}
	defer tx.Rollback()
	queries := clientstatedb.New(tx)
	var records []clientstatedb.LocalTunnel
	if projectRoot != "" {
		records, err = queries.ListOpenTunnelsForProject(ctx, projectRoot)
	} else {
		records, err = queries.ListOpenTunnels(ctx)
	}
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: list tunnels: %w", err)
	}
	integrationURLs, err := d.snapshotIntegrationURLs(ctx, tx, records, observedAt)
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("read integration URL status: %w", err)
	}
	aliases, err := d.snapshotAliases(ctx, tx, projectRoot, observedAt)
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("read alias status: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: commit tunnel snapshot: %w", err)
	}
	snapshot := TunnelSnapshot{
		SchemaVersion:   tunnelSnapshotSchemaVersion,
		ObservedAt:      observedAt,
		Tunnels:         make([]TunnelInfo, 0, len(records)),
		IntegrationURLs: integrationURLs,
		Aliases:         aliases,
	}
	for _, row := range records {
		info := tunnelInfo(row, observedAt)
		snapshot.Tunnels = append(snapshot.Tunnels, info)
	}
	snapshot.Summary = summarizeTunnels(snapshot.Tunnels)
	return snapshot, nil
}

// SelectService narrows a snapshot to publications, aliases and webhook endpoints
// for one named service. project-wide integration URLs have no service selector.
func (snapshot *TunnelSnapshot) SelectService(name string) {
	snapshot.Tunnels = slices.DeleteFunc(snapshot.Tunnels, func(t TunnelInfo) bool { return t.Service != name })
	snapshot.Summary = summarizeTunnels(snapshot.Tunnels)
	snapshot.Aliases = slices.DeleteFunc(snapshot.Aliases, func(a AliasInfo) bool { return a.Service != name })
	for i := range snapshot.IntegrationURLs {
		u := &snapshot.IntegrationURLs[i]
		u.Endpoints = slices.DeleteFunc(u.Endpoints, func(e WebhookEndpointInfo) bool { return e.Service != name })
	}
	snapshot.IntegrationURLs = slices.DeleteFunc(snapshot.IntegrationURLs, func(u IntegrationURLInfo) bool { return len(u.Endpoints) == 0 })
}

func summarizeTunnels(tunnels []TunnelInfo) TunnelSummary {
	summary := TunnelSummary{Total: len(tunnels)}
	for _, t := range tunnels {
		switch t.State {
		case TunnelStateStarting:
			summary.Starting++
		case TunnelStateProvisioning:
			summary.Provisioning++
		case TunnelStateReady:
			summary.Ready++
		case TunnelStateDraining:
			summary.Draining++
		case TunnelStateStale:
			summary.Stale++
		}
	}
	return summary
}

func (t *Tunnel) heartbeat(ctx context.Context) {
	defer close(t.done)
	ticker := time.NewTicker(t.database.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := t.database.now().UTC()
			rows, err := t.database.queries.HeartbeatTunnel(ctx, clientstatedb.HeartbeatTunnelParams{
				Now: now.UnixNano(), LeaseExpiresAt: now.Add(tunnelLeaseDuration).UnixNano(), ID: t.id,
			})
			if err := tunnelUpdateResult(rows, err); err != nil {
				t.cancel(fmt.Errorf("clientstate: maintain tunnel lease: %w", err))
				return
			}
		}
	}
}

func tunnelInfo(row clientstatedb.LocalTunnel, observedAt time.Time) TunnelInfo {
	state := TunnelState(row.State)
	if !row.StoppedAt.Valid && !unixNanoTime(row.LeaseExpiresAt).After(observedAt) {
		state = TunnelStateStale
	}
	info := TunnelInfo{
		ID: row.ID, Command: TunnelCommand(row.Command), State: state, ProcessID: int(row.ProcessID),
		Server: row.ServerOrigin, Project: row.ProjectRoot, Service: row.Service.String,
		ServiceProtocol: controlv1.ServiceProtocol(row.ServiceProtocol), ServiceID: row.ServiceID.String,
		PublishRunNumber: uint64(row.PublishRunNumber.Int64), ServiceRunID: row.ServiceRunID.String, RunHostname: row.RunHostname.String,
		Hostname: row.Hostname.String, Target: row.Target.String, Framework: row.Framework.String,
		IntegrationScope: IntegrationScope{PrimaryProjectRoot: row.PrimaryProjectRoot.String, Namespace: row.IntegrationNamespace.String},
		StartedAt:        unixNanoTime(row.StartedAt), UpdatedAt: unixNanoTime(row.UpdatedAt),
		HeartbeatAt: unixNanoTime(row.HeartbeatAt), LeaseExpiresAt: unixNanoTime(row.LeaseExpiresAt),
		Failure: row.FailureCode.String,
	}
	if info.Hostname != "" {
		info.PublicURL = "https://" + info.Hostname
	}
	return info
}

func newTunnelID() (string, error) {
	id, err := opaqueid.New(opaqueid.TunnelPrefix)
	if err != nil {
		return "", fmt.Errorf("clientstate: generate tunnel ID: %w", err)
	}
	return id, nil
}

func tunnelUpdateResult(rows int64, err error) error {
	if err != nil {
		return fmt.Errorf("clientstate: update tunnel: %w", err)
	}
	if rows != 1 {
		return errors.New("clientstate: tunnel is no longer active")
	}
	return nil
}
