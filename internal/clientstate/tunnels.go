package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const tunnelSnapshotSchemaVersion = 1

const (
	tunnelLeaseDuration     = 20 * time.Second
	tunnelHeartbeatInterval = 5 * time.Second
	tunnelTerminalRetention = 24 * time.Hour
	tunnelStaleRetention    = 7 * 24 * time.Hour
)

type TunnelCommand string

const (
	TunnelCommandPublish TunnelCommand = "publish"
	TunnelCommandDev     TunnelCommand = "dev"
)

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
	Project          string
	Service          string
	IntegrationGroup string
}

// Tunnel is the write handle for one local publish or dev invocation.
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
	SchemaVersion int           `json:"schema_version"`
	ObservedAt    time.Time     `json:"observed_at"`
	Summary       TunnelSummary `json:"summary"`
	Tunnels       []TunnelInfo  `json:"tunnels"`
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
	ID               string        `json:"tunnel_id"`
	Command          TunnelCommand `json:"command"`
	State            TunnelState   `json:"state"`
	ProcessID        int           `json:"process_id"`
	Server           string        `json:"server"`
	Project          string        `json:"project"`
	Service          string        `json:"service,omitempty"`
	PublicURLID      string        `json:"public_url_id,omitempty"`
	PublishRunNumber uint64        `json:"publish_run_number,omitempty"`
	Hostname         string        `json:"hostname,omitempty"`
	PublicURL        string        `json:"public_url,omitempty"`
	Target           string        `json:"target,omitempty"`
	Framework        string        `json:"framework,omitempty"`
	IntegrationGroup string        `json:"-"`
	StartedAt        time.Time     `json:"started_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
	HeartbeatAt      time.Time     `json:"heartbeat_at"`
	LeaseExpiresAt   time.Time     `json:"lease_expires_at"`
}

// BeginTunnel registers a local tunnel and maintains its liveness lease until
// Finish joins the heartbeat worker.
func (d *Database) BeginTunnel(ctx context.Context, options BeginTunnelOptions) (*Tunnel, error) {
	if options.Command != TunnelCommandPublish && options.Command != TunnelCommandDev {
		return nil, errors.New("clientstate: invalid tunnel command")
	}
	server, err := CanonicalServer(options.Server)
	if err != nil {
		return nil, err
	}
	if options.Target != "" {
		options.Target, err = localproxy.NormalizeTarget(options.Target)
		if err != nil {
			return nil, err
		}
	} else if options.Command != TunnelCommandDev {
		return nil, errors.New("clientstate: publish tunnel target is required")
	}
	if options.Project == "" || !filepath.IsAbs(options.Project) {
		return nil, errors.New("clientstate: absolute tunnel project path is required")
	}
	options.Project = filepath.Clean(options.Project)
	if options.Service != "" && !naming.ValidServiceName(options.Service) {
		return nil, errors.New("clientstate: invalid tunnel service")
	}
	if len(options.IntegrationGroup) > 1024 {
		return nil, failure.Wrap("validate integration URL group", failure.ProjectConfigInvalid, errors.New("integration group exceeds limit"))
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
		ProjectRoot: options.Project, Service: options.Service, Target: options.Target,
		Now: now.UnixNano(), LeaseExpiresAt: now.Add(tunnelLeaseDuration).UnixNano(), IntegrationGroup: options.IntegrationGroup,
	}); err != nil {
		return nil, fmt.Errorf("clientstate: begin tunnel: %w", err)
	}
	leaseCtx, cancel := context.WithCancelCause(ctx)
	tunnel := &Tunnel{database: d, id: id, ctx: leaseCtx, cancel: cancel, done: make(chan struct{})}
	go tunnel.heartbeat(leaseCtx)
	return tunnel, nil
}

func (t *Tunnel) ID() string { return t.id }

// SetIntegrationGroup joins this tunnel to its machine-local project group.
func (t *Tunnel) SetIntegrationGroup(ctx context.Context, group string) error {
	if group == "" || len(group) > 1024 {
		return failure.Wrap("validate integration URL group", failure.ProjectConfigInvalid, errors.New("group must be nonempty and within 1024 bytes"))
	}
	count, err := t.database.queries.SetTunnelIntegrationGroup(ctx, clientstatedb.SetTunnelIntegrationGroupParams{
		IntegrationGroup: group, TunnelID: t.id,
	})
	if err != nil {
		return failure.Wrap("register integration URL group", failure.ClientStateUnavailable, err)
	}
	if count != 1 {
		return failure.Wrap("register integration URL group", failure.ClientStateUnavailable, errors.New("tunnel stopped before registration"))
	}
	return nil
}

// Context is canceled if the parent ends or a failed heartbeat leaves the
// tunnel's local lease unmaintained.
func (t *Tunnel) Context() context.Context { return t.ctx }

func (t *Tunnel) SetDevTarget(ctx context.Context, framework, target string) error {
	target, err := localproxy.NormalizeTarget(target)
	if err != nil {
		return err
	}
	if !validFramework(framework) {
		return errors.New("clientstate: invalid tunnel framework")
	}
	rows, err := t.database.queries.SetTunnelDevTarget(ctx, clientstatedb.SetTunnelDevTargetParams{
		Target: target, Framework: framework, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetPublicURL(ctx context.Context, publicURLID, hostname string) error {
	hostname, err := naming.CanonicalizeHostname(hostname)
	if err != nil || !validPublicURLID(publicURLID) {
		return errors.New("clientstate: invalid tunnel route")
	}
	rows, err := t.database.queries.SetTunnelPublicURL(ctx, clientstatedb.SetTunnelPublicURLParams{
		PublicURLID: publicURLID, Hostname: hostname, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetProvisioning(ctx context.Context, publishRunNumber uint64) error {
	versionValue, err := databaseVersion(publishRunNumber)
	if err != nil || publishRunNumber == 0 {
		return errors.New("clientstate: invalid tunnel publish run number")
	}
	rows, err := t.database.queries.SetTunnelProvisioning(ctx, clientstatedb.SetTunnelProvisioningParams{
		PublishRunNumber: versionValue, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetReady(ctx context.Context, publicURL string, publishRunNumber uint64) error {
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("clientstate: invalid tunnel public URL")
	}
	hostname, err := naming.CanonicalizeHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Hostname() {
		return errors.New("clientstate: invalid tunnel public URL")
	}
	versionValue, err := databaseVersion(publishRunNumber)
	if err != nil || publishRunNumber == 0 {
		return errors.New("clientstate: invalid tunnel publish run number")
	}
	rows, err := t.database.queries.SetTunnelReady(ctx, clientstatedb.SetTunnelReadyParams{
		Hostname: hostname, PublishRunNumber: versionValue, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
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
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			state, message = TunnelStateFailed, string(failure.Unexpected)
			if reason, _, ok := failure.Describe(runErr); ok {
				message = string(reason)
			}
		}
		now := t.database.now().UTC().UnixNano()
		rows, err := t.database.queries.FinishTunnel(ctx, clientstatedb.FinishTunnelParams{
			State: string(state), LastError: message, Now: now, ID: t.id,
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
	if err := tx.Commit(); err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: commit tunnel snapshot: %w", err)
	}
	snapshot := TunnelSnapshot{
		SchemaVersion: tunnelSnapshotSchemaVersion,
		ObservedAt:    observedAt,
		Tunnels:       make([]TunnelInfo, 0, len(records)),
	}
	for _, row := range records {
		state := TunnelState(row.State)
		if !unixNanoTime(row.LeaseExpiresAt).After(observedAt) {
			state = TunnelStateStale
		}
		info := TunnelInfo{
			ID: row.ID, Command: TunnelCommand(row.Command), State: state, ProcessID: int(row.ProcessID),
			Server: row.ServerOrigin, Project: row.ProjectRoot, Service: row.Service,
			PublicURLID: row.PublicURLID, PublishRunNumber: uint64(row.PublishRunNumber),
			Hostname: row.Hostname, Target: row.Target, Framework: row.Framework, IntegrationGroup: row.IntegrationGroup,
			StartedAt: unixNanoTime(row.StartedAt), UpdatedAt: unixNanoTime(row.UpdatedAt),
			HeartbeatAt: unixNanoTime(row.HeartbeatAt), LeaseExpiresAt: unixNanoTime(row.LeaseExpiresAt),
		}
		if info.Hostname != "" {
			info.PublicURL = "https://" + info.Hostname
		}
		snapshot.Tunnels = append(snapshot.Tunnels, info)
		snapshot.Summary.Total++
		switch state {
		case TunnelStateStarting:
			snapshot.Summary.Starting++
		case TunnelStateProvisioning:
			snapshot.Summary.Provisioning++
		case TunnelStateReady:
			snapshot.Summary.Ready++
		case TunnelStateDraining:
			snapshot.Summary.Draining++
		case TunnelStateStale:
			snapshot.Summary.Stale++
		}
	}
	return snapshot, nil
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

func validFramework(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}
