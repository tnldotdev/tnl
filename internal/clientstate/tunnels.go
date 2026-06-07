package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
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
	Command TunnelCommand
	Server  string
	Target  string
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
	ID             string        `json:"tunnel_id"`
	Command        TunnelCommand `json:"command"`
	State          TunnelState   `json:"state"`
	ProcessID      int           `json:"process_id"`
	Server         string        `json:"server"`
	RouteID        string        `json:"route_id,omitempty"`
	RouteVersion   uint64        `json:"route_version,omitempty"`
	Hostname       string        `json:"hostname,omitempty"`
	PublicURL      string        `json:"public_url,omitempty"`
	Target         string        `json:"target,omitempty"`
	Framework      string        `json:"framework,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
	HeartbeatAt    time.Time     `json:"heartbeat_at"`
	LeaseExpiresAt time.Time     `json:"lease_expires_at"`
}

// BeginTunnel registers a local tunnel and maintains its liveness lease until Finish.
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
		Target: options.Target, Now: now.UnixNano(), LeaseExpiresAt: now.Add(tunnelLeaseDuration).UnixNano(),
	}); err != nil {
		return nil, fmt.Errorf("clientstate: begin tunnel: %w", err)
	}
	leaseCtx, cancel := context.WithCancelCause(ctx)
	tunnel := &Tunnel{database: d, id: id, ctx: leaseCtx, cancel: cancel, done: make(chan struct{})}
	go tunnel.heartbeat(leaseCtx)
	return tunnel, nil
}

func (t *Tunnel) ID() string { return t.id }

// Context is canceled if the parent context ends or the tunnel lease cannot be maintained.
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

func (t *Tunnel) SetRoute(ctx context.Context, routeID, hostname string) error {
	hostname, err := naming.CanonicalizeHostname(hostname)
	if err != nil || !validRouteID(routeID) {
		return errors.New("clientstate: invalid tunnel route")
	}
	rows, err := t.database.queries.SetTunnelRoute(ctx, clientstatedb.SetTunnelRouteParams{
		RouteID: routeID, Hostname: hostname, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetProvisioning(ctx context.Context, routeVersion uint64) error {
	versionValue, err := databaseVersion(routeVersion)
	if err != nil || routeVersion == 0 {
		return errors.New("clientstate: invalid tunnel route version")
	}
	rows, err := t.database.queries.SetTunnelProvisioning(ctx, clientstatedb.SetTunnelProvisioningParams{
		RouteVersion: versionValue, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetReady(ctx context.Context, publicURL string, routeVersion uint64) error {
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("clientstate: invalid tunnel public URL")
	}
	hostname, err := naming.CanonicalizeHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Hostname() {
		return errors.New("clientstate: invalid tunnel public URL")
	}
	versionValue, err := databaseVersion(routeVersion)
	if err != nil || routeVersion == 0 {
		return errors.New("clientstate: invalid tunnel route version")
	}
	rows, err := t.database.queries.SetTunnelReady(ctx, clientstatedb.SetTunnelReadyParams{
		Hostname: hostname, RouteVersion: versionValue, Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

func (t *Tunnel) SetDraining(ctx context.Context) error {
	rows, err := t.database.queries.SetTunnelDraining(ctx, clientstatedb.SetTunnelDrainingParams{
		Now: t.database.now().UTC().UnixNano(), ID: t.id,
	})
	return tunnelUpdateResult(rows, err)
}

// Finish stops lease maintenance and records a terminal state.
func (t *Tunnel) Finish(ctx context.Context, runErr error) error {
	t.finishOnce.Do(func() {
		t.cancel(nil)
		<-t.done
		state, message := TunnelStateStopped, ""
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			state, message = TunnelStateFailed, runErr.Error()
			if len(message) > 1024 {
				message = message[:1024]
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
	observedAt := d.now().UTC()
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: begin tunnel snapshot: %w", err)
	}
	defer tx.Rollback()
	rows, err := d.queries.WithTx(tx).ListOpenTunnels(ctx)
	if err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: list tunnels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TunnelSnapshot{}, fmt.Errorf("clientstate: commit tunnel snapshot: %w", err)
	}
	snapshot := TunnelSnapshot{
		SchemaVersion: tunnelSnapshotSchemaVersion,
		ObservedAt:    observedAt,
		Tunnels:       make([]TunnelInfo, 0, len(rows)),
	}
	for _, row := range rows {
		state := TunnelState(row.State)
		if !unixNanoTime(row.LeaseExpiresAt).After(observedAt) {
			state = TunnelStateStale
		}
		info := TunnelInfo{
			ID: row.ID, Command: TunnelCommand(row.Command), State: state, ProcessID: int(row.ProcessID),
			Server: row.ServerOrigin, RouteID: row.RouteID, RouteVersion: uint64(row.RouteVersion),
			Hostname: row.Hostname, Target: row.Target, Framework: row.Framework,
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
	id, err := opaqueid.New("tunnel_")
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
