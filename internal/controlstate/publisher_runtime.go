package controlstate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/publisherprovenance"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrPublisherRuntimeStale = errors.New("publisher runtime has been replaced or stopped")
var ErrPublisherDeploymentConflict = errors.New("publisher deployment binding conflicts with the recorded replica")

type PublisherRuntimeRequest struct {
	PublisherIdentityID string
	ScopeID             string
	ProcessRunID        string
	Action              string
	Assertion           string
	Audience            string
	SourceIP            string
	ExpectedEpoch       int64
	Now                 time.Time
	Deployment          *controlv1.PublisherDeploymentReport
}

type PublisherRuntimeResponse struct {
	Epoch          int64                `json:"epoch"`
	LeaseExpiresAt *time.Time           `json:"lease_expires_at,omitempty"`
	GroupLease     *PublisherGroupLease `json:"group_lease,omitempty"`
}

type PublisherRuntimeStatus struct {
	PublisherIdentityID string                                    `json:"publisher_identity_id"`
	TeamID              string                                    `json:"team_id"`
	ProcessRunID        string                                    `json:"process_run_id"`
	Epoch               int64                                     `json:"epoch"`
	Evidence            string                                    `json:"evidence"`
	Address             string                                    `json:"address,omitempty"`
	AddressFamily       string                                    `json:"address_family"`
	StartedAt           time.Time                                 `json:"started_at"`
	ObservedAt          time.Time                                 `json:"observed_at"`
	LastSeenAt          time.Time                                 `json:"last_seen_at"`
	LeaseExpiresAt      time.Time                                 `json:"lease_expires_at"`
	StoppedAt           *time.Time                                `json:"stopped_at,omitempty"`
	Active              bool                                      `json:"active"`
	Deployment          *controlv1.PublisherDeploymentObservation `json:"deployment,omitempty"`
}

// PublisherRuntime is the sole observation writer. enrollment, key verification,
// token exchange and preflight group leases never call it.
func (d *Database) PublisherRuntime(ctx context.Context, r PublisherRuntimeRequest) (result PublisherRuntimeResponse, retErr error) {
	run, err := hex.DecodeString(r.ProcessRunID)
	if err != nil || len(run) != 16 || hex.EncodeToString(run) != r.ProcessRunID || r.ExpectedEpoch < 0 || r.ExpectedEpoch == math.MaxInt64 || (r.Action != "inspect" && r.Action != "start" && r.Action != "renew" && r.Action != "stop") {
		return result, ErrPublisherIdentity
	}
	if publisherprovenance.Validate(r.Deployment) != nil {
		return result, ErrPublisherIdentity
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "observe publisher runtime", &retErr)()
	q := controlstatedb.New(tx)
	var team string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.publisher_identities WHERE id=$1`, r.PublisherIdentityID).Scan(&team); err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	i, err := q.LockPublisherIdentity(ctx, r.PublisherIdentityID)
	if err != nil {
		return result, err
	}
	if i.RevokedAt.Valid || i.Kind == "guest" {
		return result, ErrPublisherIdentity
	}
	var group, groupKey string
	err = tx.QueryRow(ctx, `SELECT m.group_id,m.key_id FROM control.publisher_group_members m JOIN control.project_publisher_groups g ON g.id=m.group_id WHERE m.publisher_identity_id=$1 AND g.deleted_at IS NULL AND g.team_id=$2 AND control.active_publisher(m.publisher_identity_id,$3)`, i.ID, team, r.Now).Scan(&group, &groupKey)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if group != "" {
		if group != r.ScopeID {
			return result, ErrPublisherIdentity
		}
	} else {
		if r.Deployment != nil {
			return result, ErrPublisherIdentity
		}
		if _, _, err = d.livePublisher(ctx, q, i.ID, r.ScopeID, "", r.Now); err != nil {
			return result, err
		}
	}
	kid, err := publisheridentity.KeyID(r.Assertion)
	if err != nil {
		return result, ErrPublisherIdentity
	}
	k, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: kid, PublisherIdentityID: i.ID})
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherIdentity)
	}
	if k.RetiredAt.Valid || group != "" && groupKey != kid {
		return result, ErrPublisherIdentity
	}
	a, err := publisheridentity.Verify(r.Assertion, i.ID, kid, publisheridentity.RuntimeScope(r.ScopeID, r.Action, r.ProcessRunID, r.ExpectedEpoch, publisherprovenance.Digest(r.Deployment)), r.Audience, k.PublicKey, r.Now)
	if err != nil {
		return result, ErrPublisherIdentity
	}
	if err = q.PrunePublisherAssertions(ctx, controlstatedb.PrunePublisherAssertionsParams{PublisherIdentityID: i.ID, Now: timestamptz(r.Now)}); err != nil {
		return result, err
	}
	claimed, err := q.ClaimPublisherAssertion(ctx, controlstatedb.ClaimPublisherAssertionParams{PublisherIdentityID: i.ID, AssertionID: a.ID, ExpiresAt: timestamptz(a.Until)})
	if err != nil {
		return result, err
	}
	if claimed != 1 {
		return result, ErrPublisherIdentity
	}
	current, err := q.GetPublisherRuntime(ctx, i.ID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	result.Epoch = current.Epoch
	if r.Action == "inspect" {
		return result, tx.Commit(ctx)
	}
	var previous *controlv1.PublisherDeploymentReport
	if len(current.DeploymentReport) != 0 {
		previous = &controlv1.PublisherDeploymentReport{}
		if err := json.Unmarshal(current.DeploymentReport, previous); err != nil {
			return result, err
		}
		if !publisherprovenance.SameBinding(previous, r.Deployment) {
			return result, ErrPublisherDeploymentConflict
		}
	}
	// a fresh process may report new software/template bytes. renewal and lost
	// start replies must preserve the complete report originally accepted.
	if r.Action != "start" || current.ProcessRunID == r.ProcessRunID {
		if publisherprovenance.Digest(previous) != publisherprovenance.Digest(r.Deployment) {
			return result, ErrPublisherDeploymentConflict
		}
	}
	var deploymentJSON []byte
	var deploymentGroup pgtype.Text
	var deploymentFirst pgtype.Timestamptz
	if r.Deployment != nil {
		deploymentJSON, err = json.Marshal(r.Deployment)
		if err != nil {
			return result, err
		}
		deploymentGroup = nullableText(group)
		deploymentFirst = timestamptz(r.Now)
	}
	address, family := publicPublisherAddress(r.SourceIP)
	until := r.Now.Add(PublisherGroupLeaseLifetime)
	if r.Action == "start" {
		if current.ProcessRunID == r.ProcessRunID && current.Epoch == r.ExpectedEpoch+1 && current.ScopeID == r.ScopeID && current.KeyID == kid && !current.StoppedAt.Valid {
			// a fresh one-use proof may recover a lost start reply. it must not
			// change the original observation or extend an expired lease.
		} else {
			if current.Epoch != r.ExpectedEpoch || current.ProcessRunID == r.ProcessRunID {
				return result, ErrPublisherRuntimeStale
			}
			current, err = q.StartPublisherRuntime(ctx, controlstatedb.StartPublisherRuntimeParams{PublisherIdentityID: i.ID, TeamID: team, KeyID: kid, ScopeID: r.ScopeID, ProcessRunID: r.ProcessRunID, Epoch: r.ExpectedEpoch + 1, Address: nullableText(address), AddressFamily: family, Now: timestamptz(r.Now), LeaseExpiresAt: timestamptz(until), DeploymentReport: deploymentJSON, DeploymentGroupID: deploymentGroup, DeploymentFirstObservedAt: deploymentFirst})
		}
	} else {
		if current.ProcessRunID != r.ProcessRunID || current.Epoch != r.ExpectedEpoch || current.ScopeID != r.ScopeID || current.KeyID != kid || r.Action == "renew" && current.StoppedAt.Valid {
			return result, ErrPublisherRuntimeStale
		}
		if r.Action == "renew" {
			current, err = q.RenewPublisherRuntime(ctx, controlstatedb.RenewPublisherRuntimeParams{PublisherIdentityID: i.ID, ProcessRunID: r.ProcessRunID, Epoch: r.ExpectedEpoch, Address: nullableText(address), AddressFamily: family, Now: timestamptz(r.Now), LeaseExpiresAt: timestamptz(until)})
		} else {
			current, err = q.StopPublisherRuntime(ctx, controlstatedb.StopPublisherRuntimeParams{PublisherIdentityID: i.ID, ProcessRunID: r.ProcessRunID, Epoch: r.ExpectedEpoch, Now: timestamptz(r.Now)})
		}
	}
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" && pgError.ConstraintName == "publisher_runtime_deployment_replica" {
			return result, ErrPublisherDeploymentConflict
		}
		return result, err
	}
	result.Epoch, result.LeaseExpiresAt = current.Epoch, &current.LeaseExpiresAt.Time
	if group != "" {
		if r.Action == "stop" {
			_, err = tx.Exec(ctx, `DELETE FROM control.publisher_group_leases WHERE publisher_identity_id=$1`, i.ID)
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE control.publisher_group_members SET lease_expires_at=$2,healthy=false WHERE publisher_identity_id=$1`, i.ID, r.Now)
			}
		} else {
			lease, leaseErr := issuePublisherGroupLease(ctx, tx, i.ID, kid, current.LeaseExpiresAt.Time)
			result.GroupLease, err = &lease, leaseErr
		}
		if err != nil {
			return result, err
		}
	}
	return result, tx.Commit(ctx)
}

func publisherRuntimeStatus(ctx context.Context, q *controlstatedb.Queries, id string, now time.Time) (*PublisherRuntimeStatus, error) {
	r, err := q.GetPublisherRuntime(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	active, err := q.PublisherRuntimeActive(ctx, controlstatedb.PublisherRuntimeActiveParams{PublisherIdentityID: id, ProcessRunID: r.ProcessRunID, Epoch: r.Epoch, Now: timestamptz(now)})
	if err != nil {
		return nil, err
	}
	s := &PublisherRuntimeStatus{PublisherIdentityID: id, TeamID: r.TeamID, ProcessRunID: r.ProcessRunID, Epoch: r.Epoch, Evidence: r.Evidence, Address: r.Address.String, AddressFamily: r.AddressFamily, StartedAt: r.StartedAt.Time, ObservedAt: r.ObservedAt.Time, LastSeenAt: r.LastSeenAt.Time, LeaseExpiresAt: r.LeaseExpiresAt.Time, Active: active}
	if len(r.DeploymentReport) != 0 {
		var report controlv1.PublisherDeploymentReport
		if err := json.Unmarshal(r.DeploymentReport, &report); err != nil {
			return nil, err
		}
		s.Deployment = &controlv1.PublisherDeploymentObservation{Report: report, GroupId: r.DeploymentGroupID.String, Evidence: "publisher_reported", FirstObservedAt: r.DeploymentFirstObservedAt.Time, ObservedAt: r.LastSeenAt.Time}
	}
	if r.StoppedAt.Valid {
		s.StoppedAt = &r.StoppedAt.Time
	}
	return s, nil
}
