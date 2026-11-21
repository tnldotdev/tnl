package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the caller has authenticated and locked this exact run. the snapshot read
// and the renewal use the same eligibility check. if time can change a parent
// permission, only a new full read can establish its current value.
func (d *Database) policyConfirmation(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (*controlv1.PublisherPolicyConfirmation, error) {
	row, err := q.ReadPublisherPolicyConfirmation(ctx, controlstatedb.ReadPublisherPolicyConfirmationParams{
		ServiceID: run.ServiceID, RunID: run.ID, RunNumber: run.RunNumber, MaxUntil: timestamptz(now.Add(d.servingTolerance())),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !row.ValidUntil.Valid || !row.ValidUntil.Time.After(now) {
		return nil, nil
	}
	// include process-local inputs to IP policy and encrypted configuration,
	// and bind the observation to the run. a watch bookmark is not this key.
	h := sha256.Sum256([]byte(strings.Join([]string{"publisher-policy-confirmation-v1", run.ID, row.CertificateHostname, row.Bookmark, row.Issuer, d.storageKey.CurrentID(), d.storageKey.PreviousID()}, "\x00")))
	return &controlv1.PublisherPolicyConfirmation{ConfirmationKey: hex.EncodeToString(h[:]), Hostname: row.CertificateHostname, ObservedAt: now, ValidUntil: row.ValidUntil.Time}, nil
}
