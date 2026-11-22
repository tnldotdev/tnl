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

type policyConfirmations struct {
	canonical, alias *controlv1.PublisherPolicyConfirmation
}

// the caller has authenticated and locked this exact run. the snapshot read
// and the renewal use the same eligibility check. if time can change a parent
// permission, only a new full read can establish its current value.
func (d *Database) policyConfirmations(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (result policyConfirmations, err error) {
	row, err := q.ReadPublisherPolicyConfirmation(ctx, controlstatedb.ReadPublisherPolicyConfirmationParams{
		ServiceID: run.ServiceID, RunID: run.ID, RunNumber: run.RunNumber, MaxUntil: timestamptz(now.Add(d.servingTolerance())),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if !row.ValidUntil.Valid || !row.ValidUntil.Time.After(now) {
		return result, nil
	}
	// include process-local inputs to IP policy and encrypted configuration,
	// and bind the observation to the run. a watch bookmark is not this key.
	confirm := func(hostname string) *controlv1.PublisherPolicyConfirmation {
		h := sha256.Sum256([]byte(strings.Join([]string{"publisher-policy-confirmation-v1", run.ID, hostname, row.Bookmark, row.Issuer, d.storageKey.CurrentID(), d.storageKey.PreviousID()}, "\x00")))
		return &controlv1.PublisherPolicyConfirmation{ConfirmationKey: hex.EncodeToString(h[:]), Hostname: hostname, ObservedAt: now, ValidUntil: row.ValidUntil.Time}
	}
	result.canonical = confirm(row.CertificateHostname)
	if row.AliasHostname != "" {
		result.alias = confirm(row.AliasHostname)
	}
	return result, nil
}

func (p policyConfirmations) forHost(hostname string) *controlv1.PublisherPolicyConfirmation {
	if p.canonical != nil && p.canonical.Hostname == hostname {
		return p.canonical
	}
	if p.alias != nil && p.alias.Hostname == hostname {
		return p.alias
	}
	return nil
}
