package controlstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

var ErrDNSChallengeNotFound = errors.New("controlstate: DNS challenge not found")

type DNSChallengeContext struct {
	RouteID               string
	TeamID                string
	DomainID              string
	DNSAuthorityReference string
	CanonicalDomain       string
	AuthorizationID       string
	Identifier            string
	PresentationReference string
	State                 string
	ChallengeDigest       [32]byte
	Presentations         []DNSChallengePresentation
}

type DNSChallengePresentation struct {
	ChallengeDigest [32]byte
	Active          bool
}

func (d *Database) GetDNSChallengeContext(
	ctx context.Context,
	routeID, authorizationID string,
) (DNSChallengeContext, error) {
	if !validStateText(routeID) || !validStateText(authorizationID) {
		return DNSChallengeContext{}, ErrDNSChallengeNotFound
	}
	if err := d.requireOpen(); err != nil {
		return DNSChallengeContext{}, err
	}
	queries := controlstatedb.New(d.pool)
	row, err := queries.GetDNSChallengeContext(ctx, controlstatedb.GetDNSChallengeContextParams{
		RouteID: routeID, AuthorizationID: authorizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DNSChallengeContext{}, ErrDNSChallengeNotFound
	}
	if err != nil {
		return DNSChallengeContext{}, fmt.Errorf("controlstate: get DNS challenge context: %w", err)
	}
	baseIdentifier := strings.TrimPrefix(row.Identifier, "*.")
	canonical, err := naming.CanonicalizeHostname(baseIdentifier)
	if err != nil || canonical != baseIdentifier || len(row.ChallengeDigest) != 32 ||
		!validStateText(row.PresentationReference.String) ||
		row.CanonicalDomain != "" && !hostnameWithin(baseIdentifier, row.CanonicalDomain) ||
		row.CanonicalHostname != baseIdentifier && !strings.HasSuffix(row.CanonicalHostname, "."+baseIdentifier) {
		return DNSChallengeContext{}, errors.New("controlstate: invalid DNS challenge context row")
	}
	presentations, err := queries.ListDNSChallengePresentations(ctx, baseIdentifier)
	if err != nil {
		return DNSChallengeContext{}, fmt.Errorf("controlstate: list DNS challenge presentations: %w", err)
	}
	result := DNSChallengeContext{
		RouteID: row.RouteID, TeamID: row.TeamID, DomainID: row.DomainID,
		DNSAuthorityReference: row.DnsAuthorityReference.String, CanonicalDomain: row.CanonicalDomain,
		AuthorizationID: row.AuthorizationID, Identifier: row.Identifier,
		PresentationReference: row.PresentationReference.String, State: row.State,
		Presentations: make([]DNSChallengePresentation, len(presentations)),
	}
	copy(result.ChallengeDigest[:], row.ChallengeDigest)
	for index, presentation := range presentations {
		if len(presentation.ChallengeDigest) != 32 {
			return DNSChallengeContext{}, errors.New("controlstate: invalid DNS challenge presentation row")
		}
		copy(result.Presentations[index].ChallengeDigest[:], presentation.ChallengeDigest)
		result.Presentations[index].Active = presentation.State == "presenting" || presentation.State == "presented" ||
			presentation.State == "validating" || presentation.State == "valid"
	}
	return result, nil
}

// WithDNSChallengeLock serializes the durable snapshot and DNS update for one
// TXT name across control processes. A transaction lock also works with pooled
// PostgreSQL connections and is released on cancellation or connection loss.
func (d *Database) WithDNSChallengeLock(ctx context.Context, recordName string, run func() error) (retErr error) {
	base := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(recordName), "."), "_acme-challenge.")
	if canonical, err := naming.CanonicalizeHostname(base); err != nil || canonical != base || run == nil {
		return errors.New("controlstate: invalid DNS challenge lock")
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	// The callback reads through d.pool. Waiting for locks must not exhaust that
	// pool and deadlock those reads, including when pool_max_conns is one.
	connection, err := pgx.ConnectConfig(ctx, d.pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("controlstate: connect DNS challenge lock: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, connection.Close(closeCtx))
	}()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: begin DNS challenge lock: %w", err)
	}
	defer rollback(ctx, tx, "DNS challenge lock", &retErr)()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "tnl:dns-challenge:"+base); err != nil {
		return fmt.Errorf("controlstate: lock DNS challenge: %w", err)
	}
	return run()
}
