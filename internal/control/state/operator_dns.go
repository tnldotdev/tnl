package state

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming"
)

// ReserveOperatorNameservers keeps infrastructure names out of customer
// domains and endpoint bindings, even after the operator changes the default.
func (d *Database) ReserveOperatorNameservers(ctx context.Context, domain, setID string) (retErr error) {
	names, err := naming.BrandedNameservers(domain)
	if err != nil {
		return err
	}
	if !naming.ValidDelegationSetID(setID) {
		return ErrAuthorityInvalid
	}
	var allReserved bool
	const reserved = `SELECT count(*) = cardinality($1::text[]) FROM control.operator_nameserver_hostnames
		WHERE hostname=ANY($1) AND delegation_set_id=$2`
	if err := d.pool.QueryRow(ctx, reserved, names, setID).Scan(&allReserved); err != nil || allReserved {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "reserve operator nameservers", &retErr)()
	// claims and endpoint triggers join these exact names. unrelated domains
	// and endpoint writes can proceed while a reservation is being installed.
	for _, name := range names {
		if _, err := tx.Exec(ctx, `SELECT control.lock_dns_claim_name($1,true)`, name); err != nil {
			return err
		}
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM unnest($1::text[]) names(hostname)
		JOIN control.domains domain ON domain.kind='custom' AND domain.released_at IS NULL
		    AND (domain.canonical_domain=names.hostname
		        OR right(domain.canonical_domain,length(names.hostname)+1)='.'||names.hostname
		        OR right(names.hostname,length(domain.canonical_domain)+1)='.'||domain.canonical_domain)
		UNION ALL
		SELECT 1 FROM unnest($1::text[]) names(hostname)
		JOIN control.service_endpoints endpoint ON endpoint.hostname=names.hostname
		WHERE endpoint.retired_at IS NULL OR endpoint.dns_state NOT IN ('unmanaged','removed')
	)`, names).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return errors.New("nameserver hostnames overlap a saved custom domain or service endpoint")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO control.operator_nameserver_hostnames (hostname,delegation_set_id)
		SELECT unnest($1::text[]),$2 ON CONFLICT DO NOTHING`, names, setID); err != nil {
		return fmt.Errorf("save nameserver reservations: %w", err)
	}
	if err := tx.QueryRow(ctx, reserved, names, setID).Scan(&allReserved); err != nil {
		return err
	}
	if !allReserved {
		return errors.New("nameserver hostnames already use a different Route 53 delegation set; choose a new nameserver domain")
	}
	return tx.Commit(ctx)
}
