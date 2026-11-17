package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const maximumStorageRotationBatch = 1000
const storageRotationClaimRetry = 100 * time.Millisecond

// CompleteStorageKeyRotation re-encrypts all currently claimable secrets. new
// writes always use the current key, so a successful pass cannot create more
// work for the configured previous key.
func (d *Database) CompleteStorageKeyRotation(ctx context.Context) (retErr error) {
	defer func() { retErr = storageRotationError(ctx, retErr) }()
	for {
		rotated, err := d.ReencryptStorageSecrets(ctx, maximumStorageRotationBatch)
		if err != nil {
			return err
		}
		remaining, err := d.countPreviousStorageSecrets(ctx)
		if err != nil {
			return err
		}
		if remaining == 0 {
			return nil
		}
		if rotated == 0 {
			timer := time.NewTimer(storageRotationClaimRetry)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

func storageRotationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return errors.Join(err, cause)
	}
	// pgx's socket deadline may fire before the context's timer is scheduled.
	// retain the driver error and the spent operation deadline in either order.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

func (d *Database) countPreviousStorageSecrets(ctx context.Context) (int64, error) {
	previousKeyID := d.storageKey.PreviousID()
	if previousKeyID == "" {
		return 0, nil
	}
	var count int64
	err := d.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM control.control_sessions WHERE retry_secret_storage_key_id = $1) +
			(SELECT count(*) FROM control.device_logins WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.team_invitation_email_deliveries WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.acme_accounts WHERE account_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.service_client_certificate_issuer WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.visitor_token_keys WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.relay_services WHERE transport_private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_certificate_orders WHERE private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.service_runs WHERE assignment_seed_storage_key_id = $1) +
			(SELECT count(*) FROM control.connector_peer_pairs WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.connector_peer_pairs WHERE session_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE source_storage_key_id = $1) +
			(SELECT count(*) FROM control.connector_peer_pending_bindings WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.workload_sessions WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.applied_projects WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.services WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.service_ip_keys WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.deployments WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.deployment_publisher_enrollments WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.service_http_browser_logins WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.service_http_browser_sessions WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.service_http_browser_handoffs WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.deployment_namespace_renames WHERE storage_key_id=$1)
	`, previousKeyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("controlstate: count previous-key secrets: %w", err)
	}
	return count, nil
}

// ReencryptStorageSecrets claims and re-encrypts up to limit rows written with
// the previous storage key. row locks last through commit, so
// concurrent control processes skip work already claimed by another process.
func (d *Database) ReencryptStorageSecrets(ctx context.Context, limit int) (rotated int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	previousKeyID := d.storageKey.PreviousID()
	if previousKeyID == "" {
		return 0, nil
	}
	if limit <= 0 || limit > maximumStorageRotationBatch {
		return 0, errors.New("controlstate: invalid storage rotation batch size")
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: begin storage rotation: %w", err)
	}
	defer rollback(ctx, tx, "storage rotation", &retErr)()

	remaining := limit
	rotate := func(query string, scan func(pgx.Rows) (string, string, []byte, error), update func(string, string, []byte) error) error {
		if remaining == 0 {
			return nil
		}
		rows, err := tx.Query(ctx, query, previousKeyID, remaining)
		if err != nil {
			return err
		}
		type claimedSecret struct {
			rowID      string
			context    string
			ciphertext []byte
		}
		claimed := make([]claimedSecret, 0, remaining)
		for rows.Next() {
			rowID, secretContext, ciphertext, err := scan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			claimed = append(claimed, claimedSecret{
				rowID: rowID, context: secretContext, ciphertext: append([]byte(nil), ciphertext...),
			})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, secret := range claimed {
			plaintext, previous, err := d.openSecret(previousKeyID, secret.context, secret.ciphertext)
			if err != nil || !previous {
				return errors.New("stored secret does not match the configured previous storage key")
			}
			rotatedCiphertext, err := d.sealSecret(secret.context, plaintext)
			clear(plaintext)
			if err != nil {
				return err
			}
			if err := update(secret.rowID, d.storageKey.CurrentID(), rotatedCiphertext); err != nil {
				return err
			}
			rotated++
			remaining--
		}
		return nil
	}
	if err := rotate(`SELECT ctid::text,id,seed_ciphertext FROM control.visitor_token_keys WHERE storage_key_id=$1 FOR UPDATE SKIP LOCKED LIMIT $2`,
		func(rows pgx.Rows) (string, string, []byte, error) {
			var row, id string
			var ciphertext []byte
			err := rows.Scan(&row, &id, &ciphertext)
			return row, visitorSigningKeyContext(id), ciphertext, err
		}, func(row, key string, ciphertext []byte) error {
			_, err := tx.Exec(ctx, `UPDATE control.visitor_token_keys SET seed_ciphertext=$1,storage_key_id=$2 WHERE ctid=$3::tid AND storage_key_id=$4`, ciphertext, key, row, previousKeyID)
			return err
		}); err != nil {
		return 0, err
	}
	if err := rotate(`SELECT ctid::text, seed_ciphertext FROM control.service_client_certificate_issuer WHERE storage_key_id=$1 FOR UPDATE SKIP LOCKED LIMIT $2`,
		func(rows pgx.Rows) (string, string, []byte, error) {
			var row string
			var ciphertext []byte
			err := rows.Scan(&row, &ciphertext)
			return row, serviceClientIssuerContext, ciphertext, err
		}, func(row, key string, ciphertext []byte) error {
			_, err := tx.Exec(ctx, `UPDATE control.service_client_certificate_issuer SET seed_ciphertext=$1,storage_key_id=$2 WHERE ctid=$3::tid AND storage_key_id=$4`, ciphertext, key, row, previousKeyID)
			return err
		}); err != nil {
		return 0, err
	}
	if err := rotate(`SELECT ctid::text, delivery_id, payload_ciphertext FROM control.team_invitation_email_deliveries
		WHERE storage_key_id = $1 ORDER BY delivery_id FOR UPDATE SKIP LOCKED LIMIT $2`,
		func(rows pgx.Rows) (string, string, []byte, error) {
			var rowID, id string
			var ciphertext []byte
			err := rows.Scan(&rowID, &id, &ciphertext)
			return rowID, emailPayloadContext(id), ciphertext, err
		}, func(rowID, keyID string, ciphertext []byte) error {
			_, err := tx.Exec(ctx, `UPDATE control.team_invitation_email_deliveries SET payload_ciphertext=$1, storage_key_id=$2 WHERE ctid=$3::tid AND storage_key_id=$4`, ciphertext, keyID, rowID, previousKeyID)
			return err
		}); err != nil {
		return 0, err
	}

	if err := rotate(`
		SELECT ctid::text, id, retry_secret_ciphertext
		FROM control.control_sessions
		WHERE retry_secret_storage_key_id = $1
		ORDER BY id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, id string
		var ciphertext []byte
		err := rows.Scan(&rowID, &id, &ciphertext)
		return rowID, controlSessionRetrySecretContext(id), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.control_sessions
			SET retry_secret_ciphertext = $1, retry_secret_storage_key_id = $2
			WHERE ctid = $3::tid AND retry_secret_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate control-session retry secrets: %w", err)
	}

	if err := rotate(`
		SELECT ctid::text, id, account_key_ciphertext
		FROM control.acme_accounts
		WHERE account_key_storage_key_id = $1
		ORDER BY id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, id string
		var ciphertext []byte
		err := rows.Scan(&rowID, &id, &ciphertext)
		return rowID, acmeAccountKeyContext(id), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.acme_accounts
			SET account_key_ciphertext = $1, account_key_storage_key_id = $2
			WHERE ctid = $3::tid AND account_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate ACME account keys: %w", err)
	}

	if err := rotate(`
		SELECT ctid::text, relay_service_id, transport_private_key_ciphertext
		FROM control.relay_services
		WHERE transport_private_key_storage_key_id = $1
		ORDER BY relay_service_id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, relayServiceID string
		var ciphertext []byte
		err := rows.Scan(&rowID, &relayServiceID, &ciphertext)
		return rowID, relayTransportPrivateKeyContext(relayServiceID), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.relay_services
			SET transport_private_key_ciphertext = $1, transport_private_key_storage_key_id = $2
			WHERE ctid = $3::tid AND transport_private_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate relay transport private keys: %w", err)
	}

	if err := rotate(`
		SELECT ctid::text, id, private_key_ciphertext
		FROM control.relay_certificate_orders
		WHERE private_key_storage_key_id = $1
		ORDER BY id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, orderID string
		var ciphertext []byte
		err := rows.Scan(&rowID, &orderID, &ciphertext)
		return rowID, relayCertificateOrderPrivateKeyContext(orderID), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.relay_certificate_orders
			SET private_key_ciphertext = $1, private_key_storage_key_id = $2
			WHERE ctid = $3::tid AND private_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate relay certificate order private keys: %w", err)
	}

	for _, source := range []struct {
		query, column, keyIDColumn, table string
		context                           func(string) string
	}{
		{`SELECT c.ctid::text,c.pair_id || '/' || c.delivery_generation || '/' || c.connection_slot,c.source_ciphertext
		  FROM control.connector_peer_pairs p JOIN control.connector_peer_pair_leg_claims c ON c.pair_id=p.id
		  WHERE c.source_storage_key_id=$1
		  ORDER BY c.pair_id,c.delivery_generation,c.connection_slot FOR UPDATE OF p,c SKIP LOCKED LIMIT $2`,
			"source_ciphertext", "source_storage_key_id", "control.connector_peer_pair_leg_claims",
			func(id string) string { return "connector-source/" + id }},
		{`SELECT ctid::text,service_id || '/' || purpose,key_ciphertext FROM control.service_ip_keys
		  WHERE storage_key_id=$1 ORDER BY service_id,purpose FOR UPDATE SKIP LOCKED LIMIT $2`,
			"key_ciphertext", "storage_key_id", "control.service_ip_keys", serviceIPKeyContext},
		{`SELECT ctid::text, 'device-login:' || encode(credential_digest,'hex'), payload FROM control.device_logins
		  WHERE storage_key_id=$1 ORDER BY credential_digest FOR UPDATE SKIP LOCKED LIMIT $2`,
			"payload", "storage_key_id", "control.device_logins", func(scope string) string { return scope }},
		{`SELECT ctid::text, encode(token_digest,'hex'), cookie_ciphertext FROM control.service_http_browser_handoffs
		  WHERE storage_key_id=$1 ORDER BY token_digest FOR UPDATE SKIP LOCKED LIMIT $2`,
			"cookie_ciphertext", "storage_key_id", "control.service_http_browser_handoffs", func(id string) string { return "browser-access:" + id }},
		{`SELECT ctid::text,id,credential_ciphertext FROM control.workload_sessions WHERE storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"credential_ciphertext", "storage_key_id", "control.workload_sessions", workloadCredentialContext},
		{`SELECT ctid::text, encode(state_digest,'hex'), verifier_ciphertext FROM control.service_http_browser_logins
		  WHERE storage_key_id=$1 ORDER BY state_digest FOR UPDATE SKIP LOCKED LIMIT $2`,
			"verifier_ciphertext", "storage_key_id", "control.service_http_browser_logins", func(id string) string { return "browser-access:" + id }},
		{`SELECT ctid::text, encode(token_digest,'hex'), refresh_ciphertext FROM control.service_http_browser_sessions
		  WHERE storage_key_id=$1 ORDER BY token_digest FOR UPDATE SKIP LOCKED LIMIT $2`,
			"refresh_ciphertext", "storage_key_id", "control.service_http_browser_sessions", func(id string) string { return "browser-access:" + id }},
		{`SELECT ctid::text, team_id || '/' || project_key, configuration_ciphertext FROM control.applied_projects
		  WHERE storage_key_id=$1 ORDER BY team_id,project_key FOR UPDATE SKIP LOCKED LIMIT $2`,
			"configuration_ciphertext", "storage_key_id", "control.applied_projects", func(id string) string { return "applied-project/" + id }},
		{`SELECT ctid::text,id,configuration_ciphertext FROM control.services
		  WHERE storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"configuration_ciphertext", "storage_key_id", "control.services", serviceConfigurationContext},
		{`SELECT ctid::text,id,configuration_ciphertext FROM control.deployments
		  WHERE storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"configuration_ciphertext", "storage_key_id", "control.deployments", deploymentConfigurationContext},
		{`SELECT ctid::text,id,secret_ciphertext FROM control.deployment_publisher_enrollments
		  WHERE storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"secret_ciphertext", "storage_key_id", "control.deployment_publisher_enrollments", deploymentPublisherEnrollmentContext},
		{`SELECT ctid::text, team_id || '/' || project_key || '/' || idempotency_key, response_ciphertext FROM control.deployment_namespace_renames
		  WHERE storage_key_id=$1 ORDER BY team_id,project_key,idempotency_key LIMIT $2 FOR UPDATE SKIP LOCKED`,
			"response_ciphertext", "storage_key_id", "control.deployment_namespace_renames", func(id string) string { return "publisher-namespace-rename/" + id }},
		{`SELECT ctid::text, id, assignment_seed_ciphertext FROM control.service_runs
		  WHERE assignment_seed_storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"assignment_seed_ciphertext", "assignment_seed_storage_key_id", "control.service_runs", serviceAssignmentSeedContext},
		{`SELECT ctid::text, id, key_ciphertext FROM control.connector_peer_pairs
		  WHERE storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"key_ciphertext", "storage_key_id", "control.connector_peer_pairs", connectorPeerPairKeyContext},
		{`SELECT ctid::text, id, session_key_ciphertext FROM control.connector_peer_pairs
		  WHERE session_key_storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"session_key_ciphertext", "session_key_storage_key_id", "control.connector_peer_pairs", connectorPeerSessionKeyContext},
		{`SELECT ctid::text, pair_id, key_ciphertext FROM control.connector_peer_pending_bindings
		  WHERE storage_key_id=$1 ORDER BY pair_id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"key_ciphertext", "storage_key_id", "control.connector_peer_pending_bindings", connectorPeerPairKeyContext},
	} {
		if err := rotate(source.query, func(rows pgx.Rows) (string, string, []byte, error) {
			var rowID, id string
			var ciphertext []byte
			err := rows.Scan(&rowID, &id, &ciphertext)
			return rowID, source.context(id), ciphertext, err
		}, func(rowID, keyID string, ciphertext []byte) error {
			_, err := tx.Exec(ctx, `UPDATE `+source.table+` SET `+source.column+`=$1, `+source.keyIDColumn+`=$2
				WHERE ctid=$3::tid AND `+source.keyIDColumn+`=$4`, ciphertext, keyID, rowID, previousKeyID)
			return err
		}); err != nil {
			return 0, fmt.Errorf("rotate stored secrets in %s: %w", source.table, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: commit storage rotation: %w", err)
	}
	return rotated, nil
}
