package controlstate

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
func (d *Database) CompleteStorageKeyRotation(ctx context.Context) error {
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

func (d *Database) countPreviousStorageSecrets(ctx context.Context) (int64, error) {
	previousKeyID := d.storageKey.PreviousID()
	if previousKeyID == "" {
		return 0, nil
	}
	var count int64
	err := d.pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM control.control_sessions WHERE retry_secret_storage_key_id = $1) +
			(SELECT count(*) FROM control.team_invitation_email_deliveries WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.acme_accounts WHERE account_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.service_client_certificate_issuer WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.relay_services WHERE transport_private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_certificate_orders WHERE private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.guest_retry_keys WHERE guest_retry_master_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.visitor_network_hash_keys WHERE visitor_network_hash_master_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.public_urls WHERE allowed_ip_policy_storage_key_id = $1) +
			(SELECT count(*) FROM control.public_urls WHERE request_digest_storage_key_id = $1) +
			(SELECT count(*) FROM control.publish_runs WHERE request_digest_storage_key_id = $1) +
			(SELECT count(*) FROM control.private_service_runs WHERE assignment_seed_storage_key_id = $1) +
			(SELECT count(*) FROM control.private_ingress_assignment_requests WHERE storage_key_id = $1) +
			(SELECT count(*) FROM control.ingress_transport_issuers WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.ingress_transport_certificates WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.applied_projects WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.managed_http_browser_logins WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.publisher_namespace_renames WHERE storage_key_id=$1) +
			(SELECT count(*) FROM control.ingress_routing_table_events WHERE policy_storage_key_id = $1)
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

	if err := rotate(`
		SELECT ctid::text, guest_retry_master_key_ciphertext
		FROM control.guest_retry_keys
		WHERE guest_retry_master_key_storage_key_id = $1
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID string
		var ciphertext []byte
		err := rows.Scan(&rowID, &ciphertext)
		return rowID, guestRetryMasterKeyContext(), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.guest_retry_keys
			SET guest_retry_master_key_ciphertext = $1, guest_retry_master_key_storage_key_id = $2
			WHERE ctid = $3::tid AND guest_retry_master_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate guest retry master key: %w", err)
	}

	if err := rotate(`
		SELECT ctid::text, visitor_network_hash_master_key_ciphertext
		FROM control.visitor_network_hash_keys
		WHERE visitor_network_hash_master_key_storage_key_id = $1
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID string
		var ciphertext []byte
		err := rows.Scan(&rowID, &ciphertext)
		return rowID, visitorNetworkHashMasterKeyContext(), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.visitor_network_hash_keys
			SET visitor_network_hash_master_key_ciphertext = $1, visitor_network_hash_master_key_storage_key_id = $2
			WHERE ctid = $3::tid AND visitor_network_hash_master_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate visitor network hash key: %w", err)
	}

	for _, source := range []struct {
		query, column, keyIDColumn, table string
		context                           func(string) string
	}{
		{`SELECT ctid::text, encode(state_digest,'hex'), verifier_ciphertext FROM control.managed_http_browser_logins
		  WHERE storage_key_id=$1 ORDER BY state_digest FOR UPDATE SKIP LOCKED LIMIT $2`,
			"verifier_ciphertext", "storage_key_id", "control.managed_http_browser_logins", func(id string) string { return "browser-access:" + id }},
		{`SELECT ctid::text, team_id || '/' || project_key, configuration_ciphertext FROM control.applied_projects
		  WHERE storage_key_id=$1 ORDER BY team_id,project_key FOR UPDATE SKIP LOCKED LIMIT $2`,
			"configuration_ciphertext", "storage_key_id", "control.applied_projects", func(id string) string { return "applied-project/" + id }},
		{`SELECT ctid::text, team_id || '/' || project_key || '/' || idempotency_key, response_ciphertext FROM control.publisher_namespace_renames
		  WHERE storage_key_id=$1 ORDER BY team_id,project_key,idempotency_key LIMIT $2 FOR UPDATE SKIP LOCKED`,
			"response_ciphertext", "storage_key_id", "control.publisher_namespace_renames", func(id string) string { return "publisher-namespace-rename/" + id }},
		{`SELECT ctid::text, id, allowed_ip_policy_ciphertext FROM control.public_urls
		  WHERE allowed_ip_policy_storage_key_id = $1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"allowed_ip_policy_ciphertext", "allowed_ip_policy_storage_key_id", "control.public_urls", publicURLIPPolicyContext},
		{`SELECT ctid::text, id, request_digest_ciphertext FROM control.public_urls
		  WHERE request_digest_storage_key_id = $1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"request_digest_ciphertext", "request_digest_storage_key_id", "control.public_urls", publicURLRequestDigestContext},
		{`SELECT ctid::text, id, request_digest_ciphertext FROM control.publish_runs
		  WHERE request_digest_storage_key_id = $1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"request_digest_ciphertext", "request_digest_storage_key_id", "control.publish_runs", publishRunRequestDigestContext},
		{`SELECT ctid::text, id, assignment_seed_ciphertext FROM control.private_service_runs
		  WHERE assignment_seed_storage_key_id=$1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"assignment_seed_ciphertext", "assignment_seed_storage_key_id", "control.private_service_runs", privateAssignmentSeedContext},
		{`SELECT ctid::text, identity_id || '/' || idempotency_key, result_ciphertext FROM control.private_ingress_assignment_requests
		  WHERE storage_key_id=$1 ORDER BY identity_id,idempotency_key FOR UPDATE SKIP LOCKED LIMIT $2`,
			"result_ciphertext", "storage_key_id", "control.private_ingress_assignment_requests", privateIngressAssignmentContext},
		{`SELECT ctid::text, revision::text, private_key_ciphertext FROM control.ingress_transport_issuers WHERE storage_key_id=$1 ORDER BY revision FOR UPDATE SKIP LOCKED LIMIT $2`,
			"private_key_ciphertext", "storage_key_id", "control.ingress_transport_issuers", func(id string) string { return "ingress-transport-issuer:" + id }},
		{`SELECT ctid::text, public_url_id, policy_ciphertext FROM control.ingress_routing_table_events
		  WHERE policy_storage_key_id = $1 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2`,
			"policy_ciphertext", "policy_storage_key_id", "control.ingress_routing_table_events", publicURLIPPolicyContext},
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
			return 0, fmt.Errorf("controlstate: rotate private IP policy: %w", err)
		}
	}
	if err := rotate(`SELECT ctid::text,ingress_id,ingress_run_id,ingress_lease_revision,tls_server_name,private_key_ciphertext
	    FROM control.ingress_transport_certificates WHERE storage_key_id=$1 ORDER BY ingress_id,ingress_run_id FOR UPDATE SKIP LOCKED LIMIT $2`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, id, run, name string
		var revision int64
		var ciphertext []byte
		err := rows.Scan(&rowID, &id, &run, &revision, &name, &ciphertext)
		return rowID, ingressTransportKeyContext(id, run, revision, name), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `UPDATE control.ingress_transport_certificates SET private_key_ciphertext=$1,storage_key_id=$2 WHERE ctid=$3::tid AND storage_key_id=$4`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate ingress transport private keys: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: commit storage rotation: %w", err)
	}
	return rotated, nil
}
