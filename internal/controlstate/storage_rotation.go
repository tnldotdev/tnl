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
			(SELECT count(*) FROM control.acme_accounts WHERE account_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.control_tls_cache WHERE cache_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_services WHERE transport_private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.relay_certificate_orders WHERE private_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.runtime_secret WHERE external_retry_master_key_storage_key_id = $1) +
			(SELECT count(*) FROM control.public_url_usage_configuration WHERE visitor_network_hash_master_key_storage_key_id = $1)
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
		SELECT ctid::text, directory_url, cache_key, cache_ciphertext
		FROM control.control_tls_cache
		WHERE cache_storage_key_id = $1
		ORDER BY directory_url, cache_key
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID, directoryURL, cacheKey string
		var ciphertext []byte
		err := rows.Scan(&rowID, &directoryURL, &cacheKey, &ciphertext)
		return rowID, controlTLSCacheContext(directoryURL, cacheKey), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.control_tls_cache
			SET cache_ciphertext = $1, cache_storage_key_id = $2
			WHERE ctid = $3::tid AND cache_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate control TLS cache: %w", err)
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
		SELECT ctid::text, external_retry_master_key_ciphertext
		FROM control.runtime_secret
		WHERE external_retry_master_key_storage_key_id = $1
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, func(rows pgx.Rows) (string, string, []byte, error) {
		var rowID string
		var ciphertext []byte
		err := rows.Scan(&rowID, &ciphertext)
		return rowID, externalRetryMasterKeyContext(), ciphertext, err
	}, func(rowID, keyID string, ciphertext []byte) error {
		_, err := tx.Exec(ctx, `
			UPDATE control.runtime_secret
			SET external_retry_master_key_ciphertext = $1, external_retry_master_key_storage_key_id = $2
			WHERE ctid = $3::tid AND external_retry_master_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate external retry master key: %w", err)
	}

	if err := rotate(`
		SELECT ctid::text, visitor_network_hash_master_key_ciphertext
		FROM control.public_url_usage_configuration
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
			UPDATE control.public_url_usage_configuration
			SET visitor_network_hash_master_key_ciphertext = $1, visitor_network_hash_master_key_storage_key_id = $2
			WHERE ctid = $3::tid AND visitor_network_hash_master_key_storage_key_id = $4
		`, ciphertext, keyID, rowID, previousKeyID)
		return err
	}); err != nil {
		return 0, fmt.Errorf("controlstate: rotate visitor network hash key: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: commit storage rotation: %w", err)
	}
	return rotated, nil
}
