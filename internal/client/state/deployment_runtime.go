package state

import (
	"context"
	"errors"
	"strings"
)

// SetDeploymentPublisherEnrollmentSecret refreshes only a pending deployment task's
// bootstrap secret. its protected signing key is never deleted or replaced,
// including when a previous redemption response was lost.
func (s *Store) SetDeploymentPublisherEnrollmentSecret(ctx context.Context, id, scope string, secret []byte) error {
	if !validOpaqueValue(id, 256) || !validOpaqueValue(scope, 1024) || !strings.HasPrefix(scope, "project-publisher:deployment:") || len(secret) == 0 || len(secret) > 256 {
		return errors.New("clientstate: invalid deployment enrollment")
	}
	sealed, err := s.secrets.Seal(ctx, pendingSecretContext(id), secret)
	if err != nil {
		return err
	}
	result, err := s.database.db.ExecContext(ctx, `UPDATE pending_publisher_enrollments SET enrollment_secret_ciphertext=?, updated_at=? WHERE server_origin=? AND enrollment_id=? AND selection_kind='project' AND selection_key=? AND result_json IS NULL`, sealed, s.database.now().UTC().UnixNano(), s.controlEndpoint, id, scope)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrPublisherStateConflict
	}
	return nil
}
