package clientstate

import (
	"context"
	"errors"
	"time"
)

type PrivateConnector struct {
	IdentityID     string
	ServiceID      string
	Protocol       string
	ProcessID      int
	ListenPort     int
	State          string
	UpdatedAt      time.Time
	LeaseExpiresAt time.Time
}

// SavePrivateConnector records a local supervisor observation, without secrets
// or provider targets. expired observations cannot reserve a new listener.
func (s *Store) SavePrivateConnector(ctx context.Context, value PrivateConnector) error {
	if !validPrivatePortKey(value.IdentityID, value.ServiceID) || value.ProcessID < 1 || value.ListenPort < 1 || value.ListenPort > 65535 ||
		(value.Protocol != "tcp" && value.Protocol != "mysql" && value.Protocol != "postgres") ||
		(value.State != "starting" && value.State != "ready" && value.State != "stopped" && value.State != "failed") ||
		!value.LeaseExpiresAt.After(s.database.now()) {
		return errors.New("invalid private connector status")
	}
	now := s.database.now().UTC().UnixNano()
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM private_connectors WHERE lease_expires_at<=? OR state IN ('stopped','failed')`, now); err != nil {
		return err
	}
	var reserved bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM private_service_ports WHERE port=? AND NOT(server_origin=? AND identity_id=? AND service_id=?))`, value.ListenPort, s.controlEndpoint, value.IdentityID, value.ServiceID).Scan(&reserved); err != nil {
		return err
	}
	if reserved {
		return errors.New("private connector port is reserved for another service")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO private_connectors(server_origin, identity_id, service_id, protocol, process_id, listen_port, state, updated_at, lease_expires_at) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(server_origin, identity_id, service_id) DO UPDATE SET protocol=excluded.protocol, process_id=excluded.process_id, listen_port=excluded.listen_port, state=excluded.state, updated_at=excluded.updated_at, lease_expires_at=excluded.lease_expires_at
		WHERE private_connectors.process_id=excluded.process_id`,
		s.controlEndpoint, value.IdentityID, value.ServiceID, value.Protocol, value.ProcessID, value.ListenPort, value.State, now, value.LeaseExpiresAt.UTC().UnixNano())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return errors.New("private connector belongs to another local process")
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PrivateConnectors(ctx context.Context, identity string) ([]PrivateConnector, error) {
	if !validPrivatePortKey(identity, "connector") {
		return nil, errors.New("invalid visitor identity")
	}
	rows, err := s.database.db.QueryContext(ctx, `SELECT service_id, protocol, process_id, listen_port, state, updated_at, lease_expires_at FROM private_connectors WHERE server_origin=? AND identity_id=? ORDER BY service_id`, s.controlEndpoint, identity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PrivateConnector{}
	for rows.Next() {
		value := PrivateConnector{IdentityID: identity}
		var updated, expires int64
		if err := rows.Scan(&value.ServiceID, &value.Protocol, &value.ProcessID, &value.ListenPort, &value.State, &updated, &expires); err != nil {
			return nil, err
		}
		value.UpdatedAt, value.LeaseExpiresAt = time.Unix(0, updated).UTC(), time.Unix(0, expires).UTC()
		if (value.State == "ready" || value.State == "starting") && !value.LeaseExpiresAt.After(s.database.now()) {
			value.State = "stale"
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Store) RemovePrivateConnector(ctx context.Context, identity, service string, processID int) error {
	if !validPrivatePortKey(identity, service) || processID < 1 {
		return errors.New("invalid private connector key")
	}
	_, err := s.database.db.ExecContext(ctx, `DELETE FROM private_connectors WHERE server_origin=? AND identity_id=? AND service_id=? AND process_id=?`, s.controlEndpoint, identity, service, processID)
	return err
}
