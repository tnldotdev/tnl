package clientstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
)

const privatePortStart = 20000
const privatePortRange = 40000

var ErrPrivatePortReserved = errors.New("loopback port is reserved for another private service")

type PortReservedError struct{ Port int }

func (e *PortReservedError) Error() string {
	return fmt.Sprintf("loopback port %d is reserved for another private service", e.Port)
}
func (e *PortReservedError) Unwrap() error { return ErrPrivatePortReserved }

// PortOccupiedError identifies the saved port occupied by another process.
// the assignment is not silently changed behind a configured GUI profile.
type PortOccupiedError struct {
	Port int
	Err  error
}

func (e *PortOccupiedError) Error() string {
	return fmt.Sprintf("loopback port %d is occupied for this private service; use --listen to override: %v", e.Port, e.Err)
}
func (e *PortOccupiedError) Unwrap() error { return e.Err }

func (s *Store) PrivateServicePort(ctx context.Context, identityID, serviceID string) (int, bool, error) {
	if !validPrivatePortKey(identityID, serviceID) {
		return 0, false, errors.New("clientstate: invalid private service port key")
	}
	var port int
	err := s.database.db.QueryRowContext(ctx, `SELECT port FROM private_service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return port, err == nil, err
}

func (s *Store) RemovePrivateServicePort(ctx context.Context, identityID, serviceID string) error {
	if !validPrivatePortKey(identityID, serviceID) {
		return errors.New("clientstate: invalid private service port key")
	}
	_, err := s.database.db.ExecContext(ctx, `DELETE FROM private_service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID)
	return err
}

// ListenPrivateService reserves the listener before persisting a new port. an
// existing assignment is never changed on a conflict. SQLite's immediate
// writer transaction serializes allocation across local publisher processes.
func (s *Store) ListenPrivateService(ctx context.Context, identityID, serviceID, protocol string) (net.Listener, error) {
	if !validPrivatePortKey(identityID, serviceID) || protocol != "tcp" && protocol != "mysql" && protocol != "postgres" {
		return nil, errors.New("clientstate: invalid private service port key")
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE server_profiles SET last_used_at=last_used_at WHERE origin=?`, s.controlEndpoint); err != nil {
		return nil, err
	}
	var saved int
	err = tx.QueryRowContext(ctx, `SELECT port FROM private_service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID).Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		listener, bindErr := listenPrivatePort(saved)
		if bindErr != nil {
			if errors.Is(bindErr, syscall.EADDRINUSE) {
				return nil, &PortOccupiedError{Port: saved, Err: bindErr}
			}
			return nil, bindErr
		}
		if err := tx.Commit(); err != nil {
			listener.Close()
			return nil, err
		}
		return listener, nil
	}
	seed := sha256.Sum256([]byte(s.controlEndpoint + "\x00" + identityID + "\x00" + serviceID))
	for attempt := range 128 {
		port := privatePortCandidate(protocol, seed, attempt)
		var taken int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM private_service_ports WHERE port=? UNION ALL SELECT 1 FROM private_connectors WHERE listen_port=? AND state IN ('starting','ready') AND lease_expires_at>? LIMIT 1`, port, port, s.database.now().UTC().UnixNano()).Scan(&taken)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		listener, err := listenPrivatePort(port)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO private_service_ports(server_origin, identity_id, service_id, port) VALUES (?, ?, ?, ?)`,
			s.controlEndpoint, identityID, serviceID, port)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			listener.Close()
			return nil, err
		}
		return listener, nil
	}
	return nil, errors.New("clientstate: no unoccupied loopback port available")
}

// PrivateServiceListenAddress chooses an install-time address using only reads.
// it does not bind a socket or save a reservation. a supervisor must later use
// ListenPrivateServiceAt with this exact address; a conflict is an error rather
// than permission to choose another port. an override never renumbers a saved
// assignment, even when another service's reservation is currently inactive.
func (s *Store) PrivateServiceListenAddress(ctx context.Context, identity, service, protocol, override string) (string, error) {
	if !validPrivatePortKey(identity, service) || protocol != "tcp" && protocol != "mysql" && protocol != "postgres" {
		return "", errors.New("invalid private service port selection")
	}
	tx, err := s.database.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	selected, port := "", 0
	if override != "" {
		selected, port, err = privateListenAddress(override)
		if err != nil {
			return "", err
		}
		if port == 0 {
			return "", errors.New("installed private listener needs an exact nonzero port")
		}
	} else {
		err := tx.QueryRowContext(ctx, `SELECT port FROM private_service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`, s.controlEndpoint, identity, service).Scan(&port)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		if err == nil {
			selected = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		}
	}
	if selected != "" {
		reserved, err := s.privatePortReserved(ctx, tx, port, identity, service)
		if err != nil {
			return "", err
		}
		if reserved {
			return "", &PortReservedError{Port: port}
		}
		return selected, nil
	}
	seed := sha256.Sum256([]byte(s.controlEndpoint + "\x00" + identity + "\x00" + service))
	for attempt := range 128 {
		port := privatePortCandidate(protocol, seed, attempt)
		reserved, err := s.privatePortReserved(ctx, tx, port, identity, service)
		if err != nil {
			return "", err
		}
		if !reserved {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
		}
	}
	return "", errors.New("no unreserved loopback port available")
}

// ListenPrivateServiceAt binds an exact loopback address. the first fixed
// address establishes a missing saved port; an existing assignment is never
// changed by an override. a stopped service's reservation still belongs to it.
// port zero is permitted for a foreground ephemeral listener and is not saved.
func (s *Store) ListenPrivateServiceAt(ctx context.Context, identity, service, address string) (net.Listener, error) {
	if !validPrivatePortKey(identity, service) {
		return nil, errors.New("clientstate: invalid private service port key")
	}
	address, port, err := privateListenAddress(address)
	if err != nil {
		return nil, err
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE server_profiles SET last_used_at=last_used_at WHERE origin=?`, s.controlEndpoint); err != nil {
		return nil, err
	}
	// port 0 is selected by the OS, then checked against future reservations.
	for range 128 {
		if port != 0 {
			reserved, err := s.privatePortReserved(ctx, tx, port, identity, service)
			if err != nil {
				return nil, err
			}
			if reserved {
				return nil, &PortReservedError{Port: port}
			}
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			if port != 0 && errors.Is(err, syscall.EADDRINUSE) {
				return nil, &PortOccupiedError{Port: port, Err: err}
			}
			return nil, err
		}
		selected := listener.Addr().(*net.TCPAddr).Port
		reserved, err := s.privatePortReserved(ctx, tx, selected, identity, service)
		if reserved {
			_ = listener.Close()
			if port == 0 {
				continue
			}
			return nil, &PortReservedError{Port: port}
		}
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
		if port != 0 {
			_, err := tx.ExecContext(ctx, `INSERT INTO private_service_ports(server_origin, identity_id, service_id, port) VALUES(?,?,?,?) ON CONFLICT(server_origin, identity_id, service_id) DO NOTHING`, s.controlEndpoint, identity, service, selected)
			if err != nil {
				_ = listener.Close()
				return nil, err
			}
		}
		if err := tx.Commit(); err != nil {
			_ = listener.Close()
			return nil, err
		}
		return listener, nil
	}
	return nil, errors.New("clientstate: no unreserved loopback port available")
}

// ListenPrivateServiceOverride retains the original override spelling for
// callers selecting a foreground listener.
func (s *Store) ListenPrivateServiceOverride(ctx context.Context, identity, service, address string) (net.Listener, error) {
	return s.ListenPrivateServiceAt(ctx, identity, service, address)
}

func privateListenAddress(value string) (string, int, error) {
	host, text, err := net.SplitHostPort(value)
	address, hostErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(text)
	if err != nil || hostErr != nil || !address.IsLoopback() || address.Zone() != "" || portErr != nil || port < 0 || port > 65535 {
		return "", 0, errors.New("private listener needs a loopback IP address and a port from 0 to 65535")
	}
	return net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port)), port, nil
}

func (s *Store) privatePortReserved(ctx context.Context, tx *sql.Tx, port int, identity, service string) (bool, error) {
	var taken int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM private_service_ports WHERE port=? AND NOT(server_origin=? AND identity_id=? AND service_id=?) UNION ALL
		SELECT 1 FROM private_connectors WHERE listen_port=? AND state IN ('starting','ready') AND lease_expires_at>? AND NOT(server_origin=? AND identity_id=? AND service_id=?) LIMIT 1`,
		port, s.controlEndpoint, identity, service, port, s.database.now().UTC().UnixNano(), s.controlEndpoint, identity, service).Scan(&taken)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func privatePortCandidate(protocol string, seed [32]byte, attempt int) int {
	preferred := preferredPrivatePort(protocol)
	if attempt == 0 && preferred != 0 {
		return preferred
	}
	if preferred != 0 {
		attempt--
	}
	return privatePortStart + int((binary.BigEndian.Uint32(seed[:4])%privatePortRange+uint32(attempt*7919))%privatePortRange)
}

func listenPrivatePort(port int) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

func preferredPrivatePort(protocol string) int {
	switch protocol {
	case "mysql":
		return 13306
	case "postgres":
		return 15432
	default:
		return 0
	}
}

func validPrivatePortKey(identityID, serviceID string) bool {
	return validOpaqueValue(identityID, 255) && validOpaqueValue(serviceID, 255) &&
		!strings.ContainsRune(identityID, 0) && !strings.ContainsRune(serviceID, 0) &&
		strings.TrimSpace(identityID) == identityID && strings.TrimSpace(serviceID) == serviceID
}
