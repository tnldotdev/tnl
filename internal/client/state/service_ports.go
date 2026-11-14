package state

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
const privatePortAttempts = 128

var ErrPrivatePortReserved = errors.New("loopback port is reserved for another service")

type PortReservedError struct{ Port int }

func (e *PortReservedError) Error() string {
	return fmt.Sprintf("loopback port %d is reserved for another service", e.Port)
}
func (e *PortReservedError) Unwrap() error { return ErrPrivatePortReserved }

// PortOccupiedError identifies the saved port occupied by another process.
// the assignment is not silently changed behind a configured GUI profile.
type PortOccupiedError struct {
	Port int
	Err  error
}

func (e *PortOccupiedError) Error() string {
	return fmt.Sprintf("loopback port %d is occupied for this service; use --listen to override: %v", e.Port, e.Err)
}
func (e *PortOccupiedError) Unwrap() error { return e.Err }

func (s *Store) ServicePort(ctx context.Context, identityID, serviceID string) (int, bool, error) {
	if !validPrivatePortKey(identityID, serviceID) {
		return 0, false, errors.New("clientstate: invalid service port key")
	}
	var port int
	err := s.database.db.QueryRowContext(ctx, `SELECT port FROM service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return port, err == nil, err
}

func (s *Store) RemoveServicePort(ctx context.Context, identityID, serviceID string) error {
	if !validPrivatePortKey(identityID, serviceID) {
		return errors.New("clientstate: invalid service port key")
	}
	_, err := s.database.db.ExecContext(ctx, `DELETE FROM service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID)
	return err
}

// ListenService reserves the listener before persisting a new port. an
// existing assignment is never changed on a conflict. SQLite's immediate
// writer transaction serializes allocation across local publisher processes.
func (s *Store) ListenService(ctx context.Context, identityID, serviceID, protocol string) (net.Listener, error) {
	return s.listenService(ctx, identityID, serviceID, protocol, listenPrivatePort)
}

// binding happens under the SQLite writer transaction. a successful listener
// stays open through persistence and handoff; a failed write closes it.
func (s *Store) listenService(ctx context.Context, identityID, serviceID, protocol string, bind func(int) (net.Listener, error)) (net.Listener, error) {
	seed := sha256.Sum256([]byte(s.controlEndpoint + "\x00" + identityID + "\x00" + serviceID))
	candidates := privatePortCandidates(protocol, seed)
	if !validPrivatePortKey(identityID, serviceID) || len(candidates) == 0 {
		return nil, errors.New("clientstate: invalid service port key")
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
	err = tx.QueryRowContext(ctx, `SELECT port FROM service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`,
		s.controlEndpoint, identityID, serviceID).Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		listener, bindErr := bind(saved)
		if bindErr != nil {
			if errors.Is(bindErr, syscall.EADDRINUSE) {
				return nil, &PortOccupiedError{Port: saved, Err: bindErr}
			}
			return nil, bindErr
		}
		if err := tx.Commit(); err != nil {
			return nil, errors.Join(err, listener.Close())
		}
		return listener, nil
	}
	for _, port := range candidates {
		var taken int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM service_ports WHERE port=? UNION ALL SELECT 1 FROM connectors WHERE listen_port=? AND state IN ('starting','ready') AND lease_expires_at>? LIMIT 1`, port, port, s.database.now().UTC().UnixNano()).Scan(&taken)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		listener, err := bind(port)
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO service_ports(server_origin, identity_id, service_id, port) VALUES (?, ?, ?, ?)`,
			s.controlEndpoint, identityID, serviceID, port)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			return nil, errors.Join(err, listener.Close())
		}
		return listener, nil
	}
	return nil, errors.New("clientstate: no unoccupied loopback port available")
}

// ServiceListenAddress chooses an install-time address using only reads.
// it does not bind a socket or save a reservation. a supervisor must later use
// ListenServiceAt with this exact address; a conflict is an error rather
// than permission to choose another port. an override never renumbers a saved
// assignment, even when another service's reservation is currently inactive.
func (s *Store) ServiceListenAddress(ctx context.Context, identity, service, protocol, override string) (string, error) {
	seed := sha256.Sum256([]byte(s.controlEndpoint + "\x00" + identity + "\x00" + service))
	candidates := privatePortCandidates(protocol, seed)
	if !validPrivatePortKey(identity, service) || len(candidates) == 0 {
		return "", errors.New("invalid service port selection")
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
		err := tx.QueryRowContext(ctx, `SELECT port FROM service_ports WHERE server_origin=? AND identity_id=? AND service_id=?`, s.controlEndpoint, identity, service).Scan(&port)
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
	for _, port := range candidates {
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

// ListenServiceAt binds an exact loopback address. the first fixed
// address establishes a missing saved port; an existing assignment is never
// changed by an override. a stopped service's reservation still belongs to it.
// port zero is permitted for a foreground ephemeral listener and is not saved.
func (s *Store) ListenServiceAt(ctx context.Context, identity, service, address string) (net.Listener, error) {
	if !validPrivatePortKey(identity, service) {
		return nil, errors.New("clientstate: invalid service port key")
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
			_, err := tx.ExecContext(ctx, `INSERT INTO service_ports(server_origin, identity_id, service_id, port) VALUES(?,?,?,?) ON CONFLICT(server_origin, identity_id, service_id) DO NOTHING`, s.controlEndpoint, identity, service, selected)
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
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM service_ports WHERE port=? AND NOT(server_origin=? AND identity_id=? AND service_id=?) UNION ALL
		SELECT 1 FROM connectors WHERE listen_port=? AND state IN ('starting','ready') AND lease_expires_at>? AND NOT(server_origin=? AND identity_id=? AND service_id=?) LIMIT 1`,
		port, s.controlEndpoint, identity, service, port, s.database.now().UTC().UnixNano(), s.controlEndpoint, identity, service).Scan(&taken)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func listenPrivatePort(port int) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// preferences apply only to the first assignment. canonical application ports
// stay free for local servers, even when a connector uses another protocol.
func privatePortCandidates(protocol string, seed [32]byte) []int {
	var preferred []int
	switch protocol {
	case "http":
		preferred = []int{8443, 9443, 10443, 11443, 12443, 14443, 18443, 19443}
	case "mysql":
		preferred = []int{13306, 23306, 33306, 43306, 53306, 63306, 3307, 3308, 3309, 3310, 3311, 3312, 3313}
	case "postgres":
		preferred = []int{15432, 25432, 35432, 45432, 55432, 5433, 5434, 5435, 5436, 5437, 5438, 5439}
	case "kubernetes":
		preferred = []int{16443, 26443, 36443, 46443, 56443, 6444, 6445, 6446, 6447, 6448, 6449}
	case "tcp":
	default:
		return nil
	}
	ports := make([]int, 0, privatePortAttempts)
	seen := make(map[int]bool, privatePortAttempts)
	add := func(port int) {
		if len(ports) == privatePortAttempts || seen[port] || port < 1024 || port > 65535 || port == 3306 || port == 5432 || port == 6443 {
			return
		}
		seen[port] = true
		ports = append(ports, port)
	}
	for _, port := range preferred {
		add(port)
	}
	for _, port := range []int{11111, 22222, 33333, 44444, 55555, 12321, 23432, 34543, 45654, 56765, 10001, 20002, 30003, 40004, 50005, 60006} {
		add(port)
	}
	offset := binary.BigEndian.Uint32(seed[:4]) % privatePortRange
	// the step is coprime with the range, so the fallback visits each high port
	// at most once. all tiers share one bounded, deduplicated candidate budget.
	for attempt := 0; len(ports) < privatePortAttempts && attempt < privatePortRange; attempt++ {
		add(privatePortStart + int((offset+uint32(attempt*7919))%privatePortRange))
	}
	return ports
}

func validPrivatePortKey(identityID, serviceID string) bool {
	return validOpaqueValue(identityID, 255) && validOpaqueValue(serviceID, 255) &&
		!strings.ContainsRune(identityID, 0) && !strings.ContainsRune(serviceID, 0) &&
		strings.TrimSpace(identityID) == identityID && strings.TrimSpace(serviceID) == serviceID
}
