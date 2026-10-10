package clientstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

type AuthPhase string

const (
	AuthPending            AuthPhase = "pending"
	AuthRedeeming          AuthPhase = "redeeming"
	AuthCredentialReceived AuthPhase = "credential_received"
	AuthExchanging         AuthPhase = "exchanging"
	AuthIssued             AuthPhase = "issued"
	AuthCompleted          AuthPhase = "completed"
	AuthCancelled          AuthPhase = "cancelled"
	AuthDenied             AuthPhase = "denied"
	AuthExpired            AuthPhase = "expired"
	AuthRecoveryRequired   AuthPhase = "recovery_required"
)

var (
	ErrAuthOperationNotFound = errors.New("login operation not found")
	ErrAuthOperationChanged  = errors.New("login operation changed")
)

// AuthOperation contains only browser-safe operation information. private
// checkpoints are sealed separately and never serialized by output adapters.
type AuthOperation struct {
	ID              string        `json:"operation_id"`
	Server          string        `json:"server"`
	Method          string        `json:"method"`
	Phase           AuthPhase     `json:"status"`
	ApprovalURL     string        `json:"approval_url,omitempty"`
	UserCode        string        `json:"user_code,omitempty"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Interval        time.Duration `json:"-"`
	IntervalSeconds int64         `json:"interval_seconds"`
	NextPollAt      time.Time     `json:"-"`
	Revision        int64         `json:"-"`
	Private         []byte        `json:"-"`
}

func NewAuthOperationID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return "auth_" + hex.EncodeToString(bytes[:]), nil
}

func validAuthOperationID(id string) bool {
	if len(id) != 37 || id[:5] != "auth_" {
		return false
	}
	_, err := hex.DecodeString(id[5:])
	return err == nil
}

// LockAuthOperationContext serializes waiters without holding the credential lock.
func LockAuthOperationContext(ctx context.Context, store *Store, id string) (*Lock, error) {
	if store == nil || !validAuthOperationID(id) {
		return nil, ErrAuthOperationNotFound
	}
	return openLockContext(ctx, filepath.Join(store.locksDir, id+".lock"), "login operation")
}

func LockAuthCleanupContext(ctx context.Context, store *Store, id string) (*Lock, error) {
	if store == nil || !validAuthOperationID(id) {
		return nil, ErrAuthOperationNotFound
	}
	return openLockContext(ctx, filepath.Join(store.locksDir, id+"-cleanup.lock"), "login credential cleanup")
}

func (s *Store) CreateAuthOperation(ctx context.Context, op AuthOperation) error {
	if !validAuthOperationID(op.ID) {
		return ErrAuthOperationNotFound
	}
	public, private, err := s.encodeAuthOperation(ctx, op)
	if err != nil {
		return err
	}
	return s.database.queries.InsertAuthOperation(ctx, clientstatedb.InsertAuthOperationParams{
		ServerOrigin: s.controlEndpoint, OperationID: op.ID, Phase: string(op.Phase), PublicJson: public,
		StoredPrivate: private, UpdatedAt: s.database.now().UnixNano(),
	})
}

func (s *Store) AuthOperation(ctx context.Context, id string) (AuthOperation, error) {
	if !validAuthOperationID(id) {
		return AuthOperation{}, ErrAuthOperationNotFound
	}
	row, err := s.database.queries.GetAuthOperation(ctx, clientstatedb.GetAuthOperationParams{ServerOrigin: s.controlEndpoint, OperationID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return AuthOperation{}, ErrAuthOperationNotFound
	}
	if err != nil {
		return AuthOperation{}, err
	}
	return s.decodeAuthOperation(ctx, row)
}

func (s *Store) ActiveAuthOperation(ctx context.Context) (AuthOperation, bool, error) {
	row, err := s.database.queries.GetActiveAuthOperation(ctx, s.controlEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthOperation{}, false, nil
	}
	if err != nil {
		return AuthOperation{}, false, err
	}
	op, err := s.decodeAuthOperation(ctx, row)
	return op, err == nil, err
}

func (s *Store) decodeAuthOperation(ctx context.Context, row clientstatedb.AuthOperation) (AuthOperation, error) {
	id := row.OperationID
	var op AuthOperation
	if err := json.Unmarshal([]byte(row.PublicJson), &op); err != nil {
		return AuthOperation{}, err
	}
	op.ID, op.Server, op.Phase, op.Revision = id, s.controlEndpoint, AuthPhase(row.Phase), row.Revision
	op.Interval = time.Duration(op.IntervalSeconds) * time.Second
	// scheduling is private metadata so output never exposes checkpoints.
	if len(row.StoredPrivate) != 0 {
		bytes, err := s.secrets.Open(ctx, "auth-operation:"+id, row.StoredPrivate)
		if err != nil {
			return AuthOperation{}, err
		}
		var checkpoint struct {
			Payload    []byte
			NextPollAt time.Time
		}
		if err := json.Unmarshal(bytes, &checkpoint); err != nil {
			return AuthOperation{}, err
		}
		op.Private, op.NextPollAt = checkpoint.Payload, checkpoint.NextPollAt
	}
	return op, nil
}

func (s *Store) CancelledAuthCredentials(ctx context.Context) ([]AuthOperation, error) {
	rows, err := s.database.queries.ListCancelledAuthCredentials(ctx, s.controlEndpoint)
	if err != nil {
		return nil, err
	}
	operations := make([]AuthOperation, 0, len(rows))
	for _, row := range rows {
		op, err := s.decodeAuthOperation(ctx, row)
		if err != nil {
			return nil, err
		}
		operations = append(operations, op)
	}
	return operations, nil
}

func (s *Store) encodeAuthOperation(ctx context.Context, op AuthOperation) (string, []byte, error) {
	op.Server = s.controlEndpoint
	op.IntervalSeconds = int64(op.Interval / time.Second)
	public, err := json.Marshal(op)
	if err != nil {
		return "", nil, err
	}
	if len(op.Private) == 0 {
		return string(public), []byte{}, nil
	}
	checkpoint, err := json.Marshal(struct {
		Payload    []byte
		NextPollAt time.Time
	}{op.Private, op.NextPollAt})
	if err != nil {
		return "", nil, err
	}
	private, err := s.secrets.Seal(ctx, "auth-operation:"+op.ID, checkpoint)
	return string(public), private, err
}

func (s *Store) UpdateAuthOperation(ctx context.Context, op *AuthOperation) error {
	public, private, err := s.encodeAuthOperation(ctx, *op)
	if err != nil {
		return err
	}
	n, err := s.database.queries.UpdateAuthOperation(ctx, clientstatedb.UpdateAuthOperationParams{
		ServerOrigin: s.controlEndpoint, OperationID: op.ID, ExpectedRevision: op.Revision,
		Phase: string(op.Phase), PublicJson: public, StoredPrivate: private, UpdatedAt: s.database.now().UnixNano(),
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAuthOperationChanged
	}
	op.Revision++
	return nil
}

// FenceAuthOperations must run under the credential lock, as must installation.
func (s *Store) FenceAuthOperations(ctx context.Context) error {
	return s.database.queries.FenceAuthOperations(ctx, clientstatedb.FenceAuthOperationsParams{ServerOrigin: s.controlEndpoint, UpdatedAt: s.database.now().UnixNano()})
}

// InstallAuthSession atomically completes the checkpoint and installs credentials.
// the caller holds the credential lock, so logout cannot race the transaction.
func (s *Store) InstallAuthSession(ctx context.Context, op *AuthOperation, session ControlSession) error {
	if err := s.validateControlSession(session); err != nil {
		return err
	}
	access, err := s.secrets.Seal(ctx, controlSessionContext(session.SessionID, "access"), []byte(session.AccessToken))
	if err != nil {
		return err
	}
	refresh, err := s.secrets.Seal(ctx, controlSessionContext(session.SessionID, "refresh"), []byte(session.RefreshToken))
	if err != nil {
		return err
	}
	completed := *op
	completed.Phase, completed.Private = AuthCompleted, nil
	public, private, err := s.encodeAuthOperation(ctx, completed)
	if err != nil {
		return err
	}
	tx, err := s.database.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := s.database.queries.WithTx(tx)
	n, err := q.UpdateAuthOperation(ctx, clientstatedb.UpdateAuthOperationParams{
		ServerOrigin: s.controlEndpoint, OperationID: op.ID, ExpectedRevision: op.Revision,
		Phase: string(AuthCompleted), PublicJson: public, StoredPrivate: private, UpdatedAt: s.database.now().UnixNano(),
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAuthOperationChanged
	}
	if err := q.UpsertControlSession(ctx, clientstatedb.UpsertControlSessionParams{
		ServerOrigin: s.controlEndpoint, SessionID: session.SessionID, StoredAccessToken: access,
		StoredRefreshToken: refresh, AccessExpiresAt: timeUnixNano(session.AccessExpiresAt),
		RefreshExpiresAt: timeUnixNano(session.RefreshExpiresAt), UpdatedAt: s.database.now().UnixNano(),
	}); err != nil {
		return err
	}
	if err := q.SetSelectedServer(ctx, sql.NullString{String: s.controlEndpoint, Valid: true}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	completed.Revision++
	*op = completed
	return nil
}
