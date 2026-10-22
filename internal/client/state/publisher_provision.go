package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

func provisionContext(kind, binding string, revision int64) string {
	return fmt.Sprintf("publisher-provision:%s:%s:%d", kind, binding, revision)
}

// PublisherProvision reads the latest protected journal entry. absence is only
// permission to start when the owner has also ruled out remote or receipt state.
func (s *Store) PublisherProvision(ctx context.Context, kind, binding string) ([]byte, int64, error) {
	if (kind != "group" && kind != "aws") || !validOpaqueValue(binding, 1024) {
		return nil, 0, ErrPublisherStateConflict
	}
	row, err := s.database.queries.LatestPublisherProvision(ctx, clientstatedb.LatestPublisherProvisionParams{ServerOrigin: s.controlEndpoint, Kind: kind, BindingKey: binding})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	document, err := s.secrets.Open(ctx, provisionContext(kind, binding, row.Revision), row.DocumentCiphertext)
	return document, row.Revision, err
}

// AppendPublisherProvision commits one transition before its external effect.
// the expected revision prevents a stale writer from replacing another key.
func (s *Store) AppendPublisherProvision(ctx context.Context, kind, binding string, previous int64, document []byte) error {
	if (kind != "group" && kind != "aws") || !validOpaqueValue(binding, 1024) || previous < 0 || len(document) > 65536 || !json.Valid(document) {
		return ErrPublisherStateConflict
	}
	sealed, err := s.secrets.Seal(ctx, provisionContext(kind, binding, previous+1), document)
	if err != nil {
		return err
	}
	rows, err := s.database.queries.AppendPublisherProvision(ctx, clientstatedb.AppendPublisherProvisionParams{
		ServerOrigin: s.controlEndpoint, Kind: kind, BindingKey: binding, PreviousRevision: previous,
		DocumentCiphertext: sealed, CreatedAt: s.database.now().UTC().UnixNano(),
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrPublisherStateConflict
	}
	return nil
}
