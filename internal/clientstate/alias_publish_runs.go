package clientstate

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

type AliasPublishRun struct {
	Selection   AliasSelection
	Owner       string
	Receiver    TunnelInfo
	PublicURLID string
	Number      uint64
}

func (d *Database) MarkAliasRunReady(ctx context.Context, run AliasPublishRun) error {
	number, err := databaseVersion(run.Number)
	if err != nil || run.Number == 0 || run.Owner == "" || run.PublicURLID == "" {
		return errors.New("invalid alias publish run")
	}
	targetNumber, err := databaseVersion(run.Receiver.PublishRunNumber)
	if err != nil {
		return err
	}
	count, err := d.queries.MarkAliasRunReady(ctx, clientstatedb.MarkAliasRunReadyParams{
		AliasID: run.Selection.ID, Owner: run.Owner, TunnelID: run.Receiver.ID,
		SelectionRevision: int64(run.Selection.Revision), PublicURLID: run.PublicURLID, PublishRunNumber: number,
		TargetPublicURLID: run.Receiver.PublicURLID, TargetPublishRunNumber: targetNumber, Now: d.now().UTC().UnixNano(),
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrAliasSelectionStale
	}
	return d.RecordAliasFailure(ctx, run.Selection, "")
}

func (d *Database) ClearAliasRun(ctx context.Context, aliasID, owner string) error {
	return d.queries.ClearAliasRun(ctx, clientstatedb.ClearAliasRunParams{AliasID: aliasID, Owner: owner})
}

func (d *Database) RecordAliasFailure(ctx context.Context, selection AliasSelection, reason failure.Reason) error {
	if reason != "" {
		if _, found := failure.DefinitionFor(reason); !found {
			return errors.New("invalid alias failure reason")
		}
	}
	return d.queries.RecordAliasFailure(ctx, clientstatedb.RecordAliasFailureParams{
		AliasID: selection.ID, SelectionRevision: int64(selection.Revision), ProjectRoot: selection.Project, Reason: string(reason),
	})
}
