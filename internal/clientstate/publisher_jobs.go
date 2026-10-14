package clientstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type PublisherJob struct {
	PublicURLID, Server, Target, Protocol string
	Identity                              []byte
}

func (d *Database) SavePublisherJob(ctx context.Context, job PublisherJob) error {
	if !d.serviceOwned || !opaqueid.Valid(job.PublicURLID, opaqueid.PublicURLPrefix) ||
		job.Server == "" || job.Target == "" || job.Protocol == "" || len(job.Identity) == 0 {
		return errors.New("clientstate: invalid service-owned publisher job")
	}
	store, err := d.Server(ctx, job.Server)
	if err != nil {
		return err
	}
	sealed, err := store.secrets.Seal(ctx, publisherJobContext(job.PublicURLID), job.Identity)
	if err != nil {
		return fmt.Errorf("clientstate: protect publisher identity: %w", err)
	}
	return d.queries.SavePublisherJob(ctx, clientstatedb.SavePublisherJobParams{
		PublicURLID: job.PublicURLID, ServerOrigin: store.controlEndpoint,
		Target: job.Target, ServiceProtocol: job.Protocol, StoredIdentity: sealed,
		CreatedAt: d.now().UTC().UnixNano(),
	})
}

func (d *Database) PublisherJobs(ctx context.Context) ([]PublisherJob, error) {
	if !d.serviceOwned {
		return nil, errors.New("clientstate: publisher jobs require service-owned state")
	}
	rows, err := d.queries.ListPublisherJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientstate: list publisher jobs: %w", err)
	}
	jobs := make([]PublisherJob, 0, len(rows))
	for _, row := range rows {
		store, err := d.Server(ctx, row.ServerOrigin)
		if err != nil {
			return nil, err
		}
		identity, err := store.secrets.Open(ctx, publisherJobContext(row.PublicURLID), row.StoredIdentity)
		if err != nil {
			return nil, fmt.Errorf("clientstate: open publisher identity for %s: %w", row.PublicURLID, err)
		}
		jobs = append(jobs, PublisherJob{PublicURLID: row.PublicURLID, Server: row.ServerOrigin,
			Target: row.Target, Protocol: row.ServiceProtocol, Identity: identity})
	}
	return jobs, nil
}

func (d *Database) DeletePublisherJob(ctx context.Context, publicURLID string) error {
	if !d.serviceOwned || !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) {
		return errors.New("clientstate: invalid service-owned publisher job")
	}
	removed, err := d.queries.DeletePublisherJob(ctx, publicURLID)
	if err != nil {
		return err
	}
	if removed == 0 {
		return errors.New("clientstate: no background publisher for that public URL")
	}
	return nil
}

func publisherJobContext(id string) string { return "publisher-job:" + id + ":identity" }
