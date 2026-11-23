package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/certificatetest"
)

// hold the parent locks of a sibling heartbeat through the operation. then
// queue the operation behind a service writer before it stages disablement.
func checkServiceObservationLocks(t *testing.T, d *Database, service string, operation func(context.Context) error, denied error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	sibling, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, sibling)
	if err := lockServiceForRun(ctx, sibling, service); err != nil {
		t.Fatal(err)
	}
	if err := operation(ctx); err != nil {
		t.Fatal("operation during sibling heartbeat:", err)
	}
	if err := sibling.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	edit, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, edit)
	if err := queueRunWriter(ctx, edit, service); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() { done <- operation(ctx) })
	waitForPostgresBlock(t, ctx, d, int32(edit.Conn().PgConn().PID()), done)
	if _, err := edit.Exec(ctx, `UPDATE control.services SET enabled=false WHERE id=$1`, service); err != nil {
		t.Fatal(err)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, denied) {
		t.Fatal("operation after service disablement:", err)
	}
}

func TestIntegrationSuppliedCertificateInstallLocks(t *testing.T) {
	f, parent := suppliedAliasFixture(t)
	issuer := certificatetest.New(t, f.now)
	material := issuer.Issue(t, []string{"*." + parent}, f.now, f.now.Add(time.Hour), nil)
	checkServiceObservationLocks(t, f.database, f.service.ID, func(ctx context.Context) error {
		_, err := f.database.markSuppliedServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber, string(material.Chain), "", f.now, issuer.Roots)
		return err
	}, ErrServiceAccess)
}

func TestIntegrationManagedCertificateRunLocks(t *testing.T) {
	for _, operation := range []string{"issue", "install"} {
		t.Run(operation, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			work := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, true, nil)
			checkServiceObservationLocks(t, f.database, f.service.ID, func(ctx context.Context) error {
				if operation == "issue" {
					_, err := f.database.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token, work.Account.DirectoryURL, "retry-csr", f.run.RunNumber, work.CSRDER, f.now)
					return err
				}
				return f.database.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, work.ID, f.run.RunNumber, *work.NotAfter, f.now)
			}, ErrServiceAccess)
		})
	}
}
