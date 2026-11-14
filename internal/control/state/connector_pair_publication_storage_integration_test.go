package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func connectorPublicationStorageFixture(t *testing.T) publishRunFixture {
	t.Helper()
	d, now, request, leases := newConnectorPairPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, creation, now)
	request.PublicURLID, request.TeamID, request.MembershipID = url.ID, url.TeamID, url.MembershipID
	request.ActingIdentityID, request.PolicyRevision = creation.ActingIdentityID, uint64(url.PolicyRevision)
	request.CertificateIdentifiers, request.ExpectedMutationRevision = []string{url.CanonicalHostname}, url.MutationRevision
	setup, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
}

func connectorPublicPairStorageInput(t *testing.T, f publishRunFixture, saved controlstatedb.ControlConnectorPeerPair) controlstatedb.InsertConnectorPeerPairParams {
	t.Helper()
	id, err := opaqueid.New("cpp_")
	if err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256([]byte("storage-fixture-secret/" + id))
	sealed, err := f.database.storageKey.Seal(connectorPeerPairKeyContext(id), secret[:])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret[:])
	delivery := sha256.Sum256([]byte("storage-fixture-delivery/" + id))
	return controlstatedb.InsertConnectorPeerPairParams{
		ID: id, PublicURLID: f.request.PublicURLID, PublishRunID: f.setup.PublishRunID, PublishRunNumber: int64(f.setup.PublishRunNumber),
		PublisherIdentityID: saved.PublisherIdentityID, SubjectKind: string(saved.SubjectKind), SubjectID: saved.SubjectID,
		ParentControlSessionID: saved.ParentControlSessionID, OwnerKey: saved.OwnerKey, IdempotencyKey: saved.IdempotencyKey,
		RequestDigest: saved.RequestDigest, KeyDigest: digest[:], KeyCiphertext: sealed, DeliveryID: delivery[:16],
		StorageKeyID: f.database.storageKey.CurrentID(), Slots: saved.Slots,
		Now: timestamptz(f.now), RequestAt: timestamptz(f.now), ExpiresAt: timestamptz(f.now.Add(10 * time.Second)),
	}
}

func requireConnectorStorageError(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) || postgres == nil || postgres.Code != code || constraint != "" && postgres.ConstraintName != constraint {
		// PostgreSQL's detail can contain delivery secrets. report only its
		// classification and the authored constraint, never the complete error.
		if postgres != nil {
			t.Fatalf("wanted PostgreSQL %s at %s; got %s at %s", code, constraint, postgres.Code, postgres.ConstraintName)
		}
		t.Fatalf("wanted PostgreSQL %s at %s; got %T", code, constraint, err)
	}
}

func requireConnectorStorageWrite(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) && postgres != nil {
		t.Fatalf("typed storage write failed: PostgreSQL %s at %s", postgres.Code, postgres.ConstraintName)
	}
	t.Fatalf("typed storage write failed: %T", err)
}

func TestIntegrationConnectorPairStorageKeepsTypedPublicationAndOwnerIsolation(t *testing.T) {
	public := connectorPublicationStorageFixture(t)
	native := connectorPairFixtureFromRun(t, public)
	private := native.create(t)
	q := controlstatedb.New(public.database.pool)
	saved, err := q.LockConnectorPeerPairForLegClaim(t.Context(), private.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := connectorPublicPairStorageInput(t, public, saved)
	preview, err := public.database.CreatePreview(t.Context(), public.request.TeamID, public.request.ActingIdentityID, "storage-preview", public.now)
	if err != nil {
		t.Fatal(err)
	}
	// storage pins a selected preview; this is not an authorization decision
	// that the current visitor or public URL belongs to that preview.
	input.PreviewID = text(preview.ID)
	row, err := q.InsertConnectorPeerPair(t.Context(), input)
	requireConnectorStorageWrite(t, err)
	if row.PublicURLID != input.PublicURLID || row.PublishRunID != input.PublishRunID || row.PublishRunNumber != input.PublishRunNumber ||
		row.ServiceID != "" || row.ServiceRunID != "" || row.RunNumber != 0 ||
		row.ServiceParentID.Valid || row.ServiceRunParentID.Valid || row.PublicURLParentID.String != input.PublicURLID || row.PublishRunParentID.String != input.PublishRunID || row.PreviewID.String != preview.ID {
		t.Fatal("public URL storage invented a service identity or lost its exact parent")
	}
	_, err = public.database.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET preview_id=NULL WHERE id=$1`, row.ID)
	requireConnectorStorageError(t, err, "23514", "connector_peer_pairs_publication_immutable")
	for _, selected := range []struct {
		serviceRun, publishRun, pair string
	}{
		{saved.ServiceRunID, "", saved.ID},
		{"", row.PublishRunID, row.ID},
	} {
		owner, err := q.GetConnectorPeerPairForOwner(t.Context(), controlstatedb.GetConnectorPeerPairForOwnerParams{
			SubjectKind: input.SubjectKind, SubjectID: input.SubjectID, ServiceRunID: selected.serviceRun,
			PublishRunID: selected.publishRun, OwnerKey: input.OwnerKey})
		if err != nil || owner.ID != selected.pair {
			t.Fatal("the same subject/owner key crossed publication families", err)
		}
		count, err := q.CountConnectorPeerPairOwners(t.Context(), controlstatedb.CountConnectorPeerPairOwnersParams{
			ServiceRunID: selected.serviceRun, PublishRunID: selected.publishRun, Now: timestamptz(public.now), OwnerLimit: 64})
		if err != nil || count != 1 {
			t.Fatal("owner capacity combined different publication runs", err)
		}
	}
	for _, instant := range []struct {
		at   time.Time
		want int64
	}{
		{row.ExpiresAt.Time, 1},
		{row.ReplayFenceUntil.Time.Add(-time.Microsecond), 1},
		{row.ReplayFenceUntil.Time, 0},
	} {
		count, err := q.CountConnectorPeerPairOwners(t.Context(), controlstatedb.CountConnectorPeerPairOwnersParams{
			PublishRunID: row.PublishRunID, Now: timestamptz(instant.at), OwnerLimit: 64})
		if err != nil || count != instant.want {
			t.Fatal("public URL owner capacity lost its exact replay horizon", err)
		}
	}
	if _, err := q.GetConnectorPeerPairForOwner(t.Context(), controlstatedb.GetConnectorPeerPairForOwnerParams{
		SubjectKind: input.SubjectKind, SubjectID: input.SubjectID, OwnerKey: input.OwnerKey,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("an empty publication selected an arbitrary connector owner", err)
	}
	replay := connectorPublicPairStorageInput(t, public, saved)
	_, err = q.InsertConnectorPeerPair(t.Context(), replay)
	requireConnectorStorageError(t, err, "23505", "")
	if _, err := q.ReplaceConnectorPeerPair(t.Context(), row.ID); err != nil {
		t.Fatal(err)
	}
	retained, err := q.GetConnectorPeerPairForOwner(t.Context(), controlstatedb.GetConnectorPeerPairForOwnerParams{
		SubjectKind: input.SubjectKind, SubjectID: input.SubjectID, ServiceRunID: saved.ServiceRunID, OwnerKey: input.OwnerKey})
	if err != nil || retained.ID != saved.ID {
		t.Fatal("public pair replacement removed the service owner's state", err)
	}
}

func TestIntegrationConnectorPairStorageRejectsMixedIncompleteAndSubstitutedParents(t *testing.T) {
	public := connectorPublicationStorageFixture(t)
	native := connectorPairFixtureFromRun(t, public)
	private := native.create(t)
	q := controlstatedb.New(public.database.pool)
	saved, err := q.LockConnectorPeerPairForLegClaim(t.Context(), private.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name             string
		edit             func(*controlstatedb.InsertConnectorPeerPairParams)
		code, constraint string
	}{
		{"mixed service", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.ServiceID = saved.ServiceID }, "23514", "connector_peer_pairs_publication"},
		{"mixed service run", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.ServiceRunID = saved.ServiceRunID }, "23514", "connector_peer_pairs_publication"},
		{"mixed run number", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.RunNumber = saved.RunNumber }, "23514", "connector_peer_pairs_publication"},
		{"missing public URL", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublicURLID = "" }, "23514", "connector_peer_pairs_publication"},
		{"missing publish run", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublishRunID = "" }, "23514", "connector_peer_pairs_publication"},
		{"missing run number", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublishRunNumber = 0 }, "23514", "connector_peer_pairs_publication"},
		{"service in URL field", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublicURLID = saved.ServiceID }, "23514", "connector_peer_pairs_publication"},
		{"service run in publish field", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublishRunID = saved.ServiceRunID }, "23514", "connector_peer_pairs_publication"},
		{"service with preview", func(p *controlstatedb.InsertConnectorPeerPairParams) {
			p.ServiceID, p.ServiceRunID, p.RunNumber = saved.ServiceID, saved.ServiceRunID, saved.RunNumber
			p.PublicURLID, p.PublishRunID, p.PublishRunNumber = "", "", 0
			p.PreviewID = text("pv_1234567890123456789012")
		}, "23514", "connector_peer_pairs_publication"},
		{"another URL", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublicURLID = "url_1234567890123456789012" }, "23503", "connector_peer_pairs_public_run"},
		{"another run", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublishRunID = "pr_1234567890123456789012" }, "23503", "connector_peer_pairs_public_run"},
		{"another run number", func(p *controlstatedb.InsertConnectorPeerPairParams) { p.PublishRunNumber++ }, "23503", "connector_peer_pairs_public_run"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := connectorPublicPairStorageInput(t, public, saved)
			test.edit(&input)
			_, err := q.InsertConnectorPeerPair(t.Context(), input)
			requireConnectorStorageError(t, err, test.code, test.constraint)
		})
	}
	input := connectorPublicPairStorageInput(t, public, saved)
	row, err := q.InsertConnectorPeerPair(t.Context(), input)
	requireConnectorStorageWrite(t, err)
	_, err = public.database.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs
		SET service_id=$2,service_run_id=$3,run_number=$4,public_url_id='',publish_run_id='',publish_run_number=0 WHERE id=$1`,
		row.ID, saved.ServiceID, saved.ServiceRunID, saved.RunNumber)
	requireConnectorStorageError(t, err, "23514", "connector_peer_pairs_publication_immutable")
	unchanged, err := q.LockConnectorPeerPairForLegClaim(t.Context(), row.ID)
	if err != nil || unchanged.PublicURLID != row.PublicURLID || unchanged.PublishRunID != row.PublishRunID || unchanged.ServiceID != "" {
		t.Fatal("failed publication substitution changed the retained owner", err)
	}
}

func TestIntegrationConnectorPairAuditStorageKeepsPublicationAfterReplacement(t *testing.T) {
	public := connectorPublicationStorageFixture(t)
	native := connectorPairFixtureFromRun(t, public)
	private := native.create(t)
	q := controlstatedb.New(public.database.pool)
	saved, err := q.LockConnectorPeerPairForLegClaim(t.Context(), private.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := connectorPublicPairStorageInput(t, public, saved)
	row, err := q.InsertConnectorPeerPair(t.Context(), input)
	requireConnectorStorageWrite(t, err)
	_, err = public.database.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_audit_bindings
		(pair_id,public_url_id,publish_run_id,publish_run_number,publisher_identity_id,source_ip,created_at,expires_at,delivery_generation)
		VALUES ($1,$2,$3,$4,$5,'192.0.2.1',$6,$7,$8)`, row.ID, row.PublicURLID, row.PublishRunID, row.PublishRunNumber,
		row.PublisherIdentityID, public.now, row.ExpiresAt.Time, row.DeliveryGeneration)
	if err != nil {
		t.Fatal("public URL audit binding lost its typed run", err)
	}
	_, err = public.database.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_audit_bindings
		(pair_id,service_id,service_run_id,run_number,public_url_id,publish_run_id,publish_run_number,publisher_identity_id,source_ip,created_at,expires_at,delivery_generation)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'192.0.2.1',$9,$10,$11)`, row.ID, saved.ServiceID, saved.ServiceRunID, saved.RunNumber,
		row.PublicURLID, row.PublishRunID, row.PublishRunNumber, row.PublisherIdentityID, public.now, row.ExpiresAt.Time, row.DeliveryGeneration+1)
	requireConnectorStorageError(t, err, "23514", "connector_peer_audit_publication")
	for _, test := range []struct {
		name, publicURL, run string
		number               int64
		code, constraint     string
	}{
		{"missing URL", "", row.PublishRunID, row.PublishRunNumber, "23514", "connector_peer_audit_publication"},
		{"missing run", row.PublicURLID, "", row.PublishRunNumber, "23514", "connector_peer_audit_publication"},
		{"missing number", row.PublicURLID, row.PublishRunID, 0, "23514", "connector_peer_audit_publication"},
		{"URL substitution", "url_1234567890123456789012", row.PublishRunID, row.PublishRunNumber, "23503", "connector_peer_audit_public_run"},
		{"run substitution", row.PublicURLID, "pr_1234567890123456789012", row.PublishRunNumber, "23503", "connector_peer_audit_public_run"},
		{"number substitution", row.PublicURLID, row.PublishRunID, row.PublishRunNumber + 1, "23503", "connector_peer_audit_public_run"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := public.database.pool.Exec(t.Context(), `INSERT INTO control.connector_peer_audit_bindings
				(pair_id,public_url_id,publish_run_id,publish_run_number,publisher_identity_id,source_ip,created_at,expires_at,delivery_generation)
				VALUES ($1,$2,$3,$4,$5,'192.0.2.1',$6,$7,$8)`, row.ID, test.publicURL, test.run, test.number,
				row.PublisherIdentityID, public.now, row.ExpiresAt.Time, row.DeliveryGeneration+1)
			requireConnectorStorageError(t, err, test.code, test.constraint)
		})
	}
	if _, err := q.ReplaceConnectorPeerPair(t.Context(), row.ID); err != nil {
		t.Fatal(err)
	}
	var retained bool
	err = public.database.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.connector_peer_audit_bindings
		WHERE pair_id=$1 AND public_url_id=$2 AND publish_run_id=$3 AND publish_run_number=$4
		AND service_id='' AND service_run_id='' AND run_number=0)`, row.ID, row.PublicURLID, row.PublishRunID, row.PublishRunNumber).Scan(&retained)
	if err != nil || !retained {
		t.Fatal("pair replacement erased the typed audit binding", err)
	}
}
