package controlstate

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestCertificateWorkSubjectBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	public := controlstatedb.ControlAcmeOrder{ID: "order", PublicURLID: "psvc_opaque-public-url", PublishRunID: "public-run", PublishRunNumber: 7, OrderRevision: 3, WorkEpoch: 2, WorkOwner: text("worker"), WorkExpiresAt: timestamptz(now.Add(time.Minute)), Attempts: 1, AvailableAt: timestamptz(now), CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now), CsrDigest: make([]byte, 32), State: "pending", ChallengeMethod: "dns-01"}
	managed := public
	managed.PublicURLID, managed.PublishRunID, managed.PublishRunNumber = "", "", 0
	managed.PrivateServiceID, managed.PrivateRunID, managed.PrivateRunNumber = "opaque-managed-service", "private-run", 11
	for _, tc := range []struct {
		name   string
		row    controlstatedb.ControlAcmeOrder
		kind   CertificateSubjectKind
		change func(*controlstatedb.ControlAcmeOrder)
	}{
		{"public URL with misleading prefix", public, CertificateSubjectPublicURL, nil},
		{"managed without prefix", managed, CertificateSubjectManagedService, nil},
		{"crossed service", public, "", func(r *controlstatedb.ControlAcmeOrder) { r.PrivateServiceID = "other" }},
		{"crossed run", public, "", func(r *controlstatedb.ControlAcmeOrder) { r.PrivateRunID = "other" }},
		{"crossed number", public, "", func(r *controlstatedb.ControlAcmeOrder) { r.PrivateRunNumber = 1 }},
		{"negative public number", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.PublishRunNumber = -1 }},
		{"missing public run", public, "", func(r *controlstatedb.ControlAcmeOrder) { r.PublishRunID = "" }},
		{"missing managed service", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.PrivateServiceID = "" }},
		{"missing number", public, "", func(r *controlstatedb.ControlAcmeOrder) { r.PublishRunNumber = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := tc.row
			if tc.change != nil {
				tc.change(&row)
			}
			work, err := acmeOrderWork(row, ACMEAccount{}, nil, true)
			if tc.kind == "" {
				if err == nil {
					t.Fatal("crossed certificate subject loaded")
				}
				return
			}
			if err != nil || work.Subject.Kind != tc.kind || !work.Subject.Valid() || work.ServiceID() != work.Subject.ID {
				t.Fatalf("loaded subject: %#v, %v", work.Subject, err)
			}
			if err := validateACMEOrderWork(work); err != nil {
				t.Fatal(err)
			}
			work.Subject.RunNumber++
			if err := validateACMEOrderWork(work); !errors.Is(err, ErrCertificateIssuanceInvalid) {
				t.Fatal("cached subject and compatibility run diverged")
			}
		})
	}
}

func TestCertificateWorkRevisionBoundary(t *testing.T) {
	for _, tc := range []struct {
		revision, epoch uint64
		valid           bool
	}{
		{1, 1, true}, {math.MaxInt64 - 1, math.MaxInt64, true},
		{0, 1, false}, {1, 0, false}, {math.MaxInt64, 1, false},
		{math.MaxInt64 + 1, 1, false}, {1, math.MaxInt64 + 1, false}, {math.MaxUint64, math.MaxUint64, false},
	} {
		binding, err := checkedACMEWorkBinding(tc.revision, tc.epoch)
		if (err == nil) != tc.valid {
			t.Fatalf("revision %d epoch %d: %v", tc.revision, tc.epoch, err)
		}
		if tc.valid && (uint64(binding.orderRevision) != tc.revision || uint64(binding.workerEpoch) != tc.epoch) {
			t.Fatal("ACME worker binding was clamped")
		}
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	authorization := ACMEAuthorizationWork{Identifier: "app.example.test", AuthorizationURL: "https://acme.example.test/authorization", State: ACMEAuthorizationComplete, AvailableAt: now, ValidatedAt: &now, CleanupCompletedAt: &now, ExpiresAt: &expires}
	for _, revision := range []uint64{0, 1, math.MaxInt64 - 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		authorization.Revision = revision
		err := validateACMEAuthorizationWork(authorization)
		if (err == nil) != (revision < math.MaxInt64) {
			t.Fatalf("authorization revision %d: %v", revision, err)
		}
	}
}

type dnsSubjectDispatchDB struct {
	query string
}

func (d *dnsSubjectDispatchDB) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	d.query = query
	return missingDNSSubjectRow{}
}

func (*dnsSubjectDispatchDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected DNS presentation query")
}

func (*dnsSubjectDispatchDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected DNS mutation")
}

type missingDNSSubjectRow struct{}

func (missingDNSSubjectRow) Scan(...any) error { return pgx.ErrNoRows }

func TestCertificateWorkDNSDispatchBoundary(t *testing.T) {
	for _, tc := range []struct {
		kind CertificateSubjectKind
		id   string
		sql  string
	}{
		{CertificateSubjectPublicURL, "psvc_misleading-public-id", "-- name: GetDNSChallengeContext :one"},
		{CertificateSubjectManagedService, "opaque-managed-id", "-- name: GetPrivateDNSChallengeContext :one"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			db := &dnsSubjectDispatchDB{}
			_, err := dnsChallengeContext(t.Context(), controlstatedb.New(db), CertificateSubject{Kind: tc.kind, ID: tc.id, RunID: "run", RunNumber: 1}, "authorization")
			if !errors.Is(err, ErrDNSChallengeNotFound) || len(db.query) < len(tc.sql) || db.query[:len(tc.sql)] != tc.sql {
				t.Fatalf("DNS SQL did not dispatch by certificate subject kind: %v", err)
			}
		})
	}
}
