package state

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestCertificateWorkSubjectBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	managed := controlstatedb.ControlAcmeOrder{ID: "order", ServiceID: "opaque-service", ServiceRunID: "service-run", ServiceRunNumber: 11,
		OrderRevision: 3, WorkEpoch: 2, WorkOwner: text("worker"), WorkExpiresAt: timestamptz(now.Add(time.Minute)), Attempts: 1,
		AvailableAt: timestamptz(now), CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now), CsrDigest: make([]byte, 32), State: "pending", ChallengeMethod: "dns-01"}
	for _, tc := range []struct {
		name   string
		row    controlstatedb.ControlAcmeOrder
		kind   CertificateSubjectKind
		change func(*controlstatedb.ControlAcmeOrder)
	}{
		{"managed without prefix", managed, CertificateSubjectService, nil},
		{"negative number", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.ServiceRunNumber = -1 }},
		{"missing run", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.ServiceRunID = "" }},
		{"missing service", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.ServiceID = "" }},
		{"missing number", managed, "", func(r *controlstatedb.ControlAcmeOrder) { r.ServiceRunNumber = 0 }},
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
			if err != nil || work.Subject.Kind != tc.kind || !work.Subject.Valid() {
				t.Fatalf("loaded subject: %#v, %v", work.Subject, err)
			}
			if err := validateACMEOrderWork(work); err != nil {
				t.Fatal(err)
			}
			work.Subject.RunNumber = 0
			if err := validateACMEOrderWork(work); !errors.Is(err, ErrCertificateIssuanceInvalid) {
				t.Fatal("invalid certificate subject accepted")
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
		{CertificateSubjectService, "opaque-managed-id", "-- name: GetPrivateDNSChallengeContext :one"},
		{"public_url", "svc_misleading-id", ""},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			db := &dnsSubjectDispatchDB{}
			_, err := dnsChallengeContext(t.Context(), controlstatedb.New(db), CertificateSubject{Kind: tc.kind, ID: tc.id, RunID: "run", RunNumber: 1}, "authorization")
			if tc.sql == "" {
				if !errors.Is(err, ErrDNSChallengeNotFound) || db.query != "" {
					t.Fatal("invalid subject reached SQL", err)
				}
				return
			}
			if !errors.Is(err, ErrDNSChallengeNotFound) || len(db.query) < len(tc.sql) || db.query[:len(tc.sql)] != tc.sql {
				t.Fatalf("DNS SQL did not dispatch by certificate subject kind: %v", err)
			}
		})
	}
}
