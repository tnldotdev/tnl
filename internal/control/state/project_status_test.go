package state

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestProjectPublicationReasons(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ready := controlstatedb.ListProjectPublicationsRow{ServiceID: text("service"), Enabled: true, RunID: "run", PublicationState: "ready", Healthy: true, PublisherExpiresAt: timestamptz(now.Add(time.Minute)), CertificateExpiresAt: timestamptz(now.Add(time.Hour)), ReadyAt: timestamptz(now.Add(-time.Minute))}
	for _, test := range []struct {
		name        string
		edit        func(*controlstatedb.ListProjectPublicationsRow)
		connections int
		want        string
	}{
		{"ready", func(*controlstatedb.ListProjectPublicationsRow) {}, 2, "ready"},
		{"one surviving connection", func(*controlstatedb.ListProjectPublicationsRow) {}, 1, "ready"},
		{"lost both connections", func(*controlstatedb.ListProjectPublicationsRow) {}, 0, "connections_pending"},
		{"first readiness needs two", func(r *controlstatedb.ListProjectPublicationsRow) { r.ReadyAt.Valid = false }, 1, "connections_pending"},
		{"not realized", func(r *controlstatedb.ListProjectPublicationsRow) { r.ServiceID.Valid = false }, 0, "not_realized"},
		{"disabled", func(r *controlstatedb.ListProjectPublicationsRow) { r.Enabled = false }, 2, "disabled"},
		{"idle", func(r *controlstatedb.ListProjectPublicationsRow) { r.RunID = "" }, 0, "not_publishing"},
		{"expired publisher", func(r *controlstatedb.ListProjectPublicationsRow) { r.PublisherExpiresAt = timestamptz(now) }, 2, "publisher_expired"},
		{"missing certificate", func(r *controlstatedb.ListProjectPublicationsRow) { r.CertificateExpiresAt.Valid = false }, 2, "certificate_pending"},
		{"expired certificate", func(r *controlstatedb.ListProjectPublicationsRow) { r.CertificateExpiresAt = timestamptz(now) }, 2, "certificate_expired"},
		{"unhealthy publisher", func(r *controlstatedb.ListProjectPublicationsRow) { r.Healthy = false }, 2, "publisher_unhealthy"},
		{"not committed ready", func(r *controlstatedb.ListProjectPublicationsRow) { r.PublicationState = "starting" }, 2, "starting"},
		{"pending DNS", func(r *controlstatedb.ListProjectPublicationsRow) {
			r.ServiceID.Valid = false
			r.PublicURLID = text("url")
			r.DnsState = "pending"
		}, 2, "dns_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := ready
			test.edit(&row)
			if got := projectPublicationReason(row, test.connections, now); got != test.want {
				t.Fatalf("reason=%s want=%s", got, test.want)
			}
		})
	}
}
