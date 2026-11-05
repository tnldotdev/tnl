package workload

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSessionOptionalHardDuration(t *testing.T) {
	session := sessionFixture(controlv1.WorkloadOIDC)
	session.ExpiresAt = nil
	if err := validateSession(session); err != nil || !SessionDeadline(session).Equal(session.IdentityExpiresAt) {
		t.Fatal("uncapped session lost its finite proof horizon", err)
	}
	data, err := json.Marshal(session)
	if err != nil || strings.Contains(string(data), `"expires_at"`) {
		t.Fatal("uncapped session serialized a synthetic hard deadline", err)
	}
	fresh := cloneSession(session)
	fresh.IdentityExpiresAt = fresh.IdentityExpiresAt.Add(time.Minute)
	if err := validateSessionUpdate(session, fresh); err != nil || !SessionDeadline(fresh).After(SessionDeadline(session)) {
		t.Fatal("same identity could not advance an uncapped proof horizon", err)
	}
	fresh.ExpiresAt = new(time.Now().Add(24 * time.Hour))
	if err := validateSessionUpdate(session, fresh); err != nil {
		t.Fatal("an uncapped session could not receive a finite hard limit", err)
	}
	copy := cloneSession(fresh)
	if !reflect.DeepEqual(copy, fresh) || copy.ExpiresAt == fresh.ExpiresAt {
		t.Fatal("session snapshots alias the optional deadline")
	}
	for _, deadline := range []*time.Time{nil, new(fresh.ExpiresAt.Add(time.Second))} {
		wider := cloneSession(fresh)
		wider.ExpiresAt = deadline
		if validateSessionUpdate(fresh, wider) == nil {
			t.Fatal("a hard deadline was removed or extended")
		}
	}
	fresh.ExpiresAt = new(time.Now().Add(2 * time.Minute))
	if !SessionDeadline(fresh).Equal(*fresh.ExpiresAt) {
		t.Fatal("proof refresh bypassed the absolute hard limit")
	}
}
