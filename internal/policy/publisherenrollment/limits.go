// package publisherenrollment defines enrollment ceilings shared by control,
// server configuration and client validation. it starts no work and grants no
// publisher authority; state applies these limits inside admission transactions.
package publisherenrollment

import (
	"errors"
	"math"
	"time"
)

const (
	MaxMembers  = math.MaxInt32
	MaxLifetime = 365 * 24 * time.Hour
)

type Limits struct {
	Members           int
	Lifetime          time.Duration
	ProjectPublishers int
}

func Default() Limits {
	return Limits{Members: 256, Lifetime: 24 * time.Hour, ProjectPublishers: 256}
}

func (l Limits) Validate() error {
	if l.Members < 1 || l.Members > MaxMembers || l.ProjectPublishers < 1 || l.ProjectPublishers > MaxMembers ||
		l.Lifetime < time.Minute || l.Lifetime > MaxLifetime || l.Lifetime%time.Second != 0 {
		return errors.New("publisher enrollment ceilings require positive 32-bit counts and a whole-second lifetime from 1m to 8760h")
	}
	return nil
}

func ValidRequest(members int, lifetime time.Duration) bool {
	return members >= 1 && members <= MaxMembers && lifetime >= time.Minute && lifetime <= MaxLifetime && lifetime%time.Second == 0
}
