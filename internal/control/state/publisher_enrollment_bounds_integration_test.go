package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestIntegrationPublisherEnrollmentFixedBounds(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	_, request := deploymentPublisherRequest(t, d, now)
	request.MaxMembers, request.Lifetime = 256, 24*time.Hour
	for _, invalid := range []CreateDeploymentPublisherEnrollmentRequest{
		func() CreateDeploymentPublisherEnrollmentRequest { r := request; r.MaxMembers++; return r }(),
		func() CreateDeploymentPublisherEnrollmentRequest { r := request; r.Lifetime += time.Second; return r }(),
	} {
		if _, err := d.CreateDeploymentPublisherEnrollment(t.Context(), invalid); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatalf("accepted an enrollment beyond the fixed ceiling: %v", err)
		}
	}
	enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), request)
	if err != nil || enrollment.MaxMembers != 256 || !enrollment.ExpiresAt.Equal(request.Now.Add(24*time.Hour).Truncate(time.Microsecond)) {
		t.Fatal("maximum enrollment changed its bounds", err)
	}
	siblingRequest := request
	siblingRequest.Selector, siblingRequest.IdempotencyKey, siblingRequest.Services = "staging", "sibling", []string{"stage"}
	sibling, err := d.CreateDeploymentPublisherEnrollment(t.Context(), siblingRequest)
	if err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		public ed25519.PublicKey
		member DeploymentPublisherIdentity
		err    error
	}
	makeAttempt := func() attempt {
		t.Helper()
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return attempt{public: public}
	}
	first := makeAttempt()
	for index := range 255 {
		a := first
		if index != 0 {
			a = makeAttempt()
		}
		a.member, a.err = d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, a.public, request.Now)
		if a.err != nil {
			t.Fatal("rejected a member below both fixed bounds", index, a.err)
		}
		if index == 0 {
			first = a
		}
	}
	last := []attempt{makeAttempt(), makeAttempt()}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i, key := range []string{enrollment.Key, sibling.Key} {
		workers.Go(func() {
			<-start
			last[i].member, last[i].err = d.RedeemDeploymentPublisherEnrollment(t.Context(), key, last[i].public, request.Now)
		})
	}
	close(start)
	workers.Wait()
	accepted := 0
	for _, a := range last {
		if a.err == nil {
			accepted++
		} else if !errors.Is(a.err, ErrDeploymentPublisher) {
			t.Fatal("unexpected concurrent admission failure", a.err)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent enrollments shared one project slot, accepted %d", accepted)
	}
	if recovered, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.Key, first.public, request.Now); err != nil || recovered != first.member {
		t.Fatal("an exhausted project must still recover the same member", err)
	}
	if err := d.RevokeDeploymentPublisher(t.Context(), request.DeploymentScope, request.Selector, first.member.PublisherIdentityID, request.Now); err != nil {
		t.Fatal(err)
	}
	next := makeAttempt()
	if _, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), sibling.Key, next.public, request.Now); err != nil {
		t.Fatal("revocation did not free project capacity for another enrollment key", err)
	}
	d.ConfigureProjectPublisherLimits(map[string]int{request.TeamID + "/" + request.ProjectKey: 257})
	extra := makeAttempt()
	if _, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), sibling.Key, extra.public, request.Now); err != nil {
		t.Fatal("the project override did not allow a 257th publisher", err)
	}
	overLimit := makeAttempt()
	if _, err := d.RedeemDeploymentPublisherEnrollment(t.Context(), sibling.Key, overLimit.public, request.Now); !errors.Is(err, ErrDeploymentPublisher) {
		t.Fatalf("accepted a publisher beyond the project override: %v", err)
	}
}
