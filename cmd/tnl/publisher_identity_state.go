package main

import (
	"context"
	"crypto/ed25519"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/publisherjob"
)

// the durable directory owns the replica's keys and its cross-task writer lock.
// control records issuance history, so losing that directory never silently
// becomes permission to replace the keys with another certificate identity.
func withPublisherCertificateState(ctx context.Context, job publisherjob.Job, profile *clientstate.Store, private ed25519.PrivateKey, client *grouppublisher.Client, serve func(context.Context) error) error {
	if job.GroupMember == nil {
		return publisherjob.ErrScope
	}
	member := *job.GroupMember
	files, err := profile.PublisherIdentityFiles(member.TeamId, member.PublisherIdentityId)
	if err != nil {
		return err
	}
	lock, err := files.Lock(ctx, "publisher.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	lease, err := client.Lease(ctx, member, private)
	if err != nil {
		return err
	}
	assignments, err := client.Assignments(ctx, lease.AccessToken)
	if err != nil {
		return err
	}
	actual := assignments.Member
	actual.GroupName = member.GroupName
	if actual != member || assignments.CertificateStateRequired == nil {
		return failure.Wrap("read publisher certificate recovery boundary", failure.ServerResponseInvalid, publisherjob.ErrScope)
	}
	found, err := profile.PublisherCertificateMaterialExists(ctx, member.TeamId, member.PublisherIdentityId)
	if err != nil {
		return err
	}
	if *assignments.CertificateStateRequired && !found {
		return failure.Wrap("restore publisher certificate state", failure.PublisherCertificateStateMissing, clientstate.ErrPublisherStateConflict)
	}
	return serve(ctx)
}
