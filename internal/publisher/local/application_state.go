package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func (a *appRuntime) applicationState() (*clientstate.ApplicationPublications, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.publications != nil {
		return a.publications, nil
	}
	worktree := a.project.Worktree.Root
	if worktree == "" {
		worktree = a.project.Root
	}
	p, err := clientstate.OpenApplicationPublications(a.state.Root(), a.project.Root, worktree, len(publisherapp.ConfiguredServices(a.project)))
	if err != nil {
		return nil, err
	}
	a.publications = p
	return p, nil
}

func (a *appRuntime) applicationCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	a.mu.Lock()
	deadline := a.cleanupDeadline
	a.mu.Unlock()
	limit := time.Now().Add(10 * time.Second)
	if deadline.IsZero() || limit.Before(deadline) {
		deadline = limit
	}
	return context.WithDeadline(ctx, deadline)
}

func (a *appRuntime) applicationCheckpoint(ctx context.Context, request publisherprotocol.ApplicationPublication, fingerprint [32]byte) (*clientstate.ApplicationPublication, error) {
	if a.manager.Alive != nil && !a.manager.Alive(request.Pid) {
		return nil, publisherapp.ErrRegistrationStale
	}
	p, err := a.applicationState()
	if err != nil {
		return nil, err
	}
	_, digest, err := a.project.Snapshot()
	if err != nil {
		return nil, err
	}
	owner := sha256.Sum256([]byte(request.Owner))
	source, err := applicationSourceProof(request.Auth, false)
	if err != nil {
		return nil, err
	}
	binding := clientstate.ApplicationPublicationBinding{ServerURL: request.ServerUrl, InvocationID: request.InvocationId, OwnerHash: hex.EncodeToString(owner[:]), PID: request.Pid, Target: request.Target, ConfigurationDigest: digest, RequestDigest: hex.EncodeToString(fingerprint[:]), ResourceID: valueOrEmpty(request.ResourceId), SourceKind: string(source.selection.Kind), SourceMachineID: source.selection.MachineId, SourceKeyID: source.selection.KeyId}
	if request.Allocate != nil {
		binding.Namespace = request.Allocate.Namespace
	}
	entry, err := p.Publication(ctx, binding, time.Now().Add(publisherapp.LeaseDuration))
	if err != nil {
		return nil, err
	}
	record, err := entry.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	clear(record.NativeKey)
	if !record.OwnerExpiresAt.After(time.Now()) || record.ConfirmationPending() && !time.Now().Before(record.ConfirmationDeadline) {
		return nil, publisherapp.ErrRegistrationStale
	}
	return entry, nil
}

// retryApplicationCleanup runs only under the existing native process owner.
// pending records outlive registration and do not need a current source proof.
func (a *appRuntime) retryApplicationCleanup(ctx context.Context) (bool, error) {
	if a.publications == nil {
		return false, nil
	}
	entries, err := a.publications.Entries(ctx)
	if err != nil {
		return true, err
	}
	var result error
	for _, entry := range entries {
		release, err := a.beginPreparation(ctx, entry.Binding().InvocationID)
		if err != nil {
			return true, errors.Join(result, err)
		}
		err = a.retryApplicationEntry(ctx, entry)
		release()
		result = errors.Join(result, err)
	}
	remaining, err := a.publications.Pending(ctx)
	return len(remaining) != 0 || err != nil, errors.Join(result, err)
}

func (a *appRuntime) retryApplicationEntry(ctx context.Context, entry *clientstate.ApplicationPublication) error {
	record, err := entry.Snapshot(ctx)
	if err != nil {
		return err
	}
	clear(record.NativeKey)
	alive := a.manager.Alive == nil || a.manager.Alive(record.Binding.PID)
	if record.Phase == clientstate.ApplicationCleanupDone {
		if !alive {
			return entry.RemoveCompleted(ctx)
		}
		return nil
	}
	cleanup := record.Phase == clientstate.ApplicationCleanupPending || record.Phase == clientstate.ApplicationDenied || !alive || !record.OwnerExpiresAt.After(time.Now()) || record.ConfirmationPending() && !record.ConfirmationDeadline.After(time.Now()) || record.Publisher != nil && record.Phase != clientstate.ApplicationRefreshPending && !record.IdentityExpiresAt.After(time.Now())
	if !cleanup {
		return nil
	}
	if err := entry.RequestCleanup(ctx); err != nil {
		return err
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == record.Binding.InvocationID && service.RegistrationID != "" {
			// unregister invalidates and joins before original-key deletion.
			return a.manager.StopRegistration(service.Name, service.RegistrationID, service.Target)
		}
	}
	return cleanupApplicationEntry(ctx, entry)
}

func cleanupApplicationEntry(ctx context.Context, entry *clientstate.ApplicationPublication) error {
	record, err := entry.Snapshot(ctx)
	if err != nil {
		return err
	}
	clear(record.NativeKey)
	authority, err := clientauthority.New(record.Binding.ServerURL, nil, "")
	if err != nil {
		return err
	}
	return publisheridentity.CleanupApplicationPublication(ctx, entry, authority)
}

func (a *appRuntime) ownedApplication(ctx context.Context, invocation string, registration publisherprotocol.Registration) (*clientstate.ApplicationPublication, error) {
	p, err := a.applicationState()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(registration.Owner))
	entry, err := p.FindOwned(ctx, invocation, hex.EncodeToString(hash[:]), registration.Target)
	if err != nil {
		return nil, err
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == invocation && service.RegistrationID != "" && service.RegistrationID != registration.RegistrationID && (registration.RegistrationID != "" || entry == nil) {
			return nil, publisherapp.ErrRegistrationStale
		}
	}
	if service, found := a.manager.ServiceForRegistration(registration.RegistrationID); found && service.Name != invocation {
		return nil, publisherapp.ErrRegistrationStale
	}
	return entry, nil
}

func (a *appRuntime) unregisterApplication(ctx context.Context, invocation string, registration publisherprotocol.Registration) error {
	release, err := a.beginPreparation(ctx, invocation)
	if err != nil {
		return err
	}
	defer release()
	a.forgetApplicationChallenge(invocation)
	entry, err := a.ownedApplication(ctx, invocation, registration)
	if err != nil {
		return err
	}
	if entry == nil {
		if registration.RegistrationID == "" {
			return nil
		}
		return a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
	}
	if err := entry.RequestCleanup(ctx); err != nil {
		return err
	}
	if registration.RegistrationID == "" {
		for _, service := range a.manager.Snapshot().Services {
			if service.Name == invocation && service.RegistrationID != "" {
				registration.RegistrationID = service.RegistrationID
			}
		}
	}
	if _, found := a.manager.ServiceForRegistration(registration.RegistrationID); found {
		return a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
	}
	return cleanupApplicationEntry(ctx, entry)
}

func (a *appRuntime) renewApplication(ctx context.Context, invocation string, registration publisherprotocol.Registration) error {
	release, err := a.beginPreparation(ctx, invocation)
	if err != nil {
		return err
	}
	defer release()
	entry, err := a.ownedApplication(ctx, invocation, registration)
	if err != nil {
		return err
	}
	if entry != nil {
		if !a.manager.CurrentRegistration(invocation, registration.RegistrationID, registration.Target) {
			return publisherapp.ErrRegistrationStale
		}
		if err := entry.RenewOwner(ctx, time.Now().Add(publisherapp.LeaseDuration)); err != nil {
			return err
		}
	}
	return a.manager.RenewTarget(registration.RegistrationID, registration.Owner, registration.Target)
}

func (a *appRuntime) releaseApplication(ctx context.Context, invocation string) error {
	release, err := a.beginPreparation(ctx, invocation)
	if err != nil {
		return err
	}
	defer release()
	a.forgetApplicationChallenge(invocation)
	p, err := a.applicationState()
	if err != nil {
		return err
	}
	return p.ForgetCompleted(ctx, invocation)
}
