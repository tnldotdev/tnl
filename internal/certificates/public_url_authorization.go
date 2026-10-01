package certificates

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

// discoverAuthorizations stores a complete set only after every CA identity is checked.
func (w *PublicURLWorker) discoverAuthorizations(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, order acmeclient.Order, now time.Time) error {
	expected := make(map[string]struct{}, len(work.CertificateIdentifiers))
	for _, identifier := range work.CertificateIdentifiers {
		expected[identifier] = struct{}{}
	}
	seen := make(map[string]struct{}, len(order.Authorizations))
	authorizations := make([]controlstate.ACMEAuthorizationWork, 0, len(order.Authorizations))
	for _, authorizationURL := range order.Authorizations {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return err
		}
		if authorizationURL == "" || authorization.URL != authorizationURL || authorization.Identifier.Type != "dns" {
			return terminalf("order authorization identity does not match %q", authorizationURL)
		}
		value, err := authorizationWork(client, authorization, work.ChallengeMethod, order.Expires, now)
		if err != nil {
			return err
		}
		if _, exists := expected[value.Identifier]; !exists {
			return terminalf("order authorization identifier %q is not in the certificate plan", value.Identifier)
		}
		if _, exists := seen[value.Identifier]; exists {
			return terminalf("order repeats authorization identifier %q", value.Identifier)
		}
		seen[value.Identifier] = struct{}{}
		authorizations = append(authorizations, value)
	}
	if len(authorizations) != len(expected) || !sameAuthorizationURLs(order.Authorizations, authorizations) {
		return terminalf("pending order authorizations do not match the certificate plan")
	}
	work.Authorizations = authorizations
	if allAuthorizationsValid(authorizations) {
		work.State = "ready_to_finalize"
	}
	work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
	return nil
}

func validateActiveAuthorizations(authorizations []controlstate.ACMEAuthorizationWork) error {
	for _, authorization := range authorizations {
		switch authorization.State {
		case "presenting", "presented", "validating", "valid", "complete":
		case "failed", "canceled", "cleaning":
			return terminalf("authorization for %q is in state %q", authorization.Identifier, authorization.State)
		default:
			return terminalf("unknown persisted authorization state %q", authorization.State)
		}
	}
	return nil
}

// advanceAuthorizations performs at most one action per claim. present every
// challenge before checking any presented one so shared DNS names are complete.
func (w *PublicURLWorker) advanceAuthorizations(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) (bool, error) {
	for _, phase := range []controlstate.ACMEAuthorizationState{
		controlstate.ACMEAuthorizationPresenting, controlstate.ACMEAuthorizationPresented, controlstate.ACMEAuthorizationValidating,
	} {
		for index := range work.Authorizations {
			authorization := &work.Authorizations[index]
			if authorization.State != phase || authorization.AvailableAt.After(now) {
				continue
			}
			var err error
			switch phase {
			case controlstate.ACMEAuthorizationPresenting:
				if authorization.ChallengeType != certificateidentity.ChallengeDNS01 {
					continue // control publishes tls-alpn-01 challenges before changing this state.
				}
				err = w.presentDNSAuthorization(ctx, work.PublicURLID, authorization, now)
			case controlstate.ACMEAuthorizationPresented:
				err = w.acceptAuthorization(ctx, client, work.ID, work.PublicURLID, authorization, now)
			case controlstate.ACMEAuthorizationValidating:
				err = w.pollAuthorization(ctx, client, authorization, now)
			}
			if err != nil {
				return true, err
			}
			work.AvailableAt = w.nextAuthorizationAt(work, now)
			return true, nil
		}
	}
	return false, nil
}

func (w *PublicURLWorker) presentDNSAuthorization(ctx context.Context, publicURLID string, authorization *controlstate.ACMEAuthorizationWork, now time.Time) error {
	if err := w.config.DNSChallenges.Present(ctx, publicURLID, authorization.ID); err != nil {
		return err
	}
	authorization.State = controlstate.ACMEAuthorizationPresented
	authorization.Attempts++
	authorization.PresentedAt = timePointer(now)
	authorization.AvailableAt = now.Add(w.config.PollInterval)
	return nil
}

func (w *PublicURLWorker) acceptAuthorization(ctx context.Context, client acmeAPI, orderID, publicURLID string, authorization *controlstate.ACMEAuthorizationWork, now time.Time) error {
	if authorization.ChallengeType == certificateidentity.ChallengeDNS01 {
		verified, err := w.config.DNSChallenges.Verify(ctx, publicURLID, authorization.ID)
		if err != nil {
			return err
		}
		if !verified {
			authorization.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
	}
	if authorization.ChallengeType == certificateidentity.ChallengeTLSALPN01 {
		// wait for every live ingress to acknowledge this challenge projection
		// before asking the CA to validate the publisher's certificate.
		ready, err := w.store.ACMEChallengeRoutingReady(ctx, orderID, now)
		if err != nil {
			return err
		}
		if !ready {
			authorization.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
	}
	retryAfter, err := client.AcceptChallenge(ctx, authorization.ChallengeURL)
	if err != nil {
		return err
	}
	authorization.State = controlstate.ACMEAuthorizationValidating
	authorization.Attempts++
	authorization.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
	return nil
}

func (w *PublicURLWorker) pollAuthorization(ctx context.Context, client acmeAPI, authorization *controlstate.ACMEAuthorizationWork, now time.Time) error {
	remote, err := client.GetAuthorization(ctx, authorization.AuthorizationURL)
	if err != nil {
		return err
	}
	if remote.URL != authorization.AuthorizationURL || remote.Identifier.Type != "dns" ||
		authorizationIdentifier(remote) != authorization.Identifier {
		return terminalf("authorization identity changed for %q", authorization.Identifier)
	}
	switch remote.Status {
	case "pending", "processing":
		authorization.AvailableAt = pollAt(now, w.config.PollInterval, remote.RetryAfter)
	case "valid":
		if remote.Expires != nil && !remote.Expires.After(now) {
			return terminalf("authorization for %q expired", authorization.Identifier)
		}
		authorization.State = controlstate.ACMEAuthorizationValid
		authorization.ValidatedAt = timePointer(now)
		authorization.AvailableAt = now
	case "invalid", "deactivated", "expired", "revoked":
		authorization.State = controlstate.ACMEAuthorizationFailed
		if problem := authorizationChallengeProblem(remote, authorization.ChallengeType, authorization.ChallengeURL); problem != "" {
			return terminalf("authorization for %q became %q: %s", authorization.Identifier, remote.Status, problem)
		}
		return terminalf("authorization for %q became %q", authorization.Identifier, remote.Status)
	default:
		return fmt.Errorf("certificates: unknown public URL authorization status %q", remote.Status)
	}
	return nil
}

func (w *PublicURLWorker) nextAuthorizationAt(work *controlstate.ACMEOrderWork, now time.Time) time.Time {
	var next time.Time
	for _, authorization := range work.Authorizations {
		if authorization.State == controlstate.ACMEAuthorizationValid || authorization.State == controlstate.ACMEAuthorizationComplete {
			continue
		}
		if next.IsZero() || authorization.AvailableAt.Before(next) {
			next = authorization.AvailableAt
		}
	}
	if next.IsZero() || next.Before(now) {
		return now
	}
	return next
}

func authorizationChallengeProblem(authorization acmeclient.Authorization, challengeType certificateidentity.ChallengeMethod, challengeURL string) string {
	for _, challenge := range authorization.Challenges {
		if challenge.Type != string(challengeType) || challenge.URL != challengeURL || challenge.Error == nil {
			continue
		}
		problem := challenge.Error
		switch {
		case problem.Type != "" && problem.Detail != "":
			return fmt.Sprintf("%s: %s", problem.Type, problem.Detail)
		case problem.Type != "":
			return problem.Type
		default:
			return problem.Detail
		}
	}
	return ""
}

// an order can become invalid before the next authorization poll. fetch the
// failed challenge while the original order is still available, so replacement
// issuance retains the CA's reason rather than only "order became invalid".
func (w *PublicURLWorker) invalidOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork) error {
	for _, authorization := range work.Authorizations {
		if authorization.AuthorizationURL == "" || authorization.ChallengeURL == "" {
			continue
		}
		remote, err := client.GetAuthorization(ctx, authorization.AuthorizationURL)
		if err != nil || remote.URL != authorization.AuthorizationURL ||
			remote.Identifier.Type != "dns" || authorizationIdentifier(remote) != authorization.Identifier {
			continue
		}
		if problem := authorizationChallengeProblem(remote, authorization.ChallengeType, authorization.ChallengeURL); problem != "" {
			return terminalf("ACME order became invalid: authorization for %q: %s", authorization.Identifier, problem)
		}
	}
	return terminalf("ACME order became invalid")
}

func authorizationWork(
	client acmeAPI,
	authorization acmeclient.Authorization,
	challengeMethod certificateidentity.ChallengeMethod,
	orderExpires *time.Time,
	now time.Time,
) (controlstate.ACMEAuthorizationWork, error) {
	result := controlstate.ACMEAuthorizationWork{
		Identifier: authorizationIdentifier(authorization), AuthorizationURL: authorization.URL,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if authorization.Status == "valid" && authorization.Expires == nil {
		return result, terminalf("valid authorization for %q has no expiry", result.Identifier)
	}
	expiresAt := authorization.Expires
	if expiresAt == nil {
		expiresAt = orderExpires
	}
	if expiresAt == nil {
		fallback := now.Add(5 * time.Minute)
		expiresAt = &fallback
	}
	result.ExpiresAt = timePointer(expiresAt.UTC())
	if !expiresAt.After(now) {
		return result, terminalf("authorization for %q expired", result.Identifier)
	}
	switch authorization.Status {
	case "valid":
		// reused authorizations need no new challenge, even if an old method is returned.
		result.State = controlstate.ACMEAuthorizationComplete
		result.ValidatedAt = timePointer(now)
		result.CleanupCompletedAt = timePointer(now)
		return result, nil
	case "pending":
	case "invalid", "deactivated", "expired", "revoked":
		return result, terminalf("authorization for %q is %q", result.Identifier, authorization.Status)
	default:
		return result, fmt.Errorf("certificates: unknown public URL authorization status %q", authorization.Status)
	}
	for _, challenge := range authorization.Challenges {
		if challenge.Type != string(challengeMethod) {
			continue
		}
		if challenge.URL == "" || challenge.Token == "" {
			return result, terminalf("authorization for %q has an incomplete %s challenge", result.Identifier, challengeMethod)
		}
		keyAuthorization, err := client.KeyAuthorization(challenge.Token)
		if err != nil {
			return result, err
		}
		result.ChallengeType = challengeMethod
		result.ChallengeURL = challenge.URL
		result.ChallengeToken = challenge.Token
		result.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
		break
	}
	if result.ChallengeType == "" {
		return result, terminalf("authorization for %q has no %s challenge", result.Identifier, challengeMethod)
	}
	result.State = controlstate.ACMEAuthorizationPresenting
	return result, nil
}

func authorizationIdentifier(authorization acmeclient.Authorization) string {
	if authorization.Wildcard {
		return "*." + authorization.Identifier.Value
	}
	return authorization.Identifier.Value
}

func allAuthorizationsValid(authorizations []controlstate.ACMEAuthorizationWork) bool {
	return len(authorizations) != 0 && !slices.ContainsFunc(authorizations, func(value controlstate.ACMEAuthorizationWork) bool {
		return value.State != controlstate.ACMEAuthorizationValid && value.State != controlstate.ACMEAuthorizationComplete
	})
}

func markAuthorizationsValid(authorizations []controlstate.ACMEAuthorizationWork, now time.Time) {
	for index := range authorizations {
		if authorizations[index].State == controlstate.ACMEAuthorizationComplete || authorizations[index].State == controlstate.ACMEAuthorizationCanceled {
			continue
		}
		authorizations[index].State = controlstate.ACMEAuthorizationValid
		if authorizations[index].ValidatedAt == nil {
			authorizations[index].ValidatedAt = timePointer(now)
		}
		authorizations[index].AvailableAt = now
	}
}

func sameAuthorizationURLs(urls []string, authorizations []controlstate.ACMEAuthorizationWork) bool {
	expected := slices.Clone(urls)
	actual := make([]string, len(authorizations))
	for index := range authorizations {
		actual[index] = authorizations[index].AuthorizationURL
	}
	slices.Sort(expected)
	slices.Sort(actual)
	return slices.Equal(expected, actual) && len(slices.Compact(expected)) == len(urls)
}

func timePointer(value time.Time) *time.Time {
	return &value
}
