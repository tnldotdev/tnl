package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func runHostClaim(ctx context.Context, flags hostClaimCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, capabilities, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	kind, labelOrDomain, err := classifyClaimHostname(flags.Hostname, capabilities.HostnameSuffix)
	if err != nil {
		return err
	}
	idempotencyKey, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	if kind == serverv1.ClaimHostnameRequestKindManaged {
		hostname, err := client.ClaimHostname(ctx, kind, labelOrDomain, idempotencyKey)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, hostname.Hostname)
		return err
	}
	if !capabilities.CustomDomainSupport {
		return errors.New("server does not support custom domains")
	}
	verification, err := client.CreateDomainVerification(ctx, labelOrDomain, idempotencyKey)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Add these DNS records:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	for _, record := range verification.Records {
		if _, err := fmt.Fprintf(output, "%-32s %-5s %s\n", record.Name, record.Type, record.Value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Waiting for DNS..."); err != nil {
		return err
	}
	for {
		hostname, err := client.CompleteDomainVerification(ctx, verification.Id)
		if err == nil {
			_, err = fmt.Fprintf(output, "Claimed %s\n", hostname.Hostname)
			return err
		}
		if !errors.Is(err, serverclient.ErrDNSProofPending) && !errors.Is(err, authorityclient.ErrDNSProofPending) {
			return err
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func runHostList(ctx context.Context, flags hostListCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, _, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	if _, err := fmt.Fprintln(output, "HOSTNAME\tTYPE\tSTATE"); err != nil {
		return err
	}
	cursor := ""
	for {
		hostnames, next, err := client.ListHostnamesPage(ctx, cursor)
		if err != nil {
			return err
		}
		for _, hostname := range hostnames {
			typeName := "managed"
			switch hostname.Kind {
			case serverv1.HostnameKindCustomDomain:
				typeName = "custom"
			case serverv1.HostnameKindTemporary:
				typeName = "temporary"
			}
			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\n", hostname.Hostname, typeName, hostname.Status); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

func runHostRelease(ctx context.Context, flags hostReleaseCommand, output io.Writer, diagnostics ...io.Writer) error {
	client, capabilities, state, err := namingClient(ctx, flags.StateDir, flags.ServerURL, flags.AccessToken, diagnosticOutput(diagnostics))
	if err != nil {
		return err
	}
	defer state.Close()
	hostnames, err := client.ListHostnames(ctx)
	if err != nil {
		return err
	}
	hostname, hostnameID, err := resolveReleaseHostname(flags.Hostname, capabilities.HostnameSuffix, hostnames)
	if err != nil {
		return err
	}
	if err := client.ReleaseHostname(ctx, hostnameID); err != nil &&
		!errors.Is(err, serverclient.ErrNotFound) && !errors.Is(err, authorityclient.ErrNotFound) {
		return err
	}
	_, err = fmt.Fprintln(output, hostname)
	return err
}

func claimPublishHostname(
	ctx context.Context,
	client hostnameAPI,
	host string,
	capabilities serverv1.Capabilities,
) (string, error) {
	if host == "" {
		idempotencyKey, err := randomIdempotencyKey()
		if err != nil {
			return "", err
		}
		hostname, err := client.ClaimHostname(ctx, serverv1.ClaimHostnameRequestKindTemporary, "", idempotencyKey)
		if err != nil {
			return "", err
		}
		if hostname.Kind != serverv1.HostnameKindTemporary || hostname.Status != serverv1.HostnameStatusPendingRoute {
			return "", errors.New("server returned an invalid temporary hostname")
		}
		return validateClaimedHostname(hostname, capabilities.HostnameSuffix)
	}
	hostnames, err := client.ListHostnames(ctx)
	if err != nil {
		return "", err
	}
	resolvedHostname, base, managed, implicit, err := resolvePublishHostname(host, capabilities.HostnameSuffix, capabilities.MaximumSubdomainDepth, hostnames)
	if err != nil {
		return "", err
	}
	if implicit {
		idempotencyKey, err := randomIdempotencyKey()
		if err != nil {
			return "", err
		}
		claimed, err := client.ClaimHostname(ctx, serverv1.ClaimHostnameRequestKindManaged, base, idempotencyKey)
		if err != nil {
			return "", err
		}
		if claimed.Hostname != resolvedHostname || claimed.Status != serverv1.HostnameStatusActive {
			return "", errors.New("server returned an invalid managed hostname")
		}
	} else if !managed && !capabilities.CustomDomainSupport {
		return "", errors.New("server does not support custom domains")
	}
	return resolvedHostname, nil
}

func validateClaimedHostname(value serverv1.Hostname, suffix string) (string, error) {
	canonicalSuffix, suffixErr := naming.CanonicalizeHostname(suffix)
	hostname, err := naming.CanonicalizeHostname(value.Hostname)
	label, found := strings.CutSuffix(hostname, "."+suffix)
	if suffixErr != nil || canonicalSuffix != suffix || err != nil || hostname != value.Hostname ||
		!found || label == "" || strings.Contains(label, ".") || value.Id == "" {
		return "", errors.New("server returned an invalid hostname")
	}
	return hostname, nil
}

func namingClient(
	ctx context.Context,
	stateDir, serverValue, accessToken string,
	diagnostics io.Writer,
) (hostnameAPI, serverv1.Capabilities, *clientstate.Database, error) {
	serverURL, state, err := resolveServer(ctx, stateDir, serverValue)
	if err != nil {
		return nil, serverv1.Capabilities{}, nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: state, AccessToken: accessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
	})
	if err != nil {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, err
	}
	client, capabilities, err := namingAPI(authenticated)
	if err != nil {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, err
	}
	if capabilities.HostnameSuffix == "" || capabilities.MaximumSubdomainDepth != 8 {
		state.Close()
		return nil, serverv1.Capabilities{}, nil, errors.New("server does not support the required naming contract")
	}
	return client, capabilities, state, nil
}

func classifyClaimHostname(input, hostnameSuffix string) (serverv1.ClaimHostnameRequestKind, string, error) {
	if input == "" {
		return serverv1.ClaimHostnameRequestKindManaged, "", nil
	}
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !absolute && !strings.Contains(canonical, ".") {
		return serverv1.ClaimHostnameRequestKindManaged, canonical, nil
	}
	if naming.IsWithin(canonical, hostnameSuffix) {
		depth, _ := naming.ChildDepth(canonical, hostnameSuffix)
		if depth != 1 {
			return "", "", errors.New("managed hostname must be exactly one label beneath the hostname suffix")
		}
		label, _ := strings.CutSuffix(canonical, "."+hostnameSuffix)
		return serverv1.ClaimHostnameRequestKindManaged, label, nil
	}
	domain, _, err := naming.CustomDomain(canonical, hostnameSuffix)
	if err != nil {
		return "", "", err
	}
	return "", domain, nil
}

func resolvePublishHostname(
	input, hostnameSuffix string,
	maximumDepth int,
	hostnames []serverv1.Hostname,
) (hostname, base string, managed, implicit bool, err error) {
	absolute := strings.HasSuffix(input, ".")
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", false, false, err
	}
	active := func(kind serverv1.HostnameKind, candidate string) bool {
		for _, hostname := range hostnames {
			if hostname.Kind == kind && hostname.Status == serverv1.HostnameStatusActive && hostname.Hostname == candidate {
				return true
			}
		}
		return false
	}
	if !absolute && !naming.IsWithin(canonical, hostnameSuffix) {
		for _, hostname := range hostnames {
			if hostname.Kind != serverv1.HostnameKindCustomDomain || hostname.Status != serverv1.HostnameStatusActive {
				continue
			}
			if depth, ok := naming.ChildDepth(canonical, hostname.Hostname); ok {
				if depth > maximumDepth {
					return "", "", false, false, errors.New("custom-domain child exceeds maximum depth")
				}
				return canonical, hostname.Hostname, false, false, nil
			}
		}
	}
	if absolute && !naming.IsWithin(canonical, hostnameSuffix) {
		for _, hostname := range hostnames {
			if hostname.Kind == serverv1.HostnameKindCustomDomain && hostname.Status == serverv1.HostnameStatusActive {
				if depth, ok := naming.ChildDepth(canonical, hostname.Hostname); ok && depth <= maximumDepth {
					return canonical, hostname.Hostname, false, false, nil
				}
			}
		}
		return "", "", false, false, errors.New("absolute hostname is not within an owned custom domain")
	}
	if !naming.IsWithin(canonical, hostnameSuffix) {
		canonical += "." + hostnameSuffix
		canonical, err = naming.CanonicalizeHostname(canonical)
		if err != nil {
			return "", "", false, false, err
		}
	}
	if canonical == hostnameSuffix {
		return "", "", false, false, errors.New("hostname suffix cannot be published")
	}
	relative, _ := strings.CutSuffix(canonical, "."+hostnameSuffix)
	labels := strings.Split(relative, ".")
	if len(labels) == 0 || len(labels)-1 > maximumDepth {
		return "", "", false, false, errors.New("managed child exceeds maximum depth")
	}
	base = labels[len(labels)-1] + "." + hostnameSuffix
	if len(labels) == 1 && !active(serverv1.HostnameKindManaged, base) {
		return canonical, labels[0], true, true, nil
	}
	if !active(serverv1.HostnameKindManaged, base) {
		return "", "", false, false, fmt.Errorf("managed hostname %s is not claimed", base)
	}
	return canonical, base, true, false, nil
}

func resolveReleaseHostname(
	input, hostnameSuffix string,
	hostnames []serverv1.Hostname,
) (string, string, error) {
	canonical, err := naming.CanonicalizeHostname(input)
	if err != nil {
		return "", "", err
	}
	if !strings.HasSuffix(input, ".") && !strings.Contains(canonical, ".") {
		canonical += "." + hostnameSuffix
	}
	for _, hostname := range hostnames {
		if hostname.Hostname == canonical {
			if hostname.Kind == serverv1.HostnameKindTemporary {
				return "", "", errors.New("temporary hostnames are retired with their route and cannot be released")
			}
			return canonical, hostname.Id, nil
		}
	}
	return "", "", errors.New("hostname not found")
}

type hostnameAPI interface {
	ClaimHostname(context.Context, serverv1.ClaimHostnameRequestKind, string, string) (serverv1.Hostname, error)
	ListHostnames(context.Context) ([]serverv1.Hostname, error)
	ListHostnamesPage(context.Context, string) ([]serverv1.Hostname, string, error)
	ReleaseHostname(context.Context, string) error
	CreateDomainVerification(context.Context, string, string) (serverv1.DomainVerification, error)
	CompleteDomainVerification(context.Context, string) (serverv1.Hostname, error)
}

type authorityHostnameAPI struct{ client *authorityclient.Client }

func (a authorityHostnameAPI) ClaimHostname(
	ctx context.Context,
	kind serverv1.ClaimHostnameRequestKind,
	label, idempotencyKey string,
) (serverv1.Hostname, error) {
	hostname, err := a.client.ClaimHostname(ctx, authorityv1.ClaimHostnameRequestKind(kind), label, idempotencyKey)
	return authorityHostname(hostname), err
}

func (a authorityHostnameAPI) ListHostnames(ctx context.Context) ([]serverv1.Hostname, error) {
	hostnames, err := a.client.ListHostnames(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]serverv1.Hostname, len(hostnames))
	for index, hostname := range hostnames {
		result[index] = authorityHostname(hostname)
	}
	return result, nil
}

func (a authorityHostnameAPI) ListHostnamesPage(
	ctx context.Context,
	cursor string,
) ([]serverv1.Hostname, string, error) {
	hostnames, next, err := a.client.ListHostnamesPage(ctx, cursor)
	if err != nil {
		return nil, "", err
	}
	result := make([]serverv1.Hostname, len(hostnames))
	for index, hostname := range hostnames {
		result[index] = authorityHostname(hostname)
	}
	return result, next, nil
}

func (a authorityHostnameAPI) ReleaseHostname(ctx context.Context, hostnameID string) error {
	return a.client.ReleaseHostname(ctx, hostnameID)
}

func (a authorityHostnameAPI) CreateDomainVerification(
	ctx context.Context,
	domain, idempotencyKey string,
) (serverv1.DomainVerification, error) {
	verification, err := a.client.CreateDomainVerification(ctx, domain, idempotencyKey)
	return authorityDomainVerification(verification), err
}

func (a authorityHostnameAPI) CompleteDomainVerification(
	ctx context.Context,
	verificationID string,
) (serverv1.Hostname, error) {
	hostname, err := a.client.CompleteDomainVerification(ctx, verificationID)
	return authorityHostname(hostname), err
}

func namingAPI(authenticated *clientauth.Client) (hostnameAPI, serverv1.Capabilities, error) {
	if authenticated == nil || authenticated.Server == nil {
		return nil, serverv1.Capabilities{}, errors.New("authentication did not return a server client")
	}
	capabilities := authenticated.ServerCapabilities
	if authenticated.Kind == clientstate.ControlSessionKindServer {
		return authenticated.Server, capabilities, nil
	}
	if authenticated.Authority == nil || authenticated.AuthorityCapabilities == nil {
		return nil, serverv1.Capabilities{}, errors.New("authentication did not return an authorization authority client")
	}
	authority := authenticated.AuthorityCapabilities
	capabilities.HostnameSuffix = authority.HostnameSuffix
	capabilities.MaximumSubdomainDepth = int(authority.HostnamePolicy.MaximumSubdomainDepth)
	capabilities.CustomDomainSupport = bool(authority.HostnamePolicy.CustomDomainSupport)
	capabilities.PersistentBaseSupport = bool(authority.HostnamePolicy.PersistentBaseSupport)
	capabilities.TemporaryNameSupport = bool(authority.HostnamePolicy.TemporaryNameSupport)
	return authorityHostnameAPI{client: authenticated.Authority}, capabilities, nil
}

func routeAPI(authenticated *clientauth.Client) (*routeclient.Client, error) {
	if authenticated.Kind == clientstate.ControlSessionKindServer {
		return routeclient.NewLocal(authenticated.Server)
	}
	if authenticated.Authority == nil || authenticated.AuthorityCapabilities == nil {
		return nil, errors.New("authentication did not return an authorization authority client")
	}
	return routeclient.NewSigned(
		authenticated.ServerEndpoint, authenticated.Server, authenticated.Authority, *authenticated.AuthorityCapabilities,
	)
}

func authorityHostname(hostname authorityv1.Hostname) serverv1.Hostname {
	return serverv1.Hostname{
		Id: hostname.Id, Hostname: hostname.Hostname,
		Kind: serverv1.HostnameKind(hostname.Kind), Status: serverv1.HostnameStatus(hostname.Status),
		Source: serverv1.HostnameSource(hostname.Source), CreatedAt: hostname.CreatedAt,
		ActivatedAt: hostname.ActivatedAt, DeactivatedAt: hostname.DeactivatedAt,
	}
}

func authorityDomainVerification(verification authorityv1.DomainVerification) serverv1.DomainVerification {
	records := make([]serverv1.DNSRecord, len(verification.Records))
	for index, record := range verification.Records {
		records[index] = serverv1.DNSRecord{Name: record.Name, Type: serverv1.DNSRecordType(record.Type), Value: record.Value}
	}
	return serverv1.DomainVerification{
		Id: verification.Id, Domain: verification.Domain, VerificationTarget: verification.VerificationTarget,
		Apex: verification.Apex, Status: serverv1.DomainVerificationStatus(verification.Status), Records: records,
		HostnameId: verification.HostnameId, CreatedAt: verification.CreatedAt,
		VerifiedAt: verification.VerifiedAt, InvalidatedAt: verification.InvalidatedAt,
	}
}

func randomIdempotencyKey() (string, error) {
	return opaqueid.New("random_")
}
