package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherServices struct {
	authenticated                                       *clientauth.Client
	state                                               *clientstate.Store
	hostname, namespace, teamID, membershipID, domainID string
	publicURLScope                                      controlv1.PublicURLScope
	domainKind                                          authorityv1.DomainKind
	customDomainAvailable                               bool
	policyRevision                                      uint64
	ephemeral                                           bool
	routes                                              *controlclient.Client
	traffic                                             trafficlimits.Selection
}

func (p publisherServices) local() localpublisher.Services {
	return localpublisher.ServicesFromFacts(localpublisher.ServiceFacts{
		Authenticated: p.authenticated, State: p.state, Hostname: p.hostname, Namespace: p.namespace,
		TeamID: p.teamID, MembershipID: p.membershipID, DomainID: p.domainID, Scope: p.publicURLScope,
		DomainKind: p.domainKind, CustomDomainAvailable: p.customDomainAvailable, PolicyRevision: p.policyRevision,
		Ephemeral: p.ephemeral, Control: p.routes, Traffic: p.traffic,
	})
}
func servicesFromLocal(services localpublisher.Services) publisherServices {
	p := services.Facts()
	return publisherServices{authenticated: p.Authenticated, state: p.State, hostname: p.Hostname, namespace: p.Namespace,
		teamID: p.TeamID, membershipID: p.MembershipID, domainID: p.DomainID, publicURLScope: p.Scope,
		domainKind: p.DomainKind, customDomainAvailable: p.CustomDomainAvailable, policyRevision: p.PolicyRevision,
		ephemeral: p.Ephemeral, routes: p.Control, traffic: p.Traffic}
}
func (p publisherServices) config(target string, prefixes []string, limits publisher.ApplicationLimits, traffic ...trafficlimits.Selection) publisher.Config {
	return p.local().Config(target, prefixes, limits, traffic...)
}

type clientIPLookup interface {
	ClientIP(context.Context) (controlv1.ClientIPResponse, error)
}
type resolvedIPPolicy struct {
	prefixes []string
	current  string
}

func resolveIPPolicy(ctx context.Context, control clientIPLookup, prefixes []string, public bool) (resolvedIPPolicy, error) {
	allowed, current, err := localpublisher.ResolveIPPolicy(ctx, control, prefixes, public)
	return resolvedIPPolicy{allowed, current}, err
}
func authenticatePublisher(ctx context.Context, state *clientstate.Database, serverURL, accessToken, command string, stdin io.Reader, diagnostics io.Writer) (*clientauth.Client, error) {
	return clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: serverURL, State: state, AccessToken: accessToken,
		Diagnostics: diagnostics, OpenURL: interactiveBrowserOpener(stdin), LoginToken: loginTokenPrompt(stdin, diagnostics), AuthenticationPrompt: authenticationPrompt(diagnostics, command)})
}
func preparePublisherServices(ctx context.Context, state *clientstate.Database, server, url, name, domain, team string, ephemeral bool, auth *clientauth.Client) (publisherServices, error) {
	services, err := localpublisher.PrepareServices(ctx, state, server, url, name, domain, team, ephemeral, auth)
	return servicesFromLocal(services), err
}
func (c teamContext) facts() localpublisher.TeamFacts {
	return localpublisher.TeamFacts{Team: c.team, Membership: c.membership, Domains: c.domains, Mode: c.mode, Builtin: c.builtin}
}
func teamFromLocal(c localpublisher.TeamFacts) teamContext {
	return teamContext{c.Team, c.Membership, c.Domains, c.Mode, c.Builtin}
}
func resolvePublishHostname(url, name, domain string, current teamContext) (string, authorityv1.Domain, controlv1.PublicURLScope, error) {
	return localpublisher.ResolveHostname(url, name, domain, current.facts())
}
func readyDomain(current teamContext, selected string) (authorityv1.Domain, error) {
	return localpublisher.ReadyDomain(current.facts(), selected)
}
func (c teamContext) namespace(domain authorityv1.Domain) (string, bool) {
	return localpublisher.Namespace(c.facts(), domain)
}
func (flags tunnelFlags) limits() publisher.ApplicationLimits { return flags.settings().Limits() }
func (flags tunnelFlags) traffic() (trafficlimits.Selection, error) {
	return flags.settings().Traffic()
}

func (flags tunnelFlags) settings() localpublisher.Settings {
	settings := localpublisher.Settings{Domain: flags.Domain, Name: flags.Name, PublicURL: flags.PublicURL,
		AllowIP: flags.AllowIP, AllowAllIPs: flags.AllowAllIPs, Ephemeral: flags.Ephemeral,
		Requests: flags.Requests, RateRequests: flags.RateRequests, RateBurst: flags.RateBurst, Concurrency: flags.Concurrency, RatePer: flags.RatePer,
		TrafficConnections: flags.TrafficConnections, TrafficRateCount: flags.TrafficRateCount, TrafficRateBurst: flags.TrafficRateBurst,
		TrafficRatePer: flags.TrafficRatePer, TrafficUpload: flags.TrafficUpload, TrafficDownload: flags.TrafficDownload,
		TargetCAFile: flags.TargetCAFile, InspectionMode: flags.InspectionMode, InspectionRetention: flags.InspectionRetention, InspectionMaxBytes: flags.InspectionMaxBytes}
	settings.SetSources(localpublisher.SettingSources{AllowAllIPs: flags.allowAllIPsFromCLI, Ephemeral: flags.ephemeralFromCLI,
		InspectionMode: flags.inspectionModeFromCLI, InspectionRetention: flags.inspectionRetentionFromCLI, InspectionMaxBytes: flags.inspectionMaxBytesFromCLI})
	return settings
}
func (flags *tunnelFlags) applySettings(settings localpublisher.Settings) {
	flags.Domain, flags.Name, flags.PublicURL = settings.Domain, settings.Name, settings.PublicURL
	flags.AllowIP, flags.AllowAllIPs, flags.Ephemeral = settings.AllowIP, settings.AllowAllIPs, settings.Ephemeral
	flags.Requests, flags.RateRequests, flags.RateBurst, flags.Concurrency, flags.RatePer = settings.Requests, settings.RateRequests, settings.RateBurst, settings.Concurrency, settings.RatePer
	flags.TrafficConnections, flags.TrafficRateCount, flags.TrafficRateBurst = settings.TrafficConnections, settings.TrafficRateCount, settings.TrafficRateBurst
	flags.TrafficRatePer, flags.TrafficUpload, flags.TrafficDownload = settings.TrafficRatePer, settings.TrafficUpload, settings.TrafficDownload
	flags.InspectionMode, flags.InspectionRetention, flags.InspectionMaxBytes = settings.InspectionMode, settings.InspectionRetention, settings.InspectionMaxBytes
}
