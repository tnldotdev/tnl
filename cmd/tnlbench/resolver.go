package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

type resolverCommand struct {
	ServerDomain       string `name:"server-domain" env:"TNL_BENCH_RESOLVER_SERVER_DOMAIN" required:"" help:"Server domain served by the parent authoritative name servers."`
	ServerNameServers  string `name:"server-name-servers" env:"TNL_BENCH_RESOLVER_SERVER_NAME_SERVERS" required:"" help:"Comma-separated authoritative name servers for the server domain."`
	ManagedDomain      string `name:"managed-domain" env:"TNL_BENCH_RESOLVER_MANAGED_DOMAIN" required:"" help:"Managed deployment domain served by the child authoritative name servers."`
	ManagedNameServers string `name:"managed-name-servers" env:"TNL_BENCH_RESOLVER_MANAGED_NAME_SERVERS" required:"" help:"Comma-separated authoritative name servers for the managed deployment domain."`
}

type authoritativeResolver struct {
	serverDomain, managedDomain           string
	serverNameServers, managedNameServers []string
	exchange                              func(context.Context, *mdns.Msg, string) (*mdns.Msg, time.Duration, error)
	lookupTimeout, retryInterval          time.Duration
	next                                  atomic.Uint64
}

func (c resolverCommand) run(ctx context.Context) error {
	resolver, err := newAuthoritativeResolver(c)
	if err != nil {
		return err
	}
	server := &mdns.Server{Addr: benchmarkPebbleDNSServer, Net: "tcp", Handler: resolver}
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case err := <-result:
		return fmt.Errorf("serve benchmark DNS: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.ShutdownContext(shutdownCtx); err != nil {
			return fmt.Errorf("stop benchmark DNS: %w", err)
		}
		return nil
	}
}

func newAuthoritativeResolver(command resolverCommand) (*authoritativeResolver, error) {
	serverDomain := canonicalDNSName(command.ServerDomain)
	managedDomain := canonicalDNSName(command.ManagedDomain)
	serverNameServers, err := resolverNameServers(command.ServerNameServers)
	if err != nil {
		return nil, fmt.Errorf("server name servers: %w", err)
	}
	managedNameServers, err := resolverNameServers(command.ManagedNameServers)
	if err != nil {
		return nil, fmt.Errorf("managed name servers: %w", err)
	}
	if serverDomain == "" || managedDomain == "" || managedDomain == serverDomain ||
		!strings.HasSuffix(managedDomain, "."+serverDomain) {
		return nil, errors.New("resolver domains are invalid")
	}
	client := &mdns.Client{Net: "tcp", Timeout: 5 * time.Second}
	return &authoritativeResolver{
		serverDomain: serverDomain, managedDomain: managedDomain,
		serverNameServers: serverNameServers, managedNameServers: managedNameServers,
		exchange: client.ExchangeContext, lookupTimeout: 12 * time.Second, retryInterval: 250 * time.Millisecond,
	}, nil
}

func resolverNameServers(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	nameServers := make([]string, 0, len(parts))
	for _, part := range parts {
		nameServer := canonicalDNSName(part)
		address := net.JoinHostPort(nameServer, "53")
		if nameServer == "" || strings.ContainsAny(nameServer, " /\t\r\n") || slices.Contains(nameServers, address) {
			return nil, errors.New("authoritative name server list is invalid")
		}
		nameServers = append(nameServers, address)
	}
	if len(nameServers) < 2 {
		return nil, errors.New("at least two authoritative name servers are required")
	}
	return nameServers, nil
}

func (r *authoritativeResolver) ServeDNS(writer mdns.ResponseWriter, request *mdns.Msg) {
	response := new(mdns.Msg)
	response.SetReply(request)
	if len(request.Question) != 1 || request.Question[0].Qclass != mdns.ClassINET ||
		!slices.Contains([]uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeTXT}, request.Question[0].Qtype) {
		response.Rcode = mdns.RcodeRefused
		_ = writer.WriteMsg(response)
		return
	}
	nameServers, ok := r.nameServers(request.Question[0].Name)
	if !ok {
		response.Rcode = mdns.RcodeRefused
		_ = writer.WriteMsg(response)
		return
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), r.lookupTimeout)
	defer cancel()
	start := int(r.next.Add(1)-1) % len(nameServers)
	rounds := 0
	for {
		rounds++
		answers := make(map[string]mdns.RR)
		response.Rcode = mdns.RcodeServerFailure
		response.Authoritative = false
		var lastErr error
		for offset := range len(nameServers) {
			nameServer := nameServers[(start+offset)%len(nameServers)]
			upstream, _, err := r.exchange(ctx, request.Copy(), nameServer)
			if err != nil {
				lastErr = err
				continue
			}
			if upstream.Rcode == mdns.RcodeSuccess {
				response.Rcode = mdns.RcodeSuccess
			}
			response.Authoritative = response.Authoritative || upstream.Authoritative
			for _, answer := range upstream.Answer {
				answers[answer.String()] = answer
			}
		}
		for _, answer := range answers {
			response.Answer = append(response.Answer, answer)
		}
		if len(response.Answer) != 0 || request.Question[0].Qtype != mdns.TypeTXT {
			if rounds > 1 {
				slog.Info("benchmark authoritative DNS answer became available", "name", request.Question[0].Name,
					"wait", time.Since(started).Round(time.Millisecond))
			}
			_ = writer.WriteMsg(response)
			return
		}
		timer := time.NewTimer(r.retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = writer.WriteMsg(response)
			slog.Warn("benchmark authoritative DNS answer remained empty", "name", request.Question[0].Name,
				"wait", time.Since(started).Round(time.Millisecond), "error", lastErr)
			return
		case <-timer.C:
		}
	}
}

func (r *authoritativeResolver) nameServers(name string) ([]string, bool) {
	name = canonicalDNSName(name)
	switch {
	case name == r.managedDomain || strings.HasSuffix(name, "."+r.managedDomain):
		return r.managedNameServers, true
	case name == r.serverDomain || strings.HasSuffix(name, "."+r.serverDomain):
		return r.serverNameServers, true
	default:
		return nil, false
	}
}
