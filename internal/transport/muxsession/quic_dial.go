package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	quic "github.com/quic-go/quic-go"
)

func dialSharedQUIC(ctx context.Context, dialer QUICDialer, address string, trust *tls.Config, config *quic.Config,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
) (*quic.Conn, error) {
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("muxsession: QUIC endpoint requires a numeric nonzero port")
	}
	if host == "" {
		return nil, errors.New("muxsession: QUIC endpoint requires a host")
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		// parse literals here so scoped IPv6 retains its zone without a DNS lookup.
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = lookup(ctx, "ip", host)
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if err != nil {
			return nil, err
		}
		// match net.ResolveUDPAddr's IPv4 preference. independently selecting a
		// different family for each relay would produce incompatible source claims.
		addresses = slices.Clone(addresses)
		slices.SortStableFunc(addresses, func(a, b netip.Addr) int {
			if a.Unmap().Is4() == b.Unmap().Is4() {
				return 0
			}
			if a.Unmap().Is4() {
				return -1
			}
			return 1
		})
	}
	if len(addresses) == 0 {
		return nil, errors.New("muxsession: shared-socket QUIC endpoint resolved no addresses")
	}
	var failures []error
	for i, ip := range addresses {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		// leave part of a finite caller budget for the remaining addresses. an
		// unreachable first family must not spend the whole QUIC attempt deadline.
		attemptCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok && i+1 < len(addresses) {
			attemptCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
		}
		connection, err := dialer.DialQUIC(attemptCtx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), trust, config)
		cancel()
		if ctx.Err() != nil {
			if connection != nil {
				_ = connection.CloseWithError(0, "")
			}
			return nil, context.Cause(ctx)
		}
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("muxsession: no shared-socket QUIC address connected: %w", errors.Join(failures...))
}
