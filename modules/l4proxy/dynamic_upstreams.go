// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4proxy

import (
	"context"
	"fmt"
	weakrand "math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(SRVUpstreams{})
}

// UpstreamSource is a source of upstreams. An upstream source is a
// provider of upstreams that can be used for proxying connections.
// Unlike static upstreams, dynamic upstream sources can provide
// a list of upstreams that changes over time, such as through
// service discovery.
type UpstreamSource interface {
	// GetUpstreams returns a list of upstreams. The repl parameter
	// is used to expand any placeholders in the upstream configuration.
	GetUpstreams(repl *caddy.Replacer) ([]*Upstream, error)
}

// SRVUpstreams provides upstreams from SRV lookups.
// The lookup DNS name can be configured either by
// its individual parts (that is, specifying the
// service, protocol, and name separately) to form
// the standard "_service._proto.name" domain, or
// the domain can be specified directly in name by
// leaving service and proto empty. See RFC 2782.
//
// Lookups are cached and refreshed at the configured
// refresh interval.
//
// Returned upstreams are sorted by priority and weight.
type SRVUpstreams struct {
	// The service label.
	Service string `json:"service,omitempty"`

	// The protocol label; either tcp or udp.
	Proto string `json:"proto,omitempty"`

	// The name label; or, if service and proto are
	// empty, the entire domain name to look up.
	Name string `json:"name,omitempty"`

	// The interval at which to refresh the SRV lookup.
	// Results are cached between lookups. Default: 1m
	Refresh caddy.Duration `json:"refresh,omitempty"`

	// If > 0 and there is an error with the lookup,
	// continue to use the cached results for up to
	// this long before trying again, (even though they
	// are stale) instead of returning an error to the
	// client. Default: 0s.
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// Configures the DNS resolver used to resolve the
	// SRV address to SRV records.
	Resolver *UpstreamResolver `json:"resolver,omitempty"`

	// If Resolver is configured, how long to wait before
	// timing out trying to connect to the DNS server.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// If Resolver is configured, how long to wait before
	// spawning an RFC 6555 Fast Fallback connection.
	// A negative value disables this.
	FallbackDelay caddy.Duration `json:"dial_fallback_delay,omitempty"`

	resolver *net.Resolver
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SRVUpstreams) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.proxy.upstreams.srv",
		New: func() caddy.Module { return new(SRVUpstreams) },
	}
}

// Provision sets up the SRV upstream source.
func (su *SRVUpstreams) Provision(ctx caddy.Context) error {
	su.logger = ctx.Logger()
	if su.Refresh == 0 {
		su.Refresh = caddy.Duration(time.Minute)
	}

	if su.Resolver != nil {
		err := su.Resolver.ParseAddresses()
		if err != nil {
			return err
		}
		d := &net.Dialer{
			Timeout:       time.Duration(su.DialTimeout),
			FallbackDelay: time.Duration(su.FallbackDelay),
		}
		su.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				//nolint:gosec
				addr := su.Resolver.netAddrs[weakrand.Intn(len(su.Resolver.netAddrs))]
				return d.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	}
	if su.resolver == nil {
		su.resolver = net.DefaultResolver
	}

	return nil
}

// GetUpstreams returns upstreams from SRV lookup.
func (su SRVUpstreams) GetUpstreams(repl *caddy.Replacer) ([]*Upstream, error) {
	suAddr, service, proto, name := su.expandedAddr(repl)

	// first, use a cheap read-lock to return a cached result quickly
	srvsMu.RLock()
	cached := srvs[suAddr]
	srvsMu.RUnlock()
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	// otherwise, obtain a write-lock to update the cached value
	srvsMu.Lock()
	defer srvsMu.Unlock()

	// check to see if it's still stale, since we're now in a different
	// lock from when we first checked freshness; another goroutine might
	// have refreshed it in the meantime before we re-obtained our lock
	cached = srvs[suAddr]
	if cached.isFresh() {
		return allNew(cached.upstreams), nil
	}

	if c := su.logger.Check(zapcore.DebugLevel, "refreshing SRV upstreams"); c != nil {
		c.Write(
			zap.String("service", service),
			zap.String("proto", proto),
			zap.String("name", name),
		)
	}

	ctx := context.Background()
	_, records, err := su.resolver.LookupSRV(ctx, service, proto, name)
	if err != nil {
		// From LookupSRV docs: "If the response contains invalid names, those records are filtered
		// out and an error will be returned alongside the remaining results, if any." Thus, we
		// only return an error if no records were also returned.
		if len(records) == 0 {
			if su.GracePeriod > 0 {
				if c := su.logger.Check(zapcore.ErrorLevel, "SRV lookup failed; using previously cached"); c != nil {
					c.Write(zap.Error(err))
				}
				cached.freshness = time.Now().Add(time.Duration(su.GracePeriod) - time.Duration(su.Refresh))
				srvs[suAddr] = cached
				return allNew(cached.upstreams), nil
			}
			return nil, err
		}
		if c := su.logger.Check(zapcore.WarnLevel, "SRV records filtered"); c != nil {
			c.Write(zap.Error(err))
		}
	}

	upstreams := make([]Upstream, len(records))
	for i, rec := range records {
		if c := su.logger.Check(zapcore.DebugLevel, "discovered SRV record"); c != nil {
			c.Write(
				zap.String("target", rec.Target),
				zap.Uint16("port", rec.Port),
				zap.Uint16("priority", rec.Priority),
				zap.Uint16("weight", rec.Weight),
			)
		}
		addr := net.JoinHostPort(rec.Target, strconv.Itoa(int(rec.Port)))
		upstreams[i] = Upstream{Dial: []string{addr}}
	}

	// before adding a new one to the cache (as opposed to replacing stale one), make room if cache is full
	if cached.freshness.IsZero() && len(srvs) >= 100 {
		for randomKey := range srvs {
			delete(srvs, randomKey)
			break
		}
	}

	srvs[suAddr] = srvLookup{
		srvUpstreams: su,
		freshness:    time.Now(),
		upstreams:    upstreams,
	}

	return allNew(upstreams), nil
}

func (su SRVUpstreams) String() string {
	if su.Service == "" && su.Proto == "" {
		return su.Name
	}
	return su.formattedAddr(su.Service, su.Proto, su.Name)
}

// expandedAddr expands placeholders in the configured SRV domain labels.
// The return values are: addr, the RFC 2782 representation of the SRV domain;
// service, the service; proto, the protocol; and name, the name.
// If su.Service and su.Proto are empty, name will be returned as addr instead.
func (su SRVUpstreams) expandedAddr(repl *caddy.Replacer) (addr, service, proto, name string) {
	name = repl.ReplaceAll(su.Name, "")
	if su.Service == "" && su.Proto == "" {
		addr = name
		return
	}
	service = repl.ReplaceAll(su.Service, "")
	proto = repl.ReplaceAll(su.Proto, "")
	addr = su.formattedAddr(service, proto, name)
	return
}

// formattedAddr the RFC 2782 representation of the SRV domain, in
// the form "_service._proto.name".
func (SRVUpstreams) formattedAddr(service, proto, name string) string {
	return fmt.Sprintf("_%s._%s.%s", service, proto, name)
}

// UnmarshalCaddyfile sets up the SRVUpstreams from Caddyfile tokens. Syntax:
//
//	lookup_srv [<name>] {
//		service <service>
//		proto <proto>
//		name <name>
//		refresh <duration>
//		grace_period <duration>
//		resolvers <addresses...>
//		dial_timeout <duration>
//		dial_fallback_delay <duration>
//	}
//	lookup_srv <name>
func (su *SRVUpstreams) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume upstream source name

	args := d.RemainingArgs()
	if len(args) > 1 {
		return d.ArgErr()
	}
	if len(args) > 0 {
		su.Name = args[0]
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "service":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if su.Service != "" {
				return d.Errf("srv service has already been specified")
			}
			su.Service = d.Val()

		case "proto":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if su.Proto != "" {
				return d.Errf("srv proto has already been specified")
			}
			su.Proto = d.Val()

		case "name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if su.Name != "" {
				return d.Errf("srv name has already been specified")
			}
			su.Name = d.Val()

		case "refresh":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing refresh interval duration: %v", err)
			}
			su.Refresh = caddy.Duration(dur)

		case "grace_period":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing grace period duration: %v", err)
			}
			su.GracePeriod = caddy.Duration(dur)

		case "resolvers":
			if su.Resolver == nil {
				su.Resolver = new(UpstreamResolver)
			}
			su.Resolver.Addresses = d.RemainingArgs()
			if len(su.Resolver.Addresses) == 0 {
				return d.Errf("must specify at least one resolver address")
			}

		case "dial_timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing dial timeout duration: %v", err)
			}
			su.DialTimeout = caddy.Duration(dur)

		case "dial_fallback_delay":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing dial fallback delay duration: %v", err)
			}
			su.FallbackDelay = caddy.Duration(dur)

		default:
			return d.Errf("unrecognized srv option '%s'", d.Val())
		}
	}

	return nil
}

type srvLookup struct {
	srvUpstreams SRVUpstreams
	freshness    time.Time
	upstreams    []Upstream
}

func (sl srvLookup) isFresh() bool {
	return time.Since(sl.freshness) < time.Duration(sl.srvUpstreams.Refresh)
}

// UpstreamResolver holds the set of addresses of DNS resolvers of
// upstream addresses
type UpstreamResolver struct {
	// The addresses of DNS resolvers to use when looking up the addresses of proxy upstreams.
	// It accepts network addresses with port range of only 1. If the host is an IP address,
	// it will be dialed directly to resolve the upstream server.
	// If the host is not an IP address, the addresses are resolved using the name resolution
	// convention of the Go standard library.
	// If the array contains more than 1 resolver address, one is chosen at random.
	Addresses []string `json:"addresses,omitempty"`
	netAddrs  []caddy.NetworkAddress
}

// ParseAddresses parses all the configured network addresses
// and ensures they're ready to be used.
func (u *UpstreamResolver) ParseAddresses() error {
	for _, v := range u.Addresses {
		addr, err := caddy.ParseNetworkAddressWithDefaults(v, "udp", 53)
		if err != nil {
			return err
		}
		if addr.PortRangeSize() != 1 {
			return fmt.Errorf("resolver address must have exactly one address; cannot call %v", addr)
		}
		u.netAddrs = append(u.netAddrs, addr)
	}
	return nil
}

func allNew(upstreams []Upstream) []*Upstream {
	results := make([]*Upstream, len(upstreams))
	for i := range upstreams {
		results[i] = &upstreams[i]
	}
	return results
}

var (
	srvs   = make(map[string]srvLookup)
	srvsMu sync.RWMutex
)

// Interface guards
var (
	_ caddy.Provisioner     = (*SRVUpstreams)(nil)
	_ UpstreamSource        = (*SRVUpstreams)(nil)
	_ caddyfile.Unmarshaler = (*SRVUpstreams)(nil)
)
