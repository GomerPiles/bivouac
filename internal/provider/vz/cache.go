package vz

import (
	"context"
	"errors"
)

// attachCacheEndpoint is the host transport for either guest OS. The caller
// supplies only a fixed helper path in an owned clone; the transport owns its
// lifetime after setup and cache.Service revokes it by guest name.
func (p *Provider) attachCacheEndpoint(ctx context.Context, name, helper string) ([]byte, error) {
	if err := p.runnerIsolation(name); err != nil {
		return nil, err
	}
	stream, err := p.rt.Duplex(context.WithoutCancel(ctx), name, []string{helper, "cache", "endpoint"})
	if err != nil {
		return nil, errors.New("open guest cache control stream")
	}
	p.cache.Revoke(name)
	listener, revocation, err := p.rt.CacheListeners(name)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return p.cache.AttachEndpoint(ctx, name, stream, listener, revocation)
}
