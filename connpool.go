package samizdat

import (
	"context"
	"sync"
	"time"
)

// connPool manages a pool of H2 transports to a server, tracking active
// stream counts and cleaning up idle connections.
type connPool struct {
	mu          sync.Mutex
	transports  []*h2Transport
	maxStreams  int
	idleTimeout time.Duration
	createFunc  func(ctx context.Context) (*h2Transport, error)
	closed      bool
	closeCh     chan struct{}
	// dialing is closed when the transport being created, if any, is ready
	// or has failed. One is created at a time: when many CONNECTs find no
	// capacity at once, as they do when a connection stalls under all of
	// them, a burst of TLS handshakes to one server is conspicuous, and the
	// first new connection can usually carry them all.
	dialing chan struct{}
}

// newConnPool creates a connection pool that creates new transports via createFunc.
func newConnPool(maxStreams int, idleTimeout time.Duration, createFunc func(ctx context.Context) (*h2Transport, error)) *connPool {
	p := &connPool{
		maxStreams:  maxStreams,
		idleTimeout: idleTimeout,
		createFunc:  createFunc,
		closeCh:     make(chan struct{}),
	}

	// Background cleanup goroutine
	go p.cleanupLoop()

	return p
}

// getTransport returns an existing transport with available capacity, or
// creates a new one, with a stream slot reserved on it for the caller, who
// must open a tunnel on it with openReserved.
func (p *connPool) getTransport(ctx context.Context) (*h2Transport, error) {
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}

		// Find an existing transport with capacity
		for _, t := range p.transports {
			if !t.isClosed() && t.tryReserve() {
				p.mu.Unlock()
				return t, nil
			}
		}

		if p.dialing == nil {
			break
		}
		// Wait for the transport being created, and look again.
		dialing := p.dialing
		p.mu.Unlock()
		select {
		case <-dialing:
		case <-p.closeCh:
			return nil, context.Canceled
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		p.mu.Lock()
	}
	dialing := make(chan struct{})
	p.dialing = dialing
	p.mu.Unlock()

	// Create a new transport
	t, err := p.create(ctx, dialing)

	p.mu.Lock()
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if p.closed {
		// Closed while this one was dialing: close would never reach it.
		p.mu.Unlock()
		t.close()
		return nil, context.Canceled
	}
	t.activeStreams.Add(1)
	p.transports = append(p.transports, t)
	p.mu.Unlock()

	return t, nil
}

// create runs createFunc, and lets the callers waiting on dialing look again
// once it's done, however it ends.
func (p *connPool) create(ctx context.Context, dialing chan struct{}) (*h2Transport, error) {
	defer func() {
		p.mu.Lock()
		p.dialing = nil
		close(dialing)
		p.mu.Unlock()
	}()
	return p.createFunc(ctx)
}

// cleanupLoop periodically removes closed and idle transports.
func (p *connPool) cleanupLoop() {
	interval := 30 * time.Second
	if p.idleTimeout > 0 && p.idleTimeout < interval {
		interval = p.idleTimeout
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.closeCh:
			return
		}
	}
}

// cleanup removes closed transports and closes those idle for idleTimeout.
// Closing one the moment it has no stream would make every pause in a
// user's browsing cost a new TCP connection and TLS handshake.
func (p *connPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	alive := make([]*h2Transport, 0, len(p.transports))
	for _, t := range p.transports {
		if t.isClosed() {
			continue
		}
		if t.streamCount() == 0 && t.idleFor(now) >= p.idleTimeout {
			t.closeWithReason("idle")
			continue
		}
		alive = append(alive, t)
	}
	p.transports = alive
}

// close shuts down all transports in the pool.
func (p *connPool) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true
	close(p.closeCh)

	for _, t := range p.transports {
		t.closeWithReason("client closed")
	}
	p.transports = nil
	return nil
}
