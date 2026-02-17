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
	maxStreams   int
	idleTimeout time.Duration
	createFunc  func(ctx context.Context) (*h2Transport, error)
	closed      bool
	closeCh     chan struct{}
}

// newConnPool creates a connection pool that creates new transports via createFunc.
func newConnPool(maxStreams int, idleTimeout time.Duration, createFunc func(ctx context.Context) (*h2Transport, error)) *connPool {
	p := &connPool{
		maxStreams:   maxStreams,
		idleTimeout: idleTimeout,
		createFunc:  createFunc,
		closeCh:     make(chan struct{}),
	}

	// Background cleanup goroutine
	go p.cleanupLoop()

	return p
}

// getTransport returns an existing transport with available capacity, or
// creates a new one.
func (p *connPool) getTransport(ctx context.Context) (*h2Transport, error) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil, context.Canceled
	}

	// Find an existing transport with capacity
	for _, t := range p.transports {
		if !t.isClosed() && t.hasCapacity() {
			p.mu.Unlock()
			return t, nil
		}
	}

	p.mu.Unlock()

	// Create a new transport
	t, err := p.createFunc(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.transports = append(p.transports, t)
	p.mu.Unlock()

	return t, nil
}

// cleanupLoop periodically removes closed and idle transports.
func (p *connPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
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

// cleanup removes closed transports and closes idle ones.
func (p *connPool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	alive := make([]*h2Transport, 0, len(p.transports))
	for _, t := range p.transports {
		if t.isClosed() {
			continue
		}
		if t.streamCount() == 0 {
			// Close idle transports (we'll create new ones on demand)
			t.close()
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
		t.close()
	}
	p.transports = nil
	return nil
}
