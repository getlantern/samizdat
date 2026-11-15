package samizdat

import (
	"context"
	"fmt"
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
	// dialing is the transport being created, if any. One is created at a
	// time: when many CONNECTs find no capacity at once, a burst of TLS
	// handshakes to one server is conspicuous and costly to it, and the first
	// new connection can usually carry them all.
	dialing *dialAttempt
	// onWait, if set, is called each time a caller starts waiting on a
	// creation; tests use it to know who is waiting.
	onWait func()
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

		// Wait for a transport to be created, and look again. The creation
		// is shared, so it runs apart from whichever caller started it: one
		// that gives up mustn't throw away the handshake the others wait on.
		a := p.dialing
		if a == nil {
			a = &dialAttempt{done: make(chan struct{})}
			p.dialing = a
			go p.dial(context.WithoutCancel(ctx), a)
		}
		p.mu.Unlock()
		if p.onWait != nil {
			p.onWait()
		}
		select {
		case <-a.done:
		case <-p.closeCh:
			return nil, context.Canceled
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if a.err != nil {
			// Every caller waiting on a failed creation fails with it at
			// once, rather than each trying in turn against a server that
			// isn't answering.
			return nil, a.err
		}
		p.mu.Lock()
	}
}

// dialAttempt is the creation of a transport that callers finding no
// capacity wait on.
type dialAttempt struct {
	done chan struct{}
	// err is the creation's error, set before done is closed.
	err error
}

// dial creates a transport for a and adds it to the pool.
func (p *connPool) dial(ctx context.Context, a *dialAttempt) {
	// Closing the pool ends the dial: nothing will use what it makes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-p.closeCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	var t *h2Transport
	defer func() {
		if r := recover(); r != nil {
			a.err = fmt.Errorf("samizdat: creating transport: %v", r)
		}
		var orphan *h2Transport
		p.mu.Lock()
		if a.err == nil {
			if p.closed {
				// Closed while this one was dialing: close would never
				// reach it.
				orphan = t
				a.err = context.Canceled
			} else {
				p.transports = append(p.transports, t)
			}
		}
		p.dialing = nil
		close(a.done)
		p.mu.Unlock()
		if orphan != nil {
			orphan.closeWithReason("client closed")
		}
	}()
	t, a.err = p.createFunc(ctx)
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
