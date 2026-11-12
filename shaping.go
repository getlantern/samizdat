package samizdat

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"sync"
	"time"
)

// Connection-start shaping. A samizdat connection's first records otherwise
// have the sizes and directions of an HTTP/2 client preface, SETTINGS
// exchange and CONNECT, which CenKL (Ortwein et al., IEEE S&P 2027) found
// distinguish HTTP/2 proxies from real TLS within the first few packets.
// With shaping, client and server instead exchange the first
// shapingRecords TLS records on a schedule of sizes and directions drawn
// from CenKL's model of real TLS (shapingmodel.go), as its ProxyShaper does:
//
//   - Both ends export keying material from the TLS session and seed the
//     same sampler with it, so they draw the same schedule without sending
//     it. The schedule's first record is always the client's.
//   - On its turn, a side sends exactly one record of the scheduled size:
//     a 2-byte length, that much of what it has queued to send, and padding.
//     With nothing queued it sends padding alone. It reads exactly the
//     records the schedule gives the peer.
//   - The client's first record starts with a marker from the keying
//     material and the schedule. A server that accepts shaping reads the
//     client's first 8 bytes: the marker means a shaping client that drew
//     the server's schedule, anything else (an HTTP/2 preface) a client
//     that doesn't shape, whose bytes are replayed. A client that drew
//     another schedule, from another version of the model or the sampler,
//     sends another marker, and the connection fails at once as a bad
//     HTTP/2 preface rather than partway through mismatched records.
//   - After the schedule both sides pass data straight through.
//
// The schedule fixes TLS record sizes and directions (dynamic record sizing
// is off on both sides, so one Write is one record). The model is of TCP
// packets, and a record usually leaves as one packet of its size, but TCP
// may split one larger than the path's MSS (a 1460-byte record on a path
// whose MSS is 1448) or coalesce records written back to back. Timing isn't
// shaped.

const (
	shapingRecords = 10
	// tls13RecordOverhead is a TLS 1.3 record's header, AEAD tag and inner
	// content type: 5 + 16 + 1 bytes for both AES-GCM and ChaCha20-Poly1305.
	tls13RecordOverhead = 22
	shapingMarkerLen    = 8
	shapingLenLen       = 2
	shapingLabel        = "EXPORTER-samizdat-shaping-v1"
	// shapingMaxQueued bounds what Writes may queue while the schedule runs.
	shapingMaxQueued = 1 << 20
	// shapingTries is how many schedules to draw before settling for one
	// whose records are raised to the smallest size that fits the framing.
	shapingTries = 32
)

// shapingGrace is how long a side waits, on its turn, for something to send
// before sending padding alone. A connection's first writes (the HTTP/2
// preface, SETTINGS) come right after the handshake; without the wait the
// first record would usually go out empty and the preface wait for the
// side's next turn. A variable for tests.
var shapingGrace = 5 * time.Millisecond

// shapingSchedule derives the schedule and the client's marker from a TLS
// session's exported keying material.
func shapingSchedule(ekm func(label string, context []byte, length int) ([]byte, error)) ([]int, [shapingMarkerLen]byte, error) {
	km, err := ekm(shapingLabel, nil, 32+shapingMarkerLen)
	if err != nil {
		return nil, [shapingMarkerLen]byte{}, err
	}
	sched, err := shapingDraw([32]byte(km[:32]))
	if err != nil {
		return nil, [shapingMarkerLen]byte{}, err
	}
	return sched, shapingMarker(km[32:], sched), nil
}

// shapingMarker is the marker a client that drew sched sends: the two ends
// each draw the schedule from their own copy of the model, and the marker
// matches only if they drew the same one.
func shapingMarker(secret []byte, sched []int) [shapingMarkerLen]byte {
	mac := hmac.New(sha256.New, secret)
	for _, s := range sched {
		binary.Write(mac, binary.BigEndian, int32(s))
	}
	var marker [shapingMarkerLen]byte
	copy(marker[:], mac.Sum(nil))
	return marker
}

// shapingDraw draws a schedule from the model with a sampler seeded by seed.
func shapingDraw(seed [32]byte) ([]int, error) {
	if shapingScheduleOverride != nil {
		return slices.Clone(shapingScheduleOverride), nil
	}
	model, err := loadShapingModel()
	if err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewChaCha8(seed))
	var sched []int
	for range shapingTries {
		sched = model.schedule(rng, shapingRecords, true)
		if shapingScheduleFits(sched) {
			return sched, nil
		}
	}
	// Rare: bring each record within what the framing and a TLS record
	// allow, keeping its direction.
	if len(sched) > 0 && sched[0] < 0 {
		sched[0] = -sched[0]
	}
	for i, s := range sched {
		size := min(max(abs(s), shapingMinSize(i)), shapingMaxSize)
		if s < 0 {
			size = -size
		}
		sched[i] = size
	}
	return sched, nil
}

func shapingMinSize(i int) int {
	n := tls13RecordOverhead + shapingLenLen
	if i == 0 {
		n += shapingMarkerLen
	}
	return n
}

// shapingMaxSize is the largest TLS 1.3 record on the wire.
const shapingMaxSize = tls13RecordOverhead + 1<<14

func shapingScheduleFits(sched []int) bool {
	if len(sched) == 0 || sched[0] <= 0 {
		return false
	}
	for i, s := range sched {
		if abs(s) < shapingMinSize(i) || abs(s) > shapingMaxSize {
			return false
		}
	}
	return true
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// shapedConn runs the shaping schedule over a TLS connection and then
// passes data straight through.
type shapedConn struct {
	net.Conn
	sched  []int
	client bool
	marker [shapingMarkerLen]byte
	// markerRead is set on the server, which has already read the marker
	// from the client's first record.
	markerRead bool

	mu      sync.Mutex
	cond    *sync.Cond
	out     []byte // queued by Write while the schedule runs
	in      []byte // received while the schedule ran, not yet Read
	shaping bool
	err     error
	// rdl and wdl are the caller's deadlines. While the schedule runs, Read
	// and Write wait on cond, and the schedule's reads on Conn run without
	// the caller's read deadline (a watchdog bounds the schedule instead),
	// which reaches Conn once the schedule is done.
	rdl, wdl time.Time
	// grace and timeout are shapingGrace and shapingTimeout when the
	// connection was made.
	grace, timeout time.Duration
	// wmu orders writes on Conn: the schedule's records, the flush of what
	// was queued, then Writes once the schedule is done.
	wmu sync.Mutex
}

// shapingTimeout bounds the whole schedule, so a peer that stops partway
// can't hold the connection. A variable for tests.
var shapingTimeout = 30 * time.Second

// shapingScheduleOverride, when set, replaces the drawn schedule. For tests.
var shapingScheduleOverride []int

// shapingScheduled, when set, is told each schedule a shapedConn runs. For
// tests.
var shapingScheduled func(client bool, sched []int)

func newShapedConn(conn net.Conn, sched []int, client bool, marker [shapingMarkerLen]byte, markerRead bool) *shapedConn {
	if f := shapingScheduled; f != nil {
		f(client, sched)
	}
	c := &shapedConn{
		Conn:       conn,
		sched:      sched,
		client:     client,
		marker:     marker,
		markerRead: markerRead,
		shaping:    true,
		grace:      shapingGrace,
		timeout:    shapingTimeout,
	}
	c.cond = sync.NewCond(&c.mu)
	go c.run()
	return c
}

// shapingActive reports whether the schedule is still running. The lean
// HTTP/2 writer doesn't batch while it is: a Write blocked on a full queue
// inside a batch would hold back the schedule's own records, which batchConn
// keeps behind the batch, and the schedule could then never free the queue.
func (c *shapedConn) shapingActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shaping
}

func (c *shapedConn) run() {
	// A peer that stops partway, reading or writing, would leave the
	// schedule blocked on Conn; closing it fails the schedule.
	watchdog := time.AfterFunc(c.timeout, func() { c.Conn.Close() })
	err := c.runSchedule()
	if !watchdog.Stop() && err == nil {
		err = errors.New("samizdat: shaping schedule timed out")
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.mu.Lock()
	pending := c.out
	c.out = nil
	c.shaping = false
	if err != nil {
		c.err = err
	} else {
		// The schedule's reads ran without the caller's read deadline.
		c.Conn.SetReadDeadline(c.rdl)
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	if err != nil {
		c.Conn.Close()
		return
	}
	if len(pending) > 0 {
		if _, err := c.Conn.Write(pending); err != nil {
			c.mu.Lock()
			c.err = err
			c.cond.Broadcast()
			c.mu.Unlock()
			// The Writes that queued these bytes have returned, and a Read
			// may already be in Conn.Read: closing is what tells them.
			c.Conn.Close()
		}
	}
}

func (c *shapedConn) runSchedule() error {
	buf := make([]byte, 1<<14)
	for i, s := range c.sched {
		mine := (s > 0) == c.client
		plain := abs(s) - tls13RecordOverhead
		head := 0
		if i == 0 {
			head = shapingMarkerLen
		}
		if plain < head+shapingLenLen || plain > len(buf) {
			return errors.New("samizdat: shaping schedule record out of range")
		}
		if mine {
			rec := buf[:plain]
			clear(rec)
			if i == 0 {
				copy(rec, c.marker[:])
			}
			data := c.take(plain - head - shapingLenLen)
			binary.BigEndian.PutUint16(rec[head:], uint16(len(data)))
			copy(rec[head+shapingLenLen:], data)
			c.wmu.Lock()
			_, err := c.Conn.Write(rec)
			c.wmu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		if i == 0 && c.markerRead {
			plain -= shapingMarkerLen
			head = 0
		}
		rec := buf[:plain]
		if _, err := io.ReadFull(c.Conn, rec); err != nil {
			return err
		}
		if head > 0 && !bytes.Equal(rec[:head], c.marker[:]) {
			return errors.New("samizdat: shaping marker mismatch")
		}
		n := int(binary.BigEndian.Uint16(rec[head:]))
		if head+shapingLenLen+n > plain {
			return errors.New("samizdat: shaped record length exceeds its record")
		}
		if n > 0 {
			c.mu.Lock()
			c.in = append(c.in, rec[head+shapingLenLen:head+shapingLenLen+n]...)
			c.cond.Broadcast()
			c.mu.Unlock()
		}
	}
	return nil
}

// waitLocked waits on cond until it's signalled or deadline passes, and
// reports false if deadline has passed. c.mu must be held.
func (c *shapedConn) waitLocked(deadline time.Time) bool {
	if deadline.IsZero() {
		c.cond.Wait()
		return true
	}
	d := time.Until(deadline)
	if d <= 0 {
		return false
	}
	expired := false
	t := time.AfterFunc(d, func() {
		c.mu.Lock()
		expired = true
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	c.cond.Wait()
	t.Stop()
	return !expired || time.Now().Before(deadline)
}

// take returns up to n queued bytes, waiting up to shapingGrace for some if
// none are queued.
func (c *shapedConn) take(n int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.out) == 0 && c.err == nil {
		deadline := time.Now().Add(c.grace)
		for len(c.out) == 0 && c.err == nil && c.waitLocked(deadline) {
		}
	}
	n = min(n, len(c.out))
	data := bytes.Clone(c.out[:n])
	c.out = c.out[n:]
	c.cond.Broadcast()
	return data
}

func (c *shapedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	for c.shaping && len(c.out)+len(b) > shapingMaxQueued && c.err == nil {
		if !c.waitLocked(c.wdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
	}
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if c.shaping {
		if !c.wdl.IsZero() && !time.Now().Before(c.wdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		c.out = append(c.out, b...)
		c.cond.Broadcast()
		c.mu.Unlock()
		return len(b), nil
	}
	c.mu.Unlock()
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.Conn.Write(b)
}

func (c *shapedConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	for len(c.in) == 0 && c.shaping && c.err == nil {
		if !c.waitLocked(c.rdl) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
	}
	if len(c.in) > 0 {
		n := copy(b, c.in)
		c.in = c.in[n:]
		c.mu.Unlock()
		return n, nil
	}
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *shapedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *shapedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl = t
	c.cond.Broadcast()
	if c.shaping {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *shapedConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *shapedConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	if c.err == nil {
		c.err = net.ErrClosed
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	return err
}

// shapedTLSConn keeps the server's TLS state reachable through a shapedConn,
// for x/net's HTTP/2 server.
type shapedTLSConn struct {
	*shapedConn
	tls *tls.Conn
}

func (c *shapedTLSConn) ConnectionState() tls.ConnectionState { return c.tls.ConnectionState() }

// replayedTLSConn returns prefix before reading on from the TLS connection:
// the bytes the server read from a client that turned out not to shape.
type replayedTLSConn struct {
	*tls.Conn
	prefix []byte
}

func (c *replayedTLSConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// shapingPeekTimeout bounds how long the server waits for a client's first
// bytes to tell whether it shapes. A variable for tests.
var shapingPeekTimeout = 10 * time.Second

// acceptShaping tells a shaping client from one that doesn't by its first
// bytes, and returns the connection to serve HTTP/2 on.
func acceptShaping(tc *tls.Conn) (net.Conn, error) {
	state := tc.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return tc, nil
	}
	sched, marker, err := shapingSchedule(state.ExportKeyingMaterial)
	if err != nil {
		return nil, err
	}
	var first [shapingMarkerLen]byte
	tc.SetReadDeadline(time.Now().Add(shapingPeekTimeout))
	_, err = io.ReadFull(tc, first[:])
	tc.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	if first != marker {
		return &replayedTLSConn{Conn: tc, prefix: first[:]}, nil
	}
	return &shapedTLSConn{shapedConn: newShapedConn(tc, sched, false, marker, true), tls: tc}, nil
}
