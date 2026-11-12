package samizdat

import (
	"hash/maphash"
	"math"
	"sync"
	"time"
)

// replayFalsePositiveRate is the chance that a fresh SessionID is taken for a
// replay, per generation searched. A false positive sends a real client to
// the masquerade, and the client then fails that dial.
const replayFalsePositiveRate = 1e-6

// replayFilter remembers the SessionIDs that have authenticated, so that one
// copied from an observed ClientHello can't authenticate again. Without it,
// anyone who sees a client's ClientHello can put its SessionID into their own
// ClientHello, complete the handshake, and find the server's own certificate
// where the cover site's should be.
//
// Legacy SessionIDs carry no timestamp, so there's no point after which a
// copy stops being valid: the filter remembers each one for between window
// and twice window, or for less when more than capacity authenticate within
// a window. It is two Bloom filters: new SessionIDs go into the current one,
// both are searched, and rotation drops the older. Memory stays at about 3.6
// bytes per capacity entry per generation, whatever the load.
type replayFilter struct {
	mu        sync.Mutex
	window    time.Duration
	capacity  int
	cur, prev *bloomFilter
	rotatedAt time.Time
	now       func() time.Time
}

func newReplayFilter(window time.Duration, capacity int) *replayFilter {
	f := &replayFilter{
		window:   window,
		capacity: capacity,
		now:      time.Now,
	}
	f.cur = newBloomFilter(capacity, replayFalsePositiveRate)
	f.rotatedAt = f.now()
	return f
}

// seen reports whether key was added before, and adds it if not.
func (f *replayFilter) seen(key []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if now := f.now(); now.Sub(f.rotatedAt) >= f.window || f.cur.n >= f.capacity {
		// After two windows with no lookup, cur is as old as prev would be
		// and goes too.
		f.prev = f.cur
		if now.Sub(f.rotatedAt) >= 2*f.window {
			f.prev = nil
		}
		f.cur = newBloomFilter(f.capacity, replayFalsePositiveRate)
		f.rotatedAt = now
	}

	h1, h2 := f.cur.hash(key)
	if f.cur.has(h1, h2) {
		return true
	}
	if f.prev != nil {
		if p1, p2 := f.prev.hash(key); f.prev.has(p1, p2) {
			return true
		}
	}
	f.cur.add(h1, h2)
	return false
}

// bloomFilter is a Bloom filter over keys hashed with random seeds, so that
// no one can choose keys that collide in it.
type bloomFilter struct {
	bits   []uint64
	m      uint64 // number of bits
	k      int    // probes per key
	n      int    // keys added
	s1, s2 maphash.Seed
}

func newBloomFilter(capacity int, p float64) *bloomFilter {
	m := uint64(math.Ceil(-float64(capacity) * math.Log(p) / (math.Ln2 * math.Ln2)))
	m = (m + 63) &^ 63
	k := max(1, int(math.Round(float64(m)/float64(capacity)*math.Ln2)))
	return &bloomFilter{
		bits: make([]uint64, m/64),
		m:    m,
		k:    k,
		s1:   maphash.MakeSeed(),
		s2:   maphash.MakeSeed(),
	}
}

func (b *bloomFilter) hash(key []byte) (uint64, uint64) {
	// Double hashing: k probes from two hashes. The step is odd so it's never 0.
	return maphash.Bytes(b.s1, key), maphash.Bytes(b.s2, key) | 1
}

func (b *bloomFilter) has(h1, h2 uint64) bool {
	for i := 0; i < b.k; i++ {
		bit := (h1 + uint64(i)*h2) % b.m
		if b.bits[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

func (b *bloomFilter) add(h1, h2 uint64) {
	for i := 0; i < b.k; i++ {
		bit := (h1 + uint64(i)*h2) % b.m
		b.bits[bit/64] |= 1 << (bit % 64)
	}
	b.n++
}
