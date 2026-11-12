package samizdat

import (
	"hash/maphash"
	"math/bits"
	"sync"
	"time"
)

// replayFilter remembers the SessionIDs that have authenticated, so that one
// copied from an observed ClientHello can't authenticate again. Without it,
// anyone who sees a client's ClientHello can put its SessionID into their own
// ClientHello, complete the handshake, and find the server's own certificate
// where the cover site's should be.
//
// Legacy SessionIDs carry no timestamp, so there's no point after which a
// copy stops being valid: the filter remembers each one for between window
// and twice window, or for less when more than capacity authenticate within
// a window. It is two generations: new SessionIDs go into the current one,
// both are searched, and rotation drops the older.
//
// A false match must be all but impossible. It sends a real client to the
// cover site, and a client that doesn't pin the server's certificate accepts
// that handshake and sends its CONNECT requests to the cover site. So each
// generation stores a keyed 63-bit fingerprint of every SessionID exactly,
// not a Bloom filter: a fresh SessionID matches one of n stored by chance
// with probability about n/2^63, around 2e-13 when both generations hold a
// million. Memory is about 10.7 bytes per capacity entry per generation,
// whatever the load.
type replayFilter struct {
	mu        sync.Mutex
	window    time.Duration
	capacity  int
	seed      maphash.Seed
	cur, prev *fingerprintSet
	rotatedAt time.Time
	now       func() time.Time
}

func newReplayFilter(window time.Duration, capacity int) *replayFilter {
	f := &replayFilter{
		window:   window,
		capacity: capacity,
		seed:     maphash.MakeSeed(),
		now:      time.Now,
	}
	f.cur = newFingerprintSet(capacity)
	f.rotatedAt = f.now()
	return f
}

// seen reports whether key was added before, and adds it if not.
func (f *replayFilter) seen(key []byte) bool {
	// The seed is secret, so no one can choose keys whose fingerprints
	// collide. Zero marks an empty slot, so fingerprints are never zero.
	fp := maphash.Bytes(f.seed, key) | 1

	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	if elapsed := now.Sub(f.rotatedAt); elapsed >= f.window {
		// After two windows with no lookup, cur is as old as prev would be
		// and goes too.
		f.rotate()
		if elapsed >= 2*f.window {
			f.prev = nil
		}
		// A rotation on time stays on the window's boundary, however late
		// the lookup that triggers it, so nothing outlives two windows.
		f.rotatedAt = now.Add(-(elapsed % f.window))
	}

	if f.cur.has(fp) || (f.prev != nil && f.prev.has(fp)) {
		return true
	}

	// Rotating for capacity only to make room for a new key, after the
	// lookup, so a repeat can't push its own generation out first.
	if f.cur.n >= f.capacity {
		f.rotate()
		f.rotatedAt = now
	}
	f.cur.add(fp)
	return false
}

func (f *replayFilter) rotate() {
	f.prev = f.cur
	f.cur = newFingerprintSet(f.capacity)
}

// fingerprintSet is an open-addressing hash set of nonzero uint64s with
// linear probing. It holds at most the capacity it was made for, which
// keeps it at most three quarters full.
type fingerprintSet struct {
	slots []uint64
	n     int
}

func newFingerprintSet(capacity int) *fingerprintSet {
	return &fingerprintSet{slots: make([]uint64, capacity+capacity/3+1)}
}

// find returns the slot holding fp, or the empty slot where it belongs.
func (s *fingerprintSet) find(fp uint64) int {
	// fp is already a keyed hash; its high bits pick the starting slot.
	i, _ := bits.Mul64(fp, uint64(len(s.slots)))
	for {
		if v := s.slots[i]; v == fp || v == 0 {
			return int(i)
		}
		if i++; i == uint64(len(s.slots)) {
			i = 0
		}
	}
}

func (s *fingerprintSet) has(fp uint64) bool {
	return s.slots[s.find(fp)] == fp
}

func (s *fingerprintSet) add(fp uint64) {
	if i := s.find(fp); s.slots[i] == 0 {
		s.slots[i] = fp
		s.n++
	}
}
