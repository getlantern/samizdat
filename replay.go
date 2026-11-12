package samizdat

import (
	"hash/maphash"
	"log"
	"math"
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
// million. A generation grows with the SessionIDs it holds, to at most
// about 10.7 bytes per capacity entry.
//
// The filter belongs to one Server and lives in memory: a restart, a Server
// created anew, or another server using the same key pair has not seen the
// SessionIDs this one has, and accepts a copy of them.
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

	now := f.now()
	if elapsed := now.Sub(f.rotatedAt); elapsed >= f.window {
		// After two windows with no lookup, cur is as old as prev would be
		// and goes too.
		if elapsed >= 2*f.window {
			f.cur.reset()
		}
		f.rotate()
		// A rotation on time stays on the window's boundary, however late
		// the lookup that triggers it, so nothing outlives two windows.
		f.rotatedAt = now.Add(-(elapsed % f.window))
	}

	if f.cur.has(fp) || (f.prev != nil && f.prev.has(fp)) {
		f.mu.Unlock()
		return true
	}

	// Rotating for capacity only to make room for a new key, after the
	// lookup, so a repeat can't push its own generation out first.
	var early time.Duration
	if f.cur.n >= f.capacity {
		early = max(now.Sub(f.rotatedAt), 1)
		f.rotate()
		f.rotatedAt = now
	}
	f.cur.add(fp)
	f.mu.Unlock()

	if early > 0 {
		// Retention is now shorter than the operator asked for, which
		// nothing else would show.
		log.Printf("[samizdat] replay filter: %d SessionIDs authenticated in %v, within ReplayWindow (%v); "+
			"they are remembered for less than ReplayWindow until the load drops or ReplayCapacity is raised",
			f.capacity, early.Round(time.Second), f.window)
	}
	return false
}

// rotate drops the older generation and starts a new current one. An empty
// current generation is kept as it is, since there is nothing in it to age.
func (f *replayFilter) rotate() {
	if f.cur.n == 0 {
		f.prev = nil
		return
	}
	f.prev = f.cur
	f.cur = newFingerprintSet(f.capacity)
}

// maxReplayCapacity is the largest ReplayCapacity whose table size,
// capacity + capacity/3 + 1, still fits in an int.
const maxReplayCapacity = math.MaxInt / 4 * 3

// fingerprintSetMinSlots is the size a fingerprintSet starts at.
const fingerprintSetMinSlots = 64

// fingerprintSet is an open-addressing hash set of nonzero uint64s with
// linear probing. It starts small and doubles as it fills, up to the size
// that holds the capacity it was made for at most three quarters full, so
// its memory follows what it holds and not what it could.
type fingerprintSet struct {
	slots    []uint64
	n        int
	maxSlots int
}

func newFingerprintSet(capacity int) *fingerprintSet {
	maxSlots := capacity + capacity/3 + 1
	return &fingerprintSet{
		slots:    make([]uint64, min(maxSlots, fingerprintSetMinSlots)),
		maxSlots: maxSlots,
	}
}

// reset empties the set.
func (s *fingerprintSet) reset() {
	if s.n > 0 {
		s.slots = make([]uint64, min(s.maxSlots, fingerprintSetMinSlots))
		s.n = 0
	}
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

// add puts fp in the set. The caller keeps the set within its capacity,
// which is what leaves find an empty slot to stop at.
func (s *fingerprintSet) add(fp uint64) {
	i := s.find(fp)
	if s.slots[i] != 0 {
		return
	}
	if 4*(s.n+1) > 3*len(s.slots) && len(s.slots) < s.maxSlots {
		s.grow()
		i = s.find(fp)
	}
	s.slots[i] = fp
	s.n++
}

// grow doubles the table, up to maxSlots, and puts every fingerprint in its
// new place.
func (s *fingerprintSet) grow() {
	old := s.slots
	s.slots = make([]uint64, min(2*len(old), s.maxSlots))
	for _, fp := range old {
		if fp != 0 {
			s.slots[s.find(fp)] = fp
		}
	}
}
