package samizdat

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Shaper implements traffic shaping for H2 DATA frames to make traffic
// patterns match those of a real browser. It adds padding to frames and
// introduces timing jitter to defeat cross-layer RTT fingerprinting.
type Shaper struct {
	padding        bool
	jitter         bool
	maxJitterMs    int
	dataThreshold  int
	paddingProfile string

	totalBytes atomic.Int64

	mu sync.Mutex
}

// NewShaper creates a traffic shaper with the given configuration.
func NewShaper(padding, jitter bool, maxJitterMs, dataThreshold int, paddingProfile string) *Shaper {
	if maxJitterMs <= 0 {
		maxJitterMs = 30
	}
	if dataThreshold <= 0 {
		dataThreshold = 14000
	}
	if paddingProfile == "" {
		paddingProfile = "chrome"
	}
	return &Shaper{
		padding:        padding,
		jitter:         jitter,
		maxJitterMs:    maxJitterMs,
		dataThreshold:  dataThreshold,
		paddingProfile: paddingProfile,
	}
}

// Write shapes the outgoing data: adds padding and timing jitter, then
// writes to the underlying writer. This is called from streamConn.Write.
func (s *Shaper) Write(w io.Writer, data []byte) (int, error) {
	if !s.padding && !s.jitter {
		return w.Write(data)
	}

	totalSent := s.totalBytes.Load()

	// Apply timing jitter (1-maxJitterMs random delay)
	if s.jitter {
		jitterMs := randomInt(1, s.maxJitterMs+1)
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
	}

	dataLen := len(data)

	// Determine if we've crossed the threshold for aggressive padding
	aggressive := totalSent > int64(s.dataThreshold)

	if s.padding && dataLen > 0 {
		paddedData := s.padData(data, aggressive)
		n, err := w.Write(paddedData)
		if err != nil {
			return 0, err
		}
		// Report original data length as written
		if n >= dataLen {
			s.totalBytes.Add(int64(n))
			return dataLen, nil
		}
		return n, err
	}

	n, err := w.Write(data)
	s.totalBytes.Add(int64(n))
	return n, err
}

// padData adds padding to match Chrome traffic size distribution.
// Chrome H2 DATA frame size buckets:
//   - Small: 0-128B (15% of frames)
//   - Medium: 128-1024B (25%)
//   - Large: 1-4KB (35%)
//   - XL: 4-16KB (25%)
//
// When aggressive=true (above data threshold), padding increases by 50%.
func (s *Shaper) padData(data []byte, aggressive bool) []byte {
	targetSize := s.chooseTargetSize(len(data), aggressive)
	if targetSize <= len(data) {
		return data
	}

	// Pad with zero bytes to reach the target size
	padded := make([]byte, targetSize)
	copy(padded, data)
	// Remaining bytes are zero-padded
	return padded
}

// chooseTargetSize picks a target frame size based on the Chrome traffic
// profile distribution.
func (s *Shaper) chooseTargetSize(dataLen int, aggressive bool) int {
	// If data already exceeds our largest bucket, don't pad further
	if dataLen >= 16384 {
		return dataLen
	}

	// Pick a target size from the next bucket up
	var target int
	switch {
	case dataLen < 128:
		// Pad small frames to a random size in [dataLen, 256)
		target = randomInt(dataLen, 256)
	case dataLen < 1024:
		// Pad medium frames to a random size in [dataLen, 2048)
		target = randomInt(dataLen, 2048)
	case dataLen < 4096:
		// Pad large frames to a random size in [dataLen, 8192)
		target = randomInt(dataLen, 8192)
	default:
		// XL: pad to a random size in [dataLen, 16384)
		target = randomInt(dataLen, 16384)
	}

	if aggressive {
		// Increase padding by ~50% when above data threshold
		extra := randomInt(target/4, target/2+1)
		target += extra
	}

	return target
}

// RecordFragmenter splits inner TLS records across multiple H2 DATA frames
// to defeat encapsulated TLS detection (USENIX Sec 2024).
type RecordFragmenter struct {
	enabled bool
}

// NewRecordFragmenter creates a record-level fragmenter.
func NewRecordFragmenter(enabled bool) *RecordFragmenter {
	return &RecordFragmenter{enabled: enabled}
}

// Fragment splits data into multiple chunks with randomized sizes.
// This is used to fragment inner TLS records across H2 DATA frames.
func (rf *RecordFragmenter) Fragment(data []byte) [][]byte {
	if !rf.enabled || len(data) < 64 {
		return [][]byte{data}
	}

	// Split into 2-4 fragments with random sizes
	numFragments := randomInt(2, 5)
	if numFragments > len(data)/16 {
		numFragments = 2
	}

	fragments := make([][]byte, 0, numFragments)
	remaining := data

	for i := 0; i < numFragments-1 && len(remaining) > 16; i++ {
		// Choose a split point at roughly even intervals with randomization
		avgSize := len(remaining) / (numFragments - i)
		splitSize := randomInt(avgSize/2, avgSize*3/2+1)
		if splitSize > len(remaining)-16 {
			splitSize = len(remaining) - 16
		}
		if splitSize < 1 {
			splitSize = 1
		}

		fragment := make([]byte, splitSize)
		copy(fragment, remaining[:splitSize])
		fragments = append(fragments, fragment)
		remaining = remaining[splitSize:]
	}

	// Last fragment gets the remainder
	if len(remaining) > 0 {
		last := make([]byte, len(remaining))
		copy(last, remaining)
		fragments = append(fragments, last)
	}

	return fragments
}
