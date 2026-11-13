package samizdat

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
