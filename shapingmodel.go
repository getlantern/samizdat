package samizdat

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
	"sync"
)

// shapingModelGz is a model of the sizes and directions of the first packets
// after the handshake in real TLS connections, built by cmd/shapingmodel
// from CenKL's Markov order 1 size-and-direction model (Ortwein et al., IEEE
// S&P 2027), which was trained on 326.5 million TLS flows at an ISP.
//
// Format, little-endian, gzipped: "SZSM", version (1), position count; then
// for each position:
//
//	size kind: 0 the size is exact, 1 it's a bin of an empirical quantizer:
//	  lookup length, lookup[size-1] = bin for each size;
//	  bin count; per bin: value count, (value u16, count u32)...
//	row count; per row: previous direction (0xff: none), previous size or
//	  bin under this position's quantizer, outcomes
//	fallback outcomes for a previous server packet, then a client one
//
// where outcomes are a count and (direction<<15 | size or bin, weight u16)...
// Direction 1 is client to server.
//
//go:embed shaping_model.bin.gz
var shapingModelGz []byte

type shapingOutcome struct {
	dir    uint8
	value  uint16 // a size, or a bin under the position's quantizer
	weight uint16
}

// shapingOutcomes are a row's outcomes. Sampling scans them: a schedule
// draws ten times, and cumulative weights would more than double the
// model's memory.
type shapingOutcomes struct {
	outs []shapingOutcome
}

// sample draws an outcome, among those whose direction keep allows when it's
// not nil.
func (o *shapingOutcomes) sample(rng *rand.Rand, keep func(dir uint8) bool) (shapingOutcome, bool) {
	var total uint64
	for _, x := range o.outs {
		if keep == nil || keep(x.dir) {
			total += uint64(x.weight)
		}
	}
	if total == 0 {
		return shapingOutcome{}, false
	}
	r := rng.Uint64N(total)
	for _, x := range o.outs {
		if keep != nil && !keep(x.dir) {
			continue
		}
		if r < uint64(x.weight) {
			return x, true
		}
		r -= uint64(x.weight)
	}
	panic("unreachable")
}

type shapingBin struct {
	values []uint16
	cum    []uint64
}

type shapingPosition struct {
	exact    bool
	lookup   []uint16 // bin for size-1
	bins     []shapingBin
	rows     map[uint32]*shapingOutcomes // keyed by dir<<16 | previous size or bin
	first    *shapingOutcomes            // position 0: no previous packet
	fallback [2]shapingOutcomes
}

type shapingModel struct {
	positions []shapingPosition
}

var loadShapingModel = sync.OnceValues(func() (*shapingModel, error) {
	zr, err := gzip.NewReader(bytes.NewReader(shapingModelGz))
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return parseShapingModel(raw)
})

func parseShapingModel(b []byte) (*shapingModel, error) {
	r := bytes.NewReader(b)
	le := binary.LittleEndian
	var magic [4]byte
	var version, npos uint8
	if err := binary.Read(r, le, &magic); err != nil || string(magic[:]) != "SZSM" {
		return nil, errors.New("shaping model: bad magic")
	}
	binary.Read(r, le, &version)
	if version != 1 {
		return nil, fmt.Errorf("shaping model: version %d", version)
	}
	if err := binary.Read(r, le, &npos); err != nil {
		return nil, err
	}
	readOutcomes := func() (shapingOutcomes, error) {
		var n uint16
		if err := binary.Read(r, le, &n); err != nil {
			return shapingOutcomes{}, err
		}
		outs := make([]shapingOutcome, n)
		for i := range outs {
			var v, w uint16
			binary.Read(r, le, &v)
			if err := binary.Read(r, le, &w); err != nil {
				return shapingOutcomes{}, err
			}
			outs[i] = shapingOutcome{dir: uint8(v >> 15), value: v & 0x7fff, weight: w}
		}
		return shapingOutcomes{outs: outs}, nil
	}
	m := &shapingModel{}
	for range npos {
		var p shapingPosition
		var kind uint8
		if err := binary.Read(r, le, &kind); err != nil {
			return nil, err
		}
		p.exact = kind == 0
		if !p.exact {
			var n uint16
			binary.Read(r, le, &n)
			p.lookup = make([]uint16, n)
			if err := binary.Read(r, le, p.lookup); err != nil {
				return nil, err
			}
			var nbins uint16
			binary.Read(r, le, &nbins)
			p.bins = make([]shapingBin, nbins)
			for i := range p.bins {
				var nv uint16
				if err := binary.Read(r, le, &nv); err != nil {
					return nil, err
				}
				var total uint64
				for range nv {
					var v uint16
					var c uint32
					binary.Read(r, le, &v)
					if err := binary.Read(r, le, &c); err != nil {
						return nil, err
					}
					total += uint64(c)
					p.bins[i].values = append(p.bins[i].values, v)
					p.bins[i].cum = append(p.bins[i].cum, total)
				}
			}
		}
		var nrows uint16
		if err := binary.Read(r, le, &nrows); err != nil {
			return nil, err
		}
		p.rows = make(map[uint32]*shapingOutcomes, nrows)
		for range nrows {
			var dir uint8
			var prev uint16
			binary.Read(r, le, &dir)
			if err := binary.Read(r, le, &prev); err != nil {
				return nil, err
			}
			outs, err := readOutcomes()
			if err != nil {
				return nil, err
			}
			if dir == 0xff {
				p.first = &outs
			} else {
				p.rows[uint32(dir)<<16|uint32(prev)] = &outs
			}
		}
		for d := range p.fallback {
			var err error
			if p.fallback[d], err = readOutcomes(); err != nil {
				return nil, err
			}
		}
		m.positions = append(m.positions, p)
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("shaping model: %d trailing bytes", r.Len())
	}
	return m, nil
}

// quantize maps a packet size to this position's value for it.
func (p *shapingPosition) quantize(size int) uint16 {
	if p.exact {
		return uint16(size)
	}
	i := min(max(size, 1), len(p.lookup)) - 1
	return p.lookup[i]
}

// size turns an outcome's value back into a packet size, drawing from the
// sizes real traffic showed in its bin.
func (p *shapingPosition) size(rng *rand.Rand, value uint16) int {
	if p.exact {
		return int(value)
	}
	b := &p.bins[value]
	if len(b.values) == 0 {
		return 0
	}
	r := rng.Uint64N(b.cum[len(b.cum)-1])
	return int(b.values[sort.Search(len(b.cum), func(i int) bool { return b.cum[i] > r })])
}

// schedule draws the signed sizes of n packets, positive for client to
// server. The first is the client's when clientFirst is set.
func (m *shapingModel) schedule(rng *rand.Rand, n int, clientFirst bool) []int {
	n = min(n, len(m.positions))
	sched := make([]int, 0, n)
	var prevDir uint8
	var prevSize int
	for i := 0; i < n; i++ {
		p := &m.positions[i]
		var outs *shapingOutcomes
		var keep func(uint8) bool
		if i == 0 {
			outs = p.first
			if clientFirst {
				keep = func(d uint8) bool { return d == 1 }
			}
		} else {
			outs = p.rows[uint32(prevDir)<<16|uint32(p.quantize(prevSize))]
			if outs == nil {
				outs = &p.fallback[prevDir]
			}
		}
		o, ok := outs.sample(rng, keep)
		if !ok {
			o, _ = p.fallback[prevDir].sample(rng, keep)
		}
		size := p.size(rng, o.value)
		prevDir, prevSize = o.dir, size
		if o.dir == 1 {
			sched = append(sched, size)
		} else {
			sched = append(sched, -size)
		}
	}
	return sched
}
