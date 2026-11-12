// Command shapingmodel builds samizdat's embedded traffic-shaping model from
// a CenKL size-and-direction model of real TLS traffic (Ortwein et al.,
// "CenKL: Information-Theoretic Visibility into Censorship Circumvention
// Traffic Patterns", IEEE S&P 2027; models at
// github.com/censoredplanet/obfuscation, models/size_direction/markov_order_1).
//
//	go run ./cmd/shapingmodel -hist hist.bin -model model_assumptions.json -out shaping_model.bin.gz
//
// It decodes the first -positions packet positions of CenKL's TrafficProfile
// (postcard) and keeps, for each position, the most likely previous packets
// covering -keep of the probability mass, and for each the most likely next
// packets covering -keep of its mass, so the table fits in the library. A
// pruned previous packet falls back to a table conditioned on its direction
// alone. See shapingmodel.go for the output format.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"slices"
	"sort"
)

const maxSize = 1461 // CenKL's largest packet size (an MSS of 1460, plus one)

func main() {
	histPath := flag.String("hist", "", "CenKL hist.bin (size_direction, markov_order_1)")
	modelPath := flag.String("model", "", "CenKL model_assumptions.json")
	out := flag.String("out", "shaping_model.bin.gz", "output file")
	positions := flag.Int("positions", 10, "packet positions to keep")
	keep := flag.Float64("keep", 0.99, "probability mass kept per position and per row")
	flag.Parse()
	if *histPath == "" || *modelPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	hist, err := os.ReadFile(*histPath)
	if err != nil {
		log.Fatal(err)
	}
	modelJSON, err := os.ReadFile(*modelPath)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := build(hist, modelJSON, *positions, *keep)
	if err != nil {
		log.Fatal(err)
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(raw)
	zw.Close()
	if err := os.WriteFile(*out, gz.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s: %d bytes (%d before gzip)", *out, gz.Len(), len(raw))
}

// build decodes a CenKL TrafficProfile and its model assumptions and
// returns the model in samizdat's format, before gzip.
func build(hist, modelJSON []byte, positions int, keep float64) ([]byte, error) {
	profile, err := decodeProfile(hist)
	if err != nil {
		return nil, err
	}
	if profile.markovOrder != 1 {
		return nil, fmt.Errorf("want a Markov order 1 model, got %d", profile.markovOrder)
	}
	quantizers, err := decodeQuantizers(modelJSON, profile.markovOrder)
	if err != nil {
		return nil, err
	}
	n := min(positions, len(profile.hists), len(quantizers))
	if n < 1 || n > 255 {
		return nil, fmt.Errorf("%d positions; the format holds 1 to 255", n)
	}
	for i, h := range profile.hists[:n] {
		want := 2
		if i == 0 {
			want = 1
		}
		for _, e := range h.counts {
			if len(e.seq) != want {
				return nil, fmt.Errorf("position %d: sequence of %d packets, want %d for a Markov order 1 model", i, len(e.seq), want)
			}
		}
	}
	var buf bytes.Buffer
	buf.WriteString("SZSM")
	buf.WriteByte(1) // format version
	buf.WriteByte(byte(n))
	for i := range n {
		writePosition(&buf, i, profile.hists[i], quantizers[i], keep)
	}
	return buf.Bytes(), nil
}

// projection is a packet's quantized direction and size. dir is 1 for client
// to server, 0 for server to client.
type projection struct{ dir, size uint32 }

type entry struct {
	seq   []projection
	count uint64
}

type histogram struct {
	counts []entry
	total  uint64
}

type profile struct {
	hists       []histogram
	markovOrder uint32
}

type decoder struct {
	b   []byte
	pos int
}

var errShort = errors.New("truncated postcard data")

func (d *decoder) varint() (uint64, error) {
	var v uint64
	for shift := 0; ; shift += 7 {
		if d.pos >= len(d.b) || shift > 63 {
			return 0, errShort
		}
		c := d.b[d.pos]
		d.pos++
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, nil
		}
	}
}

// featureValue decodes CenKL's FeatureValue: Masked (0) or Bin(u32) (1).
func (d *decoder) featureValue() (uint32, bool, error) {
	tag, err := d.varint()
	if err != nil {
		return 0, false, err
	}
	switch tag {
	case 0:
		return 0, false, nil
	case 1:
		v, err := d.varint()
		return uint32(v), true, err
	}
	return 0, false, fmt.Errorf("FeatureValue tag %d at offset %d", tag, d.pos)
}

func (d *decoder) projection() (projection, error) {
	// PacketProjection { timestamp, direction, size }; timestamps are masked.
	if _, _, err := d.featureValue(); err != nil {
		return projection{}, err
	}
	dir, okd, err := d.featureValue()
	if err != nil {
		return projection{}, err
	}
	size, oks, err := d.featureValue()
	if err != nil {
		return projection{}, err
	}
	if !okd || !oks {
		return projection{}, fmt.Errorf("masked direction or size at offset %d", d.pos)
	}
	return projection{dir, size}, nil
}

// decodeProfile decodes TrafficProfile { profile: Vec<Histogram>, markov_order: u32 }.
func decodeProfile(b []byte) (*profile, error) {
	d := &decoder{b: b}
	n, err := d.varint()
	if err != nil {
		return nil, err
	}
	p := &profile{}
	for i := uint64(0); i < n; i++ {
		// Histogram { counts: HashMap<Sequence, usize>, total: usize, alpha: f64,
		// alphabet_size: usize, sequence_len: usize }
		entries, err := d.varint()
		if err != nil {
			return nil, err
		}
		h := histogram{counts: make([]entry, 0, entries)}
		for j := uint64(0); j < entries; j++ {
			l, err := d.varint()
			if err != nil {
				return nil, err
			}
			seq := make([]projection, l)
			for k := range seq {
				if seq[k], err = d.projection(); err != nil {
					return nil, err
				}
			}
			c, err := d.varint()
			if err != nil {
				return nil, err
			}
			h.counts = append(h.counts, entry{seq, c})
		}
		if h.total, err = d.varint(); err != nil {
			return nil, err
		}
		if d.pos+8 > len(d.b) {
			return nil, errShort
		}
		d.pos += 8 // alpha
		if _, err = d.varint(); err != nil {
			return nil, err
		}
		if _, err = d.varint(); err != nil {
			return nil, err
		}
		p.hists = append(p.hists, h)
	}
	mo, err := d.varint()
	if err != nil {
		return nil, err
	}
	p.markovOrder = uint32(mo)
	if d.pos != len(d.b) {
		return nil, fmt.Errorf("%d bytes left after the profile", len(d.b)-d.pos)
	}
	return p, nil
}

type bin struct {
	Values []int    `json:"values"`
	Counts []uint64 `json:"counts"`
}

// sizeQuantizer is "Identity" or {"Empirical": {"lookup": [...], "bins": [...]}}.
type sizeQuantizer struct {
	identity bool
	lookup   []uint32
	bins     []bin
}

func decodeQuantizers(b []byte, wantOrder uint32) ([]sizeQuantizer, error) {
	var m struct {
		MarkovOrder uint32 `json:"markov_order"`
		Quantizer   struct {
			PerPacket []struct {
				Direction struct {
					Quantization json.RawMessage `json:"quantization"`
				} `json:"direction"`
				Size struct {
					Quantization json.RawMessage `json:"quantization"`
				} `json:"size"`
			} `json:"PerPacket"`
		} `json:"quantizer"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.MarkovOrder != wantOrder {
		return nil, fmt.Errorf("model_assumptions is Markov order %d, hist.bin %d", m.MarkovOrder, wantOrder)
	}
	var qs []sizeQuantizer
	for i, pq := range m.Quantizer.PerPacket {
		if string(pq.Direction.Quantization) != `"Identity"` {
			return nil, fmt.Errorf("position %d: direction quantization %s, want Identity", i, pq.Direction.Quantization)
		}
		if string(pq.Size.Quantization) == `"Identity"` {
			qs = append(qs, sizeQuantizer{identity: true})
			continue
		}
		var e struct {
			Empirical struct {
				Lookup []uint32 `json:"lookup"`
				Bins   []bin    `json:"bins"`
			} `json:"Empirical"`
		}
		if err := json.Unmarshal(pq.Size.Quantization, &e); err != nil {
			return nil, fmt.Errorf("position %d size quantizer: %w", i, err)
		}
		if n := len(e.Empirical.Lookup); n == 0 || n > maxSize {
			return nil, fmt.Errorf("position %d: lookup of %d sizes", i, n)
		}
		qs = append(qs, sizeQuantizer{lookup: e.Empirical.Lookup, bins: e.Empirical.Bins})
	}
	return qs, nil
}

type outcome struct {
	dir, size uint32
	count     uint64
}

// prune keeps the most likely outcomes covering keep of the mass, and
// quantizes their weights to 1..65535 relative to the most likely.
func prune(outs []outcome, keep float64) []outcome {
	outs = slices.Clone(outs)
	sort.Slice(outs, func(a, b int) bool {
		if outs[a].count != outs[b].count {
			return outs[a].count > outs[b].count
		}
		return outs[a].dir<<16|outs[a].size < outs[b].dir<<16|outs[b].size
	})
	var total, acc uint64
	for _, o := range outs {
		total += o.count
	}
	n := 0
	for n < len(outs) {
		acc += outs[n].count
		n++
		if float64(acc) >= keep*float64(total) {
			break
		}
	}
	kept := outs[:n]
	top := float64(kept[0].count)
	for i := range kept {
		kept[i].count = uint64(max(1, math.Round(float64(kept[i].count)*65535/top)))
	}
	sort.Slice(kept, func(a, b int) bool {
		return kept[a].dir<<16|kept[a].size < kept[b].dir<<16|kept[b].size
	})
	return kept
}

func writeOutcomes(buf *bytes.Buffer, outs []outcome) {
	binary.Write(buf, binary.LittleEndian, uint16(len(outs)))
	for _, o := range outs {
		binary.Write(buf, binary.LittleEndian, uint16(o.dir<<15|o.size))
		binary.Write(buf, binary.LittleEndian, uint16(o.count))
	}
}

func writePosition(buf *bytes.Buffer, i int, h histogram, q sizeQuantizer, keep float64) {
	le := binary.LittleEndian
	if q.identity {
		buf.WriteByte(0)
	} else {
		buf.WriteByte(1)
		binary.Write(buf, le, uint16(len(q.lookup)))
		for _, b := range q.lookup {
			binary.Write(buf, le, uint16(b))
		}
		binary.Write(buf, le, uint16(len(q.bins)))
		for _, b := range q.bins {
			binary.Write(buf, le, uint16(len(b.Values)))
			for k, v := range b.Values {
				binary.Write(buf, le, uint16(v))
				binary.Write(buf, le, uint32(b.Counts[k]))
			}
		}
	}

	// Group by previous packet (the sequence's prefix).
	type key struct {
		has bool
		p   projection
	}
	rows := map[key][]outcome{}
	mass := map[key]uint64{}
	for _, e := range h.counts {
		last := e.seq[len(e.seq)-1]
		k := key{}
		if len(e.seq) == 2 {
			k = key{true, e.seq[0]}
		}
		rows[k] = append(rows[k], outcome{last.dir, last.size, e.count})
		mass[k] += e.count
	}
	keys := make([]key, 0, len(rows))
	var total uint64
	for k := range rows {
		keys = append(keys, k)
		total += mass[k]
	}
	sort.Slice(keys, func(a, b int) bool {
		if mass[keys[a]] != mass[keys[b]] {
			return mass[keys[a]] > mass[keys[b]]
		}
		return keys[a].p.dir<<16|keys[a].p.size < keys[b].p.dir<<16|keys[b].p.size
	})
	var kept []key
	var acc uint64
	for _, k := range keys {
		if float64(acc) >= keep*float64(total) {
			break
		}
		kept = append(kept, k)
		acc += mass[k]
	}
	sort.Slice(kept, func(a, b int) bool {
		return kept[a].p.dir<<16|kept[a].p.size < kept[b].p.dir<<16|kept[b].p.size
	})
	binary.Write(buf, le, uint16(len(kept)))
	for _, k := range kept {
		if k.has {
			buf.WriteByte(byte(k.p.dir))
		} else {
			buf.WriteByte(0xff)
		}
		binary.Write(buf, le, uint16(k.p.size))
		writeOutcomes(buf, prune(rows[k], keep))
	}

	// Fallbacks by the previous packet's direction alone.
	for dir := uint32(0); dir < 2; dir++ {
		var agg []outcome
		idx := map[[2]uint32]int{}
		for k, outs := range rows {
			if !k.has || k.p.dir != dir {
				continue
			}
			for _, o := range outs {
				j, ok := idx[[2]uint32{o.dir, o.size}]
				if !ok {
					j = len(agg)
					idx[[2]uint32{o.dir, o.size}] = j
					agg = append(agg, outcome{o.dir, o.size, 0})
				}
				agg[j].count += o.count
			}
		}
		if len(agg) == 0 {
			writeOutcomes(buf, nil)
			continue
		}
		writeOutcomes(buf, prune(agg, keep))
	}
	log.Printf("position %d: %d flows, %d of %d previous packets kept", i, total, len(kept), len(keys))
}
