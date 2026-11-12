package main

import (
	"encoding/hex"
	"math"
	"testing"
)

// postcard writes CenKL's postcard encoding of a TrafficProfile.
type postcard []byte

func (p postcard) varint(v uint64) postcard {
	for v >= 0x80 {
		p = append(p, byte(v)|0x80)
		v >>= 7
	}
	return append(p, byte(v))
}

// packet is a PacketProjection with a masked timestamp.
func (p postcard) packet(dir, size uint64) postcard {
	return p.varint(0).varint(1).varint(dir).varint(1).varint(size)
}

type tinyEntry struct {
	seq   [][2]uint64
	count uint64
}

func (p postcard) histogram(entries []tinyEntry, seqLen uint64) postcard {
	p = p.varint(uint64(len(entries)))
	var total uint64
	for _, e := range entries {
		p = p.varint(uint64(len(e.seq)))
		for _, pk := range e.seq {
			p = p.packet(pk[0], pk[1])
		}
		p = p.varint(e.count)
		total += e.count
	}
	p = p.varint(total)
	p = append(p, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f) // alpha 1.0
	return p.varint(1000).varint(seqLen)
}

// tinyProfile: position 0 is a client packet of 100 bytes (3 flows) or a
// server packet of 200 (1). At position 1, after a client packet in bin 0
// comes a server packet in bin 1 (10 flows), and after a server packet in
// bin 1 a client packet in bin 0 (2 flows).
func tinyProfile() []byte {
	var p postcard
	p = p.varint(2)
	p = p.histogram([]tinyEntry{
		{[][2]uint64{{1, 100}}, 3},
		{[][2]uint64{{0, 200}}, 1},
	}, 1)
	p = p.histogram([]tinyEntry{
		{[][2]uint64{{1, 0}, {0, 1}}, 10},
		{[][2]uint64{{0, 1}, {1, 0}}, 2},
	}, 2)
	return p.varint(1)
}

// tinyModel: position 1 bins sizes below 150 to bin 0 (only ever 100) and
// the rest to bin 1 (only ever 777).
func tinyModel() []byte {
	lookup := make([]byte, 0, 2000)
	lookup = append(lookup, '[')
	for i := 1; i <= 300; i++ {
		if i > 1 {
			lookup = append(lookup, ',')
		}
		if i < 150 {
			lookup = append(lookup, '0')
		} else {
			lookup = append(lookup, '1')
		}
	}
	lookup = append(lookup, ']')
	dir := `{"feature":{"feature":"Direction","effective_min":0.0,"effective_max":2.0},"quantization":"Identity"}`
	ts := `{"feature":{"feature":"Timestamp","effective_min":0.0,"effective_max":1.0},"quantization":"Mask"}`
	return []byte(`{"markov_order":1,"quantizer":{"PerPacket":[` +
		`{"timestamp":` + ts + `,"direction":` + dir + `,"size":{"feature":{"feature":"Size","effective_min":1.0,"effective_max":1461.0},"quantization":"Identity"}},` +
		`{"timestamp":` + ts + `,"direction":` + dir + `,"size":{"feature":{"feature":"Size","effective_min":1.0,"effective_max":1461.0},"quantization":{"Empirical":{"lookup":` + string(lookup) +
		`,"bins":[{"values":[100,120],"counts":[1,0]},{"values":[777],"counts":[5]}]}}}}` +
		`]}}`)
}

// goldenHex is build's output for tinyProfile and tinyModel with keep 1.
// samizdat's TestShapingModelGolden parses the same bytes, which keeps the
// writer and the runtime's reader in agreement.
const goldenHex = "535a534d0102000100ff00000200c80055556480ffff00000000012c01000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000200020064000100000078" +
	"00000000000100090305000000020000010001000080ffff01000001000100ff" +
	"ff01000080ffff01000100ffff"

func TestBuildTinyProfile(t *testing.T) {
	raw, err := build(tinyProfile(), tinyModel(), 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got != goldenHex {
		t.Fatalf("build output changed:\n got %s\nwant %s", got, goldenHex)
	}
}

func TestDecodeProfileRejectsTrailingBytes(t *testing.T) {
	if _, err := decodeProfile(append(tinyProfile(), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

func TestPruneKeepsTopMass(t *testing.T) {
	outs := []outcome{{1, 10, 90}, {0, 20, 9}, {1, 30, 1}}
	kept := prune(outs, 0.95)
	if len(kept) != 2 {
		t.Fatalf("kept %d outcomes, want the 2 covering 95%%", len(kept))
	}
	for _, o := range kept {
		if o.size == 30 {
			t.Fatal("kept the least likely outcome")
		}
	}
	if kept[0].size != 20 || kept[0].count != 6554 || kept[1].count != 65535 {
		t.Fatalf("weights %+v, want sorted by outcome and scaled to the most likely", kept)
	}
}

func TestBuildRejectsBadKeep(t *testing.T) {
	for _, keep := range []float64{0, -1, 1.5, math.NaN()} {
		if _, err := build(tinyProfile(), tinyModel(), 10, keep); err == nil {
			t.Errorf("keep %v accepted", keep)
		}
	}
}

func TestBuildRejectsBadPositionsAndSequences(t *testing.T) {
	if _, err := build(tinyProfile(), tinyModel(), 0, 1); err == nil {
		t.Fatal("0 positions accepted")
	}
	var p postcard
	p = p.varint(1)
	p = p.histogram([]tinyEntry{{[][2]uint64{{1, 100}, {0, 200}}, 1}}, 2)
	p = p.varint(1)
	if _, err := build(p, tinyModel(), 10, 1); err == nil {
		t.Fatal("a two-packet sequence at position 0 accepted")
	}
}
