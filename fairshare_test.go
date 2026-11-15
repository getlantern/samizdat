package samizdat

import (
	"bytes"
	"sync"
	"testing"

	"golang.org/x/net/http2"
)

// TestLeanStreamShareCapped: a stream can queue no more than its share of
// the write buffer, so another stream always finds room.
func TestLeanStreamShareCapped(t *testing.T) {
	c := &leanConn{}
	c.wcond = sync.NewCond(&c.mu)
	st := &leanStream{c: c, id: 1}
	for st.roomLocked() > 0 {
		st.queueDataLocked(0, make([]byte, min(st.roomLocked(), 16<<10)))
	}
	if len(st.out) > leanMaxStreamQueue {
		t.Fatalf("one stream queued %d bytes, over its share of %d", len(st.out), leanMaxStreamQueue)
	}
	other := &leanStream{c: c, id: 3}
	if other.roomLocked() <= 0 {
		t.Fatal("a stream at its share left another no room")
	}
}

func newTestLeanConn() *leanConn {
	c := &leanConn{streams: map[uint32]*leanStream{}}
	c.wcond = sync.NewCond(&c.mu)
	return c
}

// TestLeanErrorResetDropsQueuedData: a stream reset with an error sends
// nothing more, and the connection gets back the send credit its unsent
// data took.
func TestLeanErrorResetDropsQueuedData(t *testing.T) {
	c := newTestLeanConn()
	c.connSendWin = 1000
	st := &leanStream{c: c, id: 1, cancel: func() {}, cond: sync.NewCond(&c.mu), roomCond: sync.NewCond(&c.mu)}
	c.streams[1] = st
	st.queueDataLocked(0, make([]byte, 300))
	c.connSendWin -= 300
	c.resetStreamLocked(st, http2.ErrCodeCancel)
	if len(st.out) != 0 || c.dataQueued != 0 {
		t.Fatalf("queued data survived the reset: out=%d queued=%d", len(st.out), c.dataQueued)
	}
	if c.connSendWin != 1000 {
		t.Fatalf("connection credit %d after the reset, want 1000 back", c.connSendWin)
	}
	f, err := http2.NewFramer(nil, bytes.NewReader(c.wbuf)).ReadFrame()
	if rst, ok := f.(*http2.RSTStreamFrame); err != nil || !ok || rst.StreamID != 1 {
		t.Fatalf("wbuf holds %v, %v; want the RST_STREAM", f, err)
	}
}

// TestLeanGracefulResetFollowsData: the RST_STREAM(NO_ERROR) after a
// response follows the response's queued data rather than overtaking it.
func TestLeanGracefulResetFollowsData(t *testing.T) {
	c := newTestLeanConn()
	st := &leanStream{c: c, id: 1, cancel: func() {}, cond: sync.NewCond(&c.mu), roomCond: sync.NewCond(&c.mu)}
	c.streams[1] = st
	st.queueDataLocked(http2.FlagDataEndStream, []byte("bye"))
	st.resetIfOpenLocked()
	if len(c.wbuf) != 0 {
		t.Fatal("the RST_STREAM went ahead of the response's data")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(st.out))
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameData {
		t.Fatalf("first frame %v, want the DATA", f)
	}
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameRSTStream {
		t.Fatalf("second frame %v, want the RST_STREAM", f)
	}
}

// TestLeanSettingsAckFollowsData: data queued under the client's old
// settings goes out ahead of the acknowledgement of its new ones.
func TestLeanSettingsAckFollowsData(t *testing.T) {
	c := newTestLeanConn()
	st := &leanStream{c: c, id: 1, cond: sync.NewCond(&c.mu), roomCond: sync.NewCond(&c.mu)}
	c.peerInitWin = 65535
	c.peerMaxFrame = 16384
	st.queueDataLocked(0, []byte("old"))
	f, err := http2.NewFramer(nil, bytes.NewReader(appendSettings(nil, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 32768}}))).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handleSettings(f.(*http2.SettingsFrame)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(nil, bytes.NewReader(c.wbuf))
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameData {
		t.Fatalf("first frame %v, want the DATA", f)
	}
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameSettings {
		t.Fatalf("second frame %v, want the SETTINGS ack", f)
	}
	if c.dataQueued != 0 || len(c.sched) != 0 {
		t.Fatal("data stayed queued after the flush")
	}
}
