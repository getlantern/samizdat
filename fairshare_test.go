package samizdat

import (
	"bytes"
	"sync"
	"testing"
	"time"

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
	if st.outLen() > leanMaxStreamQueue {
		t.Fatalf("one stream queued %d bytes, over its share of %d", st.outLen(), leanMaxStreamQueue)
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
	if st.outLen() != 0 || c.dataQueued != 0 {
		t.Fatalf("queued data survived the reset: out=%d queued=%d", st.outLen(), c.dataQueued)
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
	fr := http2.NewFramer(nil, bytes.NewReader(st.out[st.outOff:]))
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameData {
		t.Fatalf("first frame %v, want the DATA", f)
	}
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameRSTStream {
		t.Fatalf("second frame %v, want the RST_STREAM", f)
	}
}

// TestLeanSettingsAckFollowsData: data queued under a larger maximum frame
// size goes out ahead of the acknowledgement of a smaller one.
func TestLeanSettingsAckFollowsData(t *testing.T) {
	c := newTestLeanConn()
	st := &leanStream{c: c, id: 1, cond: sync.NewCond(&c.mu), roomCond: sync.NewCond(&c.mu)}
	c.peerInitWin = 65535
	c.peerMaxFrame = 32768
	st.queueDataLocked(0, []byte("old"))
	// A smaller maximum frame size: frames queued under the old one may be
	// too large for the new.
	f, err := http2.NewFramer(nil, bytes.NewReader(appendSettings(nil, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 16384}}))).ReadFrame()
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

func newTestLeanStream(c *leanConn, id uint32) *leanStream {
	st := &leanStream{c: c, id: id, cancel: func() {}, cond: sync.NewCond(&c.mu), roomCond: sync.NewCond(&c.mu), sendWin: 1 << 30}
	c.streams[id] = st
	return st
}

// TestLeanClientResetFreesRoom: a stream waiting for room in the write
// buffer is woken when the client resets the streams holding it, though the
// writer, with nothing left to send, takes nothing.
func TestLeanClientResetFreesRoom(t *testing.T) {
	c := newTestLeanConn()
	c.connSendWin = 1 << 30
	var bulk []*leanStream
	for i := range leanMaxWriteBuffer / leanMaxStreamQueue {
		st := newTestLeanStream(c, uint32(2*i+1))
		for st.roomLocked() > 0 {
			st.queueDataLocked(0, make([]byte, min(st.roomLocked(), 16<<10)))
		}
		bulk = append(bulk, st)
	}
	waiter := newTestLeanStream(c, 99)
	if waiter.roomLocked() > 0 {
		t.Fatal("the full buffer left room for another stream")
	}
	done := make(chan error, 1)
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		done <- waiter.waitForRoom(16 << 10)
	}()
	for {
		c.mu.Lock()
		waiting := waiter.waitingRoom
		c.mu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	for _, st := range bulk {
		st.markResetLocked()
		c.dropOutLocked(st)
	}
	c.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a stream waiting for room stayed waiting after the client reset the streams holding it")
	}
}

// TestLeanStreamClosedFollowsQueuedFrames: a RST_STREAM(STREAM_CLOSED) for
// a finished stream still sending follows the frames it queued.
func TestLeanStreamClosedFollowsQueuedFrames(t *testing.T) {
	c := newTestLeanConn()
	st := newTestLeanStream(c, 1)
	st.queueDataLocked(http2.FlagDataEndStream, []byte("bye"))
	st.removed = true
	delete(c.streams, 1)
	c.closedOut = map[uint32]*leanStream{1: st}
	c.rstLocked(1, http2.ErrCodeStreamClosed)
	if len(c.wbuf) != 0 {
		t.Fatal("the RST_STREAM went ahead of the finished stream's data")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(st.out[st.outOff:]))
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameData {
		t.Fatalf("first frame %v, want the DATA", f)
	}
	if f, _ := fr.ReadFrame(); f == nil || f.Header().Type != http2.FrameRSTStream {
		t.Fatalf("second frame %v, want the RST_STREAM", f)
	}
}

// TestLeanFullBufferNewStreamTakesTurn: with every share of the buffer
// taken by downloads, a new stream's data still goes out within a turn of
// the writer, rather than after the downloads drain.
func TestLeanFullBufferNewStreamTakesTurn(t *testing.T) {
	c := newTestLeanConn()
	c.connSendWin = 1 << 30
	for i := range leanMaxWriteBuffer / leanMaxStreamQueue {
		st := newTestLeanStream(c, uint32(2*i+1))
		for st.roomLocked() > 0 {
			st.queueDataLocked(0, make([]byte, min(st.roomLocked(), 16<<10)))
		}
	}
	// The writer takes a round, which frees room; the new stream queues
	// into it, then the bulk streams refill theirs.
	c.takeDataLocked()
	small := newTestLeanStream(c, 99)
	if small.roomLocked() <= 0 {
		t.Fatal("no room for a new stream after the writer took a round")
	}
	small.queueDataLocked(0, []byte("hello"))
	sent := 0
	for range 2 * len(c.sched) {
		b := c.takeDataLocked()
		for fr := http2.NewFramer(nil, bytes.NewReader(b)); ; {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			if f.Header().StreamID == 99 {
				if sent > 2*leanWriteChunk {
					t.Fatalf("the new stream's data went out after %d bytes of the others'", sent)
				}
				return
			}
			sent += int(f.Header().Length)
		}
	}
	t.Fatal("the new stream's data never went out")
}

// TestLeanSettingsKeepTurns: settings that leave queued frames valid don't
// move the streams' data ahead of the frames that jump the line.
func TestLeanSettingsKeepTurns(t *testing.T) {
	c := newTestLeanConn()
	st := newTestLeanStream(c, 1)
	c.peerInitWin = 65535
	c.peerMaxFrame = 16384
	st.queueDataLocked(0, []byte("data"))
	f, err := http2.NewFramer(nil, bytes.NewReader(appendSettings(nil, []http2.Setting{{ID: http2.SettingMaxFrameSize, Val: 32768}}))).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handleSettings(f.(*http2.SettingsFrame)); err != nil {
		t.Fatal(err)
	}
	if c.dataQueued == 0 {
		t.Fatal("a larger maximum frame size flushed the streams' data into the ordered frames")
	}
}

// TestLeanLargeWriteWoken: a Write waiting to queue more than a stream can
// ever hold, as one may when the client allows large frames, is woken once
// the stream has room, while other streams keep data queued.
func TestLeanLargeWriteWoken(t *testing.T) {
	c := newTestLeanConn()
	a, b, w := newTestLeanStream(c, 1), newTestLeanStream(c, 3), newTestLeanStream(c, 5)
	for _, st := range []*leanStream{a, b} {
		for st.roomLocked() > 0 {
			st.queueDataLocked(0, make([]byte, min(st.roomLocked(), 16<<10)))
		}
	}
	if w.roomLocked() > 0 {
		t.Fatalf("a full buffer left room %d", w.roomLocked())
	}
	w.wantRoom = 1<<20 + leanFrameHeaderLen
	w.waitingRoom = true
	c.roomWaiters = append(c.roomWaiters, w)
	for range 200 {
		for c.dataQueued < 128<<10 {
			a.queueDataLocked(0, make([]byte, 16<<10))
		}
		c.takeDataLocked()
		c.wakeRoomLocked(false)
		if !w.waitingRoom {
			return
		}
	}
	t.Fatalf("never woken, with room %d", w.roomLocked())
}

// TestLeanDownloadClassResets: a stream whose queue sits empty for a while
// is no longer treated as a download, so a small write after one isn't held
// back for a download's worth of room; one refilling at once still is.
func TestLeanDownloadClassResets(t *testing.T) {
	c := newTestLeanConn()
	st := newTestLeanStream(c, 1)
	for st.queuedTotal < leanBulk {
		st.queueDataLocked(0, make([]byte, 16<<10))
		for st.outLen() > leanMaxStreamQueue/2 {
			c.takeDataLocked()
		}
	}
	for st.outLen() > 0 {
		c.takeDataLocked()
	}
	// A download refilling at once keeps its class.
	st.queueDataLocked(0, []byte("more"))
	if st.queuedTotal < leanBulk {
		t.Fatal("a download refilling at once lost its class")
	}
	for st.outLen() > 0 {
		c.takeDataLocked()
	}
	// One idle past leanBulkIdle loses it.
	st.drainedAt = time.Now().Add(-2 * leanBulkIdle)
	st.queueDataLocked(0, []byte("hi"))
	if st.queuedTotal >= leanBulk {
		t.Fatalf("queuedTotal %d after the stream sat idle, want it reset", st.queuedTotal)
	}
}

// TestLeanSmallWritersAllWoken: every stream waiting to write a little is
// woken once it fits, not one per write the writer makes, so a new tunnel's
// response isn't left behind a line of trickling streams.
func TestLeanSmallWritersAllWoken(t *testing.T) {
	c := newTestLeanConn()
	bulk := newTestLeanStream(c, 1)
	other := newTestLeanStream(c, 3)
	for _, st := range []*leanStream{bulk, other} {
		for st.roomLocked() > 0 {
			st.queueDataLocked(0, make([]byte, min(st.roomLocked(), 16<<10)))
		}
	}
	var small []*leanStream
	for i := range 20 {
		st := newTestLeanStream(c, uint32(5+2*i))
		st.wantRoom = 100 + leanFrameHeaderLen
		st.waitingRoom = true
		c.roomWaiters = append(c.roomWaiters, st)
		small = append(small, st)
	}
	c.takeDataLocked()
	c.wakeRoomLocked(false)
	for _, st := range small {
		if st.waitingRoom {
			t.Fatalf("stream %d, wanting %d with room %d, is still waiting", st.id, st.wantRoom, st.roomLocked())
		}
	}
}
