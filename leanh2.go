package samizdat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The lean HTTP/2 server serves samizdat's CONNECT tunnels with the frames
// x/net's http2.Server sends, at a fraction of its CPU. x/net's server passes
// every write between three goroutines (the handler, its serve loop and a
// writeFrameAsync goroutine it starts per frame) and flushes each frame as its
// own TLS record and write syscall. Here a handler's Write appends frames to
// the connection's write buffer under a mutex, and one writer goroutine sends
// everything queued since its last write through TLS in a single socket
// write. The connection's goroutine reads frames and hands DATA straight to
// the stream.
//
// It implements the part of HTTP/2 samizdat's client, x/net's Transport,
// uses: CONNECT streams, flow control, SETTINGS, PING, RST_STREAM and GOAWAY.
// It never pushes and ignores priorities.

// The settings and windows x/net's http2.Server advertises by default. The
// lean server copies them, so its SETTINGS frame is the same.
const (
	leanMaxReadFrameSize  = 1 << 20
	leanMaxHeaderListSize = http.DefaultMaxHeaderBytes + 32*10
	leanStreamRecvWindow  = 1 << 20
	leanConnRecvWindow    = 1 << 20

	leanInitialPeerWindow = 65535 // until the client's SETTINGS says otherwise
	leanDefaultMaxFrame   = 16384 // the client sends no SETTINGS_MAX_FRAME_SIZE
	leanMaxWriteBuffer    = 512 << 10
	leanReadBuffer        = 32 << 10
	leanFrameHeaderLen    = 9
	// An idle connection keeps write buffers up to this size and drops larger
	// ones, so thousands of idle connections don't each hold a burst's worth
	// while a busy one reuses its buffers write after write.
	leanIdleBufKeep = 64 << 10
	// leanIdleTrimDelay is how long the writer must have been idle before
	// its buffers are trimmed; trimming at every pause would make a busy
	// connection reallocate after each burst.
	leanIdleTrimDelay = time.Second
	// leanMaxQueuedControl caps the control frames (PING and SETTINGS
	// acknowledgements, RST_STREAM) the read loop may queue while the writer
	// hasn't sent them, as x/net's maxQueuedControlFrames does. A peer that
	// keeps sending frames that need an answer without reading ours would
	// otherwise grow the write buffer without bound.
	leanMaxQueuedControl = 10000
	// leanMaxHandlersFactor caps the streams whose handlers are still running,
	// counting ones already reset, at this many times MaxConcurrentStreams,
	// as x/net's server caps its handlers at 4x. Reset streams stop counting
	// against MaxConcurrentStreams, so without this cap a client could open
	// and reset streams in a loop ("rapid reset") and leave a handler running
	// for each.
	leanMaxHandlersFactor = 4
	// leanMaxBatch caps the records batchConn collects while a batch is being
	// sent. TLS can write records of its own then, such as KeyUpdate
	// replies, which no other limit bounds; past it the connection fails.
	leanMaxBatch = 4 * leanMaxWriteBuffer

	// leanCloseFlush bounds how long closing waits for the writer to send
	// what's queued, such as a GOAWAY, before closing the connection.
	leanCloseFlush   = time.Second
	leanDrainTimeout = 5 * time.Second
	// A WINDOW_UPDATE goes out once a quarter of a window has been consumed.
	leanWindowUpdateDivisor = 4
)

// leanPrefaceTimeout bounds how long a client may take to send its preface
// and first SETTINGS, as x/net's server does. A variable for tests.
var leanPrefaceTimeout = 10 * time.Second

var (
	errLeanBatchFull   = errors.New("samizdat: too many TLS records pending")
	errLeanConnClosed  = errors.New("samizdat: connection closed")
	errLeanStreamReset = errors.New("samizdat: stream reset by peer")
	errLeanProtocol    = errors.New("samizdat: HTTP/2 protocol error")
	errLeanFlow        = errors.New("samizdat: HTTP/2 flow control error")
	// errLeanCalm ends a connection whose peer exceeded a cap (queued
	// control frames, running handlers) with ENHANCE_YOUR_CALM, as x/net does.
	errLeanCalm = errors.New("samizdat: peer exceeded a limit")
)

// serveLeanH2 serves HTTP/2 CONNECT tunnels on tlsConn until the peer goes
// away or the connection fails. bc is the batching layer beneath tlsConn.
func (s *Server) serveLeanH2(tlsConn net.Conn, bc *batchConn, rawConn net.Conn, shortID [8]byte) {
	base := context.WithValue(
		context.WithValue(context.Background(), sessionConnKey{}, rawConn),
		shortIDKey{}, shortID,
	)
	ctx, cancel := context.WithCancel(base)
	c := &leanConn{
		s:             s,
		conn:          tlsConn,
		bc:            bc,
		ctx:           ctx,
		cancel:        cancel,
		localAddr:     tlsConn.LocalAddr(),
		remoteAddr:    tlsConn.RemoteAddr(),
		streams:       make(map[uint32]*leanStream),
		maxStreams:    s.config.MaxConcurrentStreams,
		connSendWin:   leanInitialPeerWindow,
		peerInitWin:   leanInitialPeerWindow,
		peerMaxFrame:  leanDefaultMaxFrame,
		connRecvAvail: leanConnRecvWindow,
		hpackBuf:      new(bytes.Buffer),
		writerDone:    make(chan struct{}),
	}
	c.wcond = sync.NewCond(&c.mu)
	c.hpackEnc = hpack.NewEncoder(c.hpackBuf)
	c.serve()
}

type leanConn struct {
	s          *Server
	conn       net.Conn
	bc         *batchConn
	ctx        context.Context
	cancel     context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr

	// mu guards everything below and every leanStream's fields. wcond wakes
	// the writer when frames are queued. A stream waits on its own cond for
	// data, flow control and room in the write buffer.
	mu    sync.Mutex
	wcond *sync.Cond

	wbuf   []byte // frames queued for the writer
	spare  []byte // the writer's previous buffer, for reuse
	closed bool
	// roomWaiters are the streams waiting for room in the write buffer,
	// woken when the writer takes it.
	roomWaiters []*leanStream
	// writerIdle is set while the writer waits for frames; trimTimer trims
	// the buffers once it has stayed idle for leanIdleTrimDelay.
	writerIdle bool
	trimTimer  *time.Timer
	// queuedControl counts the control frames the read loop queued since the
	// writer last took the buffer; see leanMaxQueuedControl.
	queuedControl int

	streams map[uint32]*leanStream
	// peekedStreamID is the highest stream ID of a HEADERS frame read so
	// far, including one that failed to decode; see goAway.
	peekedStreamID uint32
	// active counts the streams in streams that neither side has reset,
	// which are the ones MaxConcurrentStreams limits.
	active       int
	maxStreams   int
	lastStreamID uint32
	goingAway    bool

	connSendWin  int64 // what the client still lets us send on the connection
	peerInitWin  int64 // the client's SETTINGS_INITIAL_WINDOW_SIZE
	peerMaxFrame int

	// connRecvAvail is what the client may still send on the connection, and
	// connRecvUnacked what has been consumed but not yet returned to it.
	connRecvAvail   int64
	connRecvUnacked int64

	hpackEnc *hpack.Encoder
	hpackBuf *bytes.Buffer

	writerDone chan struct{} // closed when writeLoop returns
}

func (c *leanConn) serve() {
	defer c.close()
	go c.writeLoop()

	// x/net's server queues its SETTINGS and connection WINDOW_UPDATE before
	// it reads the client preface, and so does this. (x/net's writer can send
	// its SETTINGS ACK between the two; either order is valid HTTP/2.)
	c.mu.Lock()
	c.wbuf = appendSettings(c.wbuf, []http2.Setting{
		{ID: http2.SettingMaxFrameSize, Val: leanMaxReadFrameSize},
		{ID: http2.SettingMaxConcurrentStreams, Val: uint32(c.maxStreams)},
		{ID: http2.SettingMaxHeaderListSize, Val: leanMaxHeaderListSize},
		{ID: http2.SettingHeaderTableSize, Val: 4096},
		{ID: http2.SettingInitialWindowSize, Val: leanStreamRecvWindow},
	})
	c.wbuf = appendWindowUpdate(c.wbuf, 0, leanConnRecvWindow-leanInitialPeerWindow)
	c.queued()
	c.mu.Unlock()

	// Frames are read through a buffer: without one, each frame costs two
	// TLS reads, one for its header and one for its payload.
	br := bufio.NewReaderSize(c.conn, leanReadBuffer)
	// The deadline is cleared once the client's first SETTINGS arrives.
	c.conn.SetReadDeadline(time.Now().Add(leanPrefaceTimeout))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}

	fr := http2.NewFramer(nil, br)
	fr.SetReuseFrames()
	fr.SetMaxReadFrameSize(leanMaxReadFrameSize)
	fr.MaxHeaderListSize = leanMaxHeaderListSize
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if f, err := fr.ReadFrame(); err != nil {
		return
	} else if sf, ok := f.(*http2.SettingsFrame); !ok || sf.IsAck() {
		return // the preface must be followed by SETTINGS
	} else if c.handleSettings(sf) != nil {
		return
	}
	c.conn.SetReadDeadline(time.Time{})
	for {
		// The next frame's header, peeked so that a HEADERS frame the framer
		// fails to decode still counts toward the GOAWAY's last stream ID,
		// as x/net's server counts it.
		if h, err := br.Peek(9); err == nil && http2.FrameType(h[3]) == http2.FrameHeaders {
			id := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
			c.mu.Lock()
			c.peekedStreamID = max(c.peekedStreamID, id)
			c.mu.Unlock()
		}
		f, err := fr.ReadFrame()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				if err := c.resetStream(se.StreamID, se.Code); err != nil {
					c.goAway(err)
					return
				}
				continue
			}
			c.goAway(err)
			return
		}
		if err := c.handleFrame(f); err != nil {
			c.goAway(err)
			return
		}
	}
}

// queued wakes the writer. c.mu must be held.
func (c *leanConn) queued() { c.wcond.Signal() }

// queuedControlFrame notes a control frame queued in answer to the peer and wakes
// the writer. It fails once the peer has made us queue too many it isn't
// reading, which ends the connection. c.mu must be held.
func (c *leanConn) queuedControlFrame() error {
	c.queuedControl++
	c.queued()
	if c.queuedControl > leanMaxQueuedControl {
		return errLeanCalm
	}
	return nil
}

func (c *leanConn) handleFrame(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.WindowUpdateFrame:
		c.handleWindowUpdate(f)
	case *http2.SettingsFrame:
		return c.handleSettings(f)
	case *http2.PingFrame:
		if !f.IsAck() {
			c.mu.Lock()
			c.wbuf = appendFrameHeader(c.wbuf, 8, http2.FramePing, http2.FlagPingAck, 0)
			c.wbuf = append(c.wbuf, f.Data[:]...)
			err := c.queuedControlFrame()
			c.mu.Unlock()
			return err
		}
	case *http2.RSTStreamFrame:
		c.mu.Lock()
		if st := c.streams[f.StreamID]; st != nil && !st.reset {
			st.markResetLocked()
			st.wakeLocked()
			st.cancel()
		}
		c.mu.Unlock()
	case *http2.GoAwayFrame:
		c.mu.Lock()
		c.goingAway = true
		c.mu.Unlock()
	case *http2.PushPromiseFrame:
		return errLeanProtocol
	}
	// PRIORITY and unknown frame types are ignored, as the spec requires.
	return nil
}

func (c *leanConn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A frame can repeat INITIAL_WINDOW_SIZE many times; the streams are
	// adjusted once, for its last value.
	oldInitWin := c.peerInitWin
	err := f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			if s.Val > 1<<31-1 {
				return errLeanProtocol
			}
			c.peerInitWin = int64(s.Val)
		case http2.SettingMaxFrameSize:
			if s.Val < 16384 || s.Val > 1<<24-1 {
				return errLeanProtocol
			}
			c.peerMaxFrame = int(s.Val)
		case http2.SettingHeaderTableSize:
			// The client's HPACK decoder keeps at most this much; our
			// response encoder must not refer past it.
			c.hpackEnc.SetMaxDynamicTableSize(s.Val)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if delta := c.peerInitWin - oldInitWin; delta != 0 {
		for _, st := range c.streams {
			st.sendWin += delta
			st.cond.Broadcast()
		}
	}
	c.wbuf = appendFrameHeader(c.wbuf, 0, http2.FrameSettings, http2.FlagSettingsAck, 0)
	return c.queuedControlFrame()
}

func (c *leanConn) handleWindowUpdate(f *http2.WindowUpdateFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.StreamID == 0 {
		c.connSendWin += int64(f.Increment)
		for _, st := range c.streams {
			st.cond.Broadcast()
		}
	} else if st := c.streams[f.StreamID]; st != nil {
		st.sendWin += int64(f.Increment)
		st.cond.Broadcast()
	}
}

func (c *leanConn) handleHeaders(f *http2.MetaHeadersFrame) error {
	id := f.StreamID
	c.mu.Lock()
	if id%2 == 1 && id <= c.lastStreamID {
		// HEADERS on a stream already opened: trailers, which must end the
		// stream, as x/net's server accepts them, or HEADERS on a stream
		// that's gone.
		defer c.mu.Unlock()
		st := c.streams[id]
		switch {
		case st == nil || st.remoteDone || st.reset:
			c.wbuf = appendRSTStream(c.wbuf, id, http2.ErrCodeStreamClosed)
			return c.queuedControlFrame()
		case !f.StreamEnded():
			c.resetStreamLocked(st, http2.ErrCodeProtocol)
			return c.queuedControlFrame()
		}
		st.remoteDone = true
		st.cond.Broadcast()
		return nil
	}
	if id%2 == 0 {
		c.mu.Unlock()
		return errLeanProtocol
	}
	c.lastStreamID = id
	if len(c.streams) >= leanMaxHandlersFactor*c.maxStreams {
		// Too many handlers still running for streams the client reset.
		c.mu.Unlock()
		return errLeanCalm
	}
	if c.goingAway || c.active >= c.maxStreams {
		c.wbuf = appendRSTStream(c.wbuf, id, http2.ErrCodeRefusedStream)
		err := c.queuedControlFrame()
		c.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(c.ctx)
	st := &leanStream{
		c:          c,
		id:         id,
		cond:       sync.NewCond(&c.mu),
		roomCond:   sync.NewCond(&c.mu),
		ctx:        ctx,
		cancel:     cancel,
		sendWin:    c.peerInitWin,
		recvAvail:  leanStreamRecvWindow,
		remoteDone: f.StreamEnded(),
	}
	c.streams[id] = st
	c.active++
	c.mu.Unlock()

	go st.run(f.PseudoValue("method"), f.PseudoValue("authority"), f.PseudoValue("scheme"), f.PseudoValue("path"), f.Truncated)
	return nil
}

// wakeLocked wakes everything waiting on st: reads, flow-control waits and
// room waits. c.mu must be held.
func (st *leanStream) wakeLocked() {
	st.cond.Broadcast()
	st.roomCond.Broadcast()
}

// markResetLocked records that st has been reset by either side, which
// frees its MaxConcurrentStreams slot. c.mu must be held.
func (st *leanStream) markResetLocked() {
	if !st.reset {
		st.reset = true
		if !st.removed {
			st.c.active--
		}
		// Nothing will read what's buffered; return it to the shared
		// connection window now rather than when the handler returns.
		st.dropUnreadLocked()
	}
}

func (c *leanConn) handleData(f *http2.DataFrame) error {
	// The whole frame, padding included, counts against flow control.
	n := int64(f.Length)
	data := f.Data()
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > c.connRecvAvail {
		return errLeanFlow
	}
	c.connRecvAvail -= n
	st := c.streams[f.StreamID]
	if st == nil || st.remoteDone || st.reset {
		// The client spent connection window on a stream that's gone; give
		// it back.
		c.creditConn(n)
		if st == nil && f.StreamID <= c.lastStreamID {
			c.wbuf = appendRSTStream(c.wbuf, f.StreamID, http2.ErrCodeStreamClosed)
			return c.queuedControlFrame()
		}
		return nil
	}
	if n > st.recvAvail {
		c.creditConn(n)
		c.resetStreamLocked(st, http2.ErrCodeFlowControl)
		return nil
	}
	st.recvAvail -= n
	// Padding is never read, and data the handler no longer reads is
	// dropped; both are returned at once so the client can finish sending.
	unread := n - int64(len(data))
	if st.closed || st.draining {
		unread = n
	} else {
		st.rbuf = append(st.rbuf, data...)
	}
	if unread > 0 {
		c.creditConn(unread)
		st.creditStream(unread)
	}
	if f.StreamEnded() {
		st.remoteDone = true
	}
	st.cond.Broadcast()
	return nil
}

// creditConn returns n consumed bytes to the client's connection window,
// batching WINDOW_UPDATEs. c.mu must be held.
func (c *leanConn) creditConn(n int64) {
	c.connRecvUnacked += n
	if c.connRecvUnacked >= leanConnRecvWindow/leanWindowUpdateDivisor {
		c.wbuf = appendWindowUpdate(c.wbuf, 0, uint32(c.connRecvUnacked))
		c.connRecvAvail += c.connRecvUnacked
		c.connRecvUnacked = 0
		c.queued()
	}
}

// resetStream ends stream id with RST_STREAM. The read loop calls it for a
// peer's stream errors, so it counts as an answer to the peer.
func (c *leanConn) resetStream(id uint32, code http2.ErrCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.streams[id]; st != nil {
		c.resetStreamLocked(st, code)
	} else {
		c.wbuf = appendRSTStream(c.wbuf, id, code)
	}
	return c.queuedControlFrame()
}

// resetStreamLocked ends st with RST_STREAM. c.mu must be held.
func (c *leanConn) resetStreamLocked(st *leanStream, code http2.ErrCode) {
	if st.reset {
		return
	}
	st.markResetLocked()
	c.wbuf = appendRSTStream(c.wbuf, st.id, code)
	c.queued()
	st.wakeLocked()
	st.cancel()
}

// writeLoop sends everything queued, all at once, until the connection
// closes.
func (c *leanConn) writeLoop() {
	for {
		c.mu.Lock()
		if len(c.wbuf) == 0 && !c.closed {
			c.writerIdle = true
			c.scheduleTrimLocked()
			for len(c.wbuf) == 0 && !c.closed {
				c.wcond.Wait()
			}
			c.writerIdle = false
		}
		if len(c.wbuf) == 0 {
			c.mu.Unlock()
			close(c.writerDone)
			return
		}
		buf := c.wbuf
		c.wbuf, c.spare = c.spare[:0], nil
		c.queuedControl = 0
		for _, st := range c.roomWaiters {
			st.waitingRoom = false
			st.roomCond.Broadcast()
		}
		clear(c.roomWaiters)
		c.roomWaiters = c.roomWaiters[:0]
		c.mu.Unlock()

		err := c.bc.batch(func() error {
			_, err := c.conn.Write(buf)
			return err
		})

		c.mu.Lock()
		if c.spare == nil {
			c.spare = buf[:0]
		}
		c.mu.Unlock()
		if err != nil {
			close(c.writerDone)
			c.close()
			return
		}
	}
}

// goAway queues a GOAWAY carrying the HTTP/2 error code for err, as x/net's
// server sends before closing a connection on an error. close sends it.
func (c *leanConn) goAway(err error) {
	code := http2.ErrCodeProtocol
	var ce http2.ConnectionError
	switch {
	case errors.As(err, &ce):
		code = http2.ErrCode(ce)
	case errors.Is(err, errLeanFlow):
		code = http2.ErrCodeFlowControl
	case errors.Is(err, errLeanCalm):
		code = http2.ErrCodeEnhanceYourCalm
	case !errors.Is(err, errLeanProtocol):
		return // the connection itself failed; there's no one to tell
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.wbuf = appendFrameHeader(c.wbuf, 8, http2.FrameGoAway, 0, 0)
	c.wbuf = binary.BigEndian.AppendUint32(c.wbuf, max(c.lastStreamID, c.peekedStreamID)&0x7fffffff)
	c.wbuf = binary.BigEndian.AppendUint32(c.wbuf, uint32(code))
	c.queued()
}

// close ends the connection: every stream's reads and writes fail and every
// handler's context ends. The writer first gets up to leanCloseFlush to send
// what's queued, such as a GOAWAY.
func (c *leanConn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	for _, st := range c.streams {
		st.wakeLocked()
	}
	c.wcond.Broadcast()
	if c.trimTimer != nil {
		c.trimTimer.Stop()
	}
	c.mu.Unlock()
	c.cancel()
	select {
	case <-c.writerDone:
	case <-time.After(leanCloseFlush):
	}
	c.conn.Close()
}

// scheduleTrimLocked arranges for the write buffers to be trimmed if the
// writer stays idle for leanIdleTrimDelay, when there's anything to trim.
// c.mu must be held.
func (c *leanConn) scheduleTrimLocked() {
	if cap(c.wbuf) <= leanIdleBufKeep && cap(c.spare) <= leanIdleBufKeep && !c.bc.overKeep(leanIdleBufKeep) {
		return
	}
	if c.trimTimer == nil {
		c.trimTimer = time.AfterFunc(leanIdleTrimDelay, c.trimIfIdle)
	} else {
		c.trimTimer.Reset(leanIdleTrimDelay)
	}
}

// trimIfIdle drops write buffers over leanIdleBufKeep if the writer is still
// idle, so an idle connection holds little memory.
func (c *leanConn) trimIfIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.writerIdle || len(c.wbuf) > 0 {
		return
	}
	if cap(c.wbuf) > leanIdleBufKeep {
		c.wbuf = nil
	}
	if cap(c.spare) > leanIdleBufKeep {
		c.spare = nil
	}
	c.bc.trim(leanIdleBufKeep)
}

// waitForRoom blocks st until the write buffer can take more frames, or st
// or the connection ends. c.mu must be held.
func (st *leanStream) waitForRoom() error {
	c := st.c
	for len(c.wbuf) >= leanMaxWriteBuffer && !c.closed && !st.reset {
		st.awaitRoomLocked()
	}
	if c.closed {
		return errLeanConnClosed
	}
	if st.reset {
		return errLeanStreamReset
	}
	return nil
}

// awaitRoomLocked waits until the writer takes the write buffer, or st is
// reset or closed. c.mu must be held.
func (st *leanStream) awaitRoomLocked() {
	if !st.waitingRoom {
		st.waitingRoom = true
		st.c.roomWaiters = append(st.c.roomWaiters, st)
	}
	st.roomCond.Wait()
}

// leanStream is one CONNECT tunnel. Its fields are guarded by c.mu.
type leanStream struct {
	c    *leanConn
	id   uint32
	cond *sync.Cond // signalled on data, END_STREAM, reset, close and window updates
	// roomCond is signalled when the writer takes the write buffer, and on
	// reset and close. A Write waiting for room waits on it rather than on
	// cond, so the client's window updates and data don't wake it for
	// nothing.
	roomCond *sync.Cond
	ctx      context.Context
	cancel   context.CancelFunc

	sendWin     int64
	recvAvail   int64 // what the client may still send on the stream
	recvUnacked int64
	rbuf        []byte
	remoteDone  bool // the client sent END_STREAM
	reset       bool
	// draining is set when the handler returns: what the client still sends
	// is dropped, as serveH2's drain does, but lingering writes go through
	// until closed is set.
	draining bool
	closed   bool // the handler closed the stream, or the drain ended
	removed  bool // finish took the stream out of c.streams
	// waitingRoom is set while st is in c.roomWaiters.
	waitingRoom bool
	// writing counts Writes in progress, so the drain doesn't end the
	// stream under one, as serverStreamConn.shutdown waits for them.
	writing int
	// wmu serializes whole Writes on the stream, as serverStreamConn's
	// mutex does: a Write releases c.mu while it waits for credit or room,
	// and another Write must not slip its bytes into the middle of it.
	wmu sync.Mutex
}

// dropUnreadLocked discards data the handler will never read and returns it
// to the client's windows, so it doesn't hold up the stream or, through the
// shared connection window, the connection's other streams. c.mu must be
// held.
func (st *leanStream) dropUnreadLocked() {
	if n := int64(len(st.rbuf)); n > 0 {
		st.rbuf = nil
		st.c.creditConn(n)
		st.creditStream(n)
	}
}

// creditStream returns n consumed bytes to the stream's window. c.mu must
// be held.
func (st *leanStream) creditStream(n int64) {
	if st.remoteDone || st.reset {
		return
	}
	st.recvUnacked += n
	if st.recvUnacked >= leanStreamRecvWindow/leanWindowUpdateDivisor {
		st.c.wbuf = appendWindowUpdate(st.c.wbuf, st.id, uint32(st.recvUnacked))
		st.recvAvail += st.recvUnacked
		st.recvUnacked = 0
		st.c.queued()
	}
}

// run answers the request and, for a CONNECT, runs the handler on the tunnel,
// as serveH2's handler does with x/net's server.
func (st *leanStream) run(method, authority, scheme, path string, truncated bool) {
	c := st.c
	defer st.finish()
	// A bug in serving one stream must not end the process and every tunnel
	// in it; the handler's own panics are handled in runHandler.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[samizdat] panic serving stream %d: %v\n%s", st.id, r, debug.Stack())
			c.mu.Lock()
			c.resetStreamLocked(st, http2.ErrCodeInternal)
			c.mu.Unlock()
		}
	}()
	if truncated {
		// The header list passed MaxHeaderListSize; x/net's server answers
		// 431 without calling the handler (handleHeaderListTooLong).
		st.reply(http.StatusRequestHeaderFieldsTooLarge, "text/html; charset=utf-8", false,
			"<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>")
		return
	}
	// x/net's server rejects a malformed request with RST_STREAM before any
	// handler sees it: every request needs a :method, a CONNECT must have
	// :authority and neither :scheme nor :path, and any other request needs a
	// :path and an http or https :scheme.
	connect := method == http.MethodConnect
	malformed := method == "" ||
		connect && (authority == "" || scheme != "" || path != "") ||
		!connect && (path == "" || scheme != "http" && scheme != "https")
	if malformed {
		if c.resetStream(st.id, http2.ErrCodeProtocol) != nil {
			c.close()
		}
		return
	}
	if !connect {
		st.replyError(http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if err := st.writeHeaders(http.StatusOK, nil); err != nil {
		return
	}

	st.runHandler(&leanStreamConn{st: st}, authority)

	// Wait for the client's END_STREAM before ending the stream, so it
	// closes normally rather than with RST_STREAM, as serveH2 does, and for
	// writes from goroutines the handler left behind to finish, up to the
	// drain timeout. Data still arriving is dropped meanwhile.
	c.mu.Lock()
	st.draining = true
	st.dropUnreadLocked()
	st.cond.Broadcast() // a read the handler left behind now fails
	timedOut := false
	timer := time.AfterFunc(leanDrainTimeout, func() {
		c.mu.Lock()
		timedOut = true
		st.cond.Broadcast()
		c.mu.Unlock()
	})
	for (!st.remoteDone || st.writing > 0) && !st.reset && !c.closed && !timedOut {
		st.cond.Wait()
	}
	timer.Stop()
	st.closed = true
	st.wakeLocked()
	st.endLocked(nil)
	c.mu.Unlock()
}

// runHandler runs the Handler on the stream. A handler that panics resets
// only its own stream, as x/net's server does, rather than ending the
// process and every tunnel in it.
func (st *leanStream) runHandler(conn net.Conn, destination string) {
	defer func() {
		if r := recover(); r != nil {
			// http.ErrAbortHandler aborts a handler on purpose; x/net's server
			// doesn't log it either.
			if r != http.ErrAbortHandler {
				log.Printf("[samizdat] panic in handler for stream %d: %v\n%s", st.id, r, debug.Stack())
			}
			st.c.mu.Lock()
			st.c.resetStreamLocked(st, http2.ErrCodeInternal)
			st.c.mu.Unlock()
		}
	}()
	st.c.s.config.Handler(st.ctx, conn, destination)
}

// endLocked sends body, if any, with END_STREAM, and RST_STREAM(NO_ERROR) if
// the client hasn't ended its side. c.mu must be held.
func (st *leanStream) endLocked(body []byte) {
	c := st.c
	// The body goes out in as few DATA frames as the send windows allow,
	// one for a short body as x/net sends it, with END_STREAM on the last.
	// Credit is rechecked after every wait, since c.mu is released.
	for {
		for {
			if st.reset {
				return
			}
			if err := st.waitForRoom(); err != nil {
				return
			}
			if len(body) == 0 || st.sendWin > 0 && c.connSendWin > 0 {
				break
			}
			st.cond.Wait()
		}
		// An empty body needs no credit; a window can be negative (the
		// client may shrink INITIAL_WINDOW_SIZE after data went out), so a
		// frame's length is taken from the windows only when both are
		// open, and never below zero.
		n := 0
		if len(body) > 0 {
			n = max(0, min(len(body), c.peerMaxFrame, int(st.sendWin), int(c.connSendWin)))
		}
		last := n == len(body)
		flags := http2.Flags(0)
		if last {
			flags = http2.FlagDataEndStream
		}
		c.wbuf = appendFrameHeader(c.wbuf, n, http2.FrameData, flags, st.id)
		c.wbuf = append(c.wbuf, body[:n]...)
		st.sendWin -= int64(n)
		c.connSendWin -= int64(n)
		body = body[n:]
		c.queued()
		if last {
			break
		}
	}
	if !st.remoteDone {
		c.wbuf = appendRSTStream(c.wbuf, st.id, http2.ErrCodeNo)
		st.markResetLocked()
		c.queued()
	}
}

// finish forgets the stream, returning anything the handler left unread to
// the client's connection window.
func (st *leanStream) finish() {
	c := st.c
	c.mu.Lock()
	delete(c.streams, st.id)
	if !st.reset {
		c.active--
	}
	st.removed = true
	st.closed = true
	if st.waitingRoom {
		st.waitingRoom = false
		if i := slices.Index(c.roomWaiters, st); i >= 0 {
			c.roomWaiters = slices.Delete(c.roomWaiters, i, i+1)
		}
	}
	st.dropUnreadLocked()
	st.wakeLocked()
	c.mu.Unlock()
	st.cancel()
}

// replyError answers with msg as http.Error writes it.
func (st *leanStream) replyError(status int, msg string) {
	st.reply(status, "text/plain; charset=utf-8", true, msg+"\n")
}

// reply answers with body and the headers net/http adds for it.
func (st *leanStream) reply(status int, contentType string, nosniff bool, body string) {
	hdrs := []hpack.HeaderField{{Name: "content-type", Value: contentType}}
	if nosniff {
		hdrs = append(hdrs, hpack.HeaderField{Name: "x-content-type-options", Value: "nosniff"})
	}
	hdrs = append(hdrs, hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
	if err := st.writeHeaders(status, hdrs); err != nil {
		return
	}
	st.c.mu.Lock()
	st.endLocked([]byte(body))
	st.c.mu.Unlock()
}

// writeHeaders sends response HEADERS with :status, extra and date, the
// fields x/net's server sends for these responses.
func (st *leanStream) writeHeaders(status int, extra []hpack.HeaderField) error {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := st.waitForRoom(); err != nil {
		return err
	}
	c.hpackBuf.Reset()
	c.hpackEnc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	for _, f := range extra {
		c.hpackEnc.WriteField(f)
	}
	c.hpackEnc.WriteField(hpack.HeaderField{Name: "date", Value: time.Now().UTC().Format(http.TimeFormat)})
	block := c.hpackBuf.Bytes()
	c.wbuf = appendFrameHeader(c.wbuf, len(block), http2.FrameHeaders, http2.FlagHeadersEndHeaders, st.id)
	c.wbuf = append(c.wbuf, block...)
	c.queued()
	return nil
}

// leanStreamConn is the net.Conn a handler gets for a lean stream. As with
// serverStreamConn, Close and CloseWrite don't end the stream; that happens
// when the handler returns.
type leanStreamConn struct {
	st *leanStream
}

func (sc *leanStreamConn) Read(b []byte) (int, error) {
	st := sc.st
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(st.rbuf) == 0 {
		switch {
		case st.closed, st.draining:
			return 0, net.ErrClosed
		case st.reset:
			return 0, errLeanStreamReset
		case st.remoteDone:
			return 0, io.EOF
		case c.closed:
			return 0, errLeanConnClosed
		case len(b) == 0:
			return 0, nil
		}
		st.cond.Wait()
	}
	n := copy(b, st.rbuf)
	st.rbuf = st.rbuf[n:]
	if len(st.rbuf) == 0 {
		st.rbuf = nil
	}
	c.creditConn(int64(n))
	st.creditStream(int64(n))
	return n, nil
}

func (sc *leanStreamConn) Write(b []byte) (int, error) {
	st := sc.st
	c := st.c
	st.wmu.Lock()
	defer st.wmu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	st.writing++
	defer func() {
		st.writing--
		if st.writing == 0 {
			st.cond.Broadcast()
		}
	}()
	written := 0
	for written < len(b) {
		for {
			if st.closed {
				return written, net.ErrClosed
			}
			if st.reset {
				return written, errLeanStreamReset
			}
			if c.closed {
				return written, errLeanConnClosed
			}
			if len(c.wbuf)+leanFrameHeaderLen >= leanMaxWriteBuffer {
				st.awaitRoomLocked()
				continue
			}
			if st.sendWin <= 0 || c.connSendWin <= 0 {
				st.cond.Wait()
				continue
			}
			break
		}
		// Bounded by the buffer's room too, so one large frame can't carry
		// the buffer far past leanMaxWriteBuffer.
		room := leanMaxWriteBuffer - len(c.wbuf) - leanFrameHeaderLen
		n := min(len(b)-written, c.peerMaxFrame, int(st.sendWin), int(c.connSendWin), room)
		c.wbuf = appendFrameHeader(c.wbuf, n, http2.FrameData, 0, st.id)
		c.wbuf = append(c.wbuf, b[written:written+n]...)
		st.sendWin -= int64(n)
		c.connSendWin -= int64(n)
		written += n
		c.queued()
	}
	return written, nil
}

func (sc *leanStreamConn) Close() error {
	st := sc.st
	st.c.mu.Lock()
	st.closed = true
	st.dropUnreadLocked()
	st.wakeLocked()
	st.c.mu.Unlock()
	return nil
}

// CloseWrite is a no-op, as for serverStreamConn: the stream ends when the
// handler returns.
func (sc *leanStreamConn) CloseWrite() error { return nil }

func (sc *leanStreamConn) LocalAddr() net.Addr                { return sc.st.c.localAddr }
func (sc *leanStreamConn) RemoteAddr() net.Addr               { return sc.st.c.remoteAddr }
func (sc *leanStreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *leanStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (sc *leanStreamConn) SetWriteDeadline(t time.Time) error { return nil }

// batchConn sits beneath the TLS connection. Inside batch, the records TLS
// writes are collected and sent to the socket in one Write when it returns.
// Outside it, writes go straight through, so the handshake and any record TLS
// sends on its own, such as an alert or a KeyUpdate, are not held back.
//
// Records must reach the socket in the order TLS wrote them. A record TLS
// writes while a batch is being sent, which it can because it no longer holds
// its own lock by then, is queued behind the batch rather than sent ahead
// of it.
type batchConn struct {
	net.Conn
	mu sync.Mutex
	// pending is set from the start of a batch until everything it and any
	// record written meanwhile collected has been sent.
	pending bool
	buf     []byte
	spare   []byte // the previous buffer, for reuse
}

func (bc *batchConn) Write(b []byte) (int, error) {
	bc.mu.Lock()
	if bc.pending {
		if len(bc.buf)+len(b) > leanMaxBatch {
			bc.mu.Unlock()
			return 0, errLeanBatchFull
		}
		bc.buf = append(bc.buf, b...)
		bc.mu.Unlock()
		return len(b), nil
	}
	bc.mu.Unlock()
	return bc.Conn.Write(b)
}

// batch runs write, which writes through TLS, then sends everything it wrote
// in one socket Write. Only the connection's writer goroutine calls it.
func (bc *batchConn) batch(write func() error) error {
	bc.mu.Lock()
	bc.pending = true
	bc.mu.Unlock()
	err := write()
	for {
		bc.mu.Lock()
		buf := bc.buf
		if len(buf) == 0 {
			bc.pending = false
			bc.mu.Unlock()
			return err
		}
		bc.buf, bc.spare = bc.spare[:0], nil
		bc.mu.Unlock()
		_, werr := bc.Conn.Write(buf)
		bc.mu.Lock()
		if bc.spare == nil {
			bc.spare = buf[:0]
		}
		if werr != nil {
			bc.pending = false
			bc.buf = bc.buf[:0]
			bc.mu.Unlock()
			return errors.Join(err, werr)
		}
		bc.mu.Unlock()
	}
}

// overKeep reports whether either buffer is larger than keep.
func (bc *batchConn) overKeep(keep int) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return cap(bc.buf) > keep || cap(bc.spare) > keep
}

// trim drops buffers over keep while no batch is being sent.
func (bc *batchConn) trim(keep int) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if bc.pending {
		return
	}
	if cap(bc.buf) > keep {
		bc.buf = nil
	}
	if cap(bc.spare) > keep {
		bc.spare = nil
	}
}

func appendFrameHeader(b []byte, length int, t http2.FrameType, flags http2.Flags, streamID uint32) []byte {
	return append(b,
		byte(length>>16), byte(length>>8), byte(length),
		byte(t), byte(flags),
		byte(streamID>>24)&0x7f, byte(streamID>>16), byte(streamID>>8), byte(streamID))
}

func appendSettings(b []byte, settings []http2.Setting) []byte {
	b = appendFrameHeader(b, 6*len(settings), http2.FrameSettings, 0, 0)
	for _, s := range settings {
		b = binary.BigEndian.AppendUint16(b, uint16(s.ID))
		b = binary.BigEndian.AppendUint32(b, s.Val)
	}
	return b
}

func appendWindowUpdate(b []byte, streamID, incr uint32) []byte {
	b = appendFrameHeader(b, 4, http2.FrameWindowUpdate, 0, streamID)
	return binary.BigEndian.AppendUint32(b, incr&0x7fffffff)
}

func appendRSTStream(b []byte, streamID uint32, code http2.ErrCode) []byte {
	b = appendFrameHeader(b, 4, http2.FrameRSTStream, 0, streamID)
	return binary.BigEndian.AppendUint32(b, uint32(code))
}

var _ net.Conn = (*leanStreamConn)(nil)
