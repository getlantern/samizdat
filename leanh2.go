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
	// An idle connection keeps a write buffer up to this size and returns a
	// larger one to leanBufPool, so thousands of idle connections don't each
	// hold a burst's worth while busy ones don't reallocate on every pause.
	leanIdleBufKeep = 64 << 10
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
	leanDrainTimeout      = 5 * time.Second
	// A WINDOW_UPDATE goes out once a quarter of a window has been consumed.
	leanWindowUpdateDivisor = 4
)

var (
	errLeanConnClosed  = errors.New("samizdat: connection closed")
	errLeanStreamReset = errors.New("samizdat: stream reset by peer")
	errLeanProtocol    = errors.New("samizdat: HTTP/2 protocol error")
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
	}
	c.wcond = sync.NewCond(&c.mu)
	c.roomCond = sync.NewCond(&c.mu)
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
	// the writer when frames are queued; roomCond wakes Writes waiting for
	// room in the write buffer. A stream waiting on data or on flow control
	// waits on its own cond.
	mu       sync.Mutex
	wcond    *sync.Cond
	roomCond *sync.Cond

	wbuf   []byte // frames queued for the writer
	closed bool
	// queuedControl counts the control frames the read loop queued since the
	// writer last took the buffer; see leanMaxQueuedControl.
	queuedControl int

	streams map[uint32]*leanStream
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
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}

	fr := http2.NewFramer(nil, br)
	fr.SetReuseFrames()
	fr.SetMaxReadFrameSize(leanMaxReadFrameSize)
	fr.MaxHeaderListSize = leanMaxHeaderListSize
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				if c.resetStream(se.StreamID, se.Code) != nil {
					return
				}
				continue
			}
			return
		}
		if err := c.handleFrame(f); err != nil {
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
		return errLeanProtocol
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
			st.cond.Broadcast()
			c.roomCond.Broadcast()
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
	err := f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			if s.Val > 1<<31-1 {
				return errLeanProtocol
			}
			delta := int64(s.Val) - c.peerInitWin
			c.peerInitWin = int64(s.Val)
			for _, st := range c.streams {
				st.sendWin += delta
				st.cond.Broadcast()
			}
		case http2.SettingMaxFrameSize:
			if s.Val < 16384 || s.Val > 1<<24-1 {
				return errLeanProtocol
			}
			c.peerMaxFrame = int(s.Val)
		}
		return nil
	})
	if err != nil {
		return err
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
	if id%2 == 0 || id <= c.lastStreamID {
		c.mu.Unlock()
		return errLeanProtocol
	}
	c.lastStreamID = id
	if len(c.streams) >= leanMaxHandlersFactor*c.maxStreams {
		// Too many handlers still running for streams the client reset.
		c.mu.Unlock()
		return errLeanProtocol
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
		ctx:        ctx,
		cancel:     cancel,
		sendWin:    c.peerInitWin,
		recvAvail:  leanStreamRecvWindow,
		remoteDone: f.StreamEnded(),
	}
	c.streams[id] = st
	c.active++
	c.mu.Unlock()

	go st.run(f.PseudoValue("method"), f.PseudoValue("authority"), f.PseudoValue("scheme"), f.PseudoValue("path"))
	return nil
}

// markResetLocked records that st has been reset by either side, which
// frees its MaxConcurrentStreams slot. c.mu must be held.
func (st *leanStream) markResetLocked() {
	if !st.reset {
		st.reset = true
		if !st.removed {
			st.c.active--
		}
	}
}

func (c *leanConn) handleData(f *http2.DataFrame) error {
	// The whole frame, padding included, counts against flow control.
	n := int64(f.Length)
	data := f.Data()
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > c.connRecvAvail {
		return errLeanProtocol
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
	st.cond.Broadcast()
	c.roomCond.Broadcast()
	st.cancel()
}

// writeLoop sends everything queued, all at once, until the connection
// closes.
func (c *leanConn) writeLoop() {
	for {
		c.mu.Lock()
		for len(c.wbuf) == 0 && !c.closed {
			if cap(c.wbuf) > leanIdleBufKeep {
				putLeanBuf(c.wbuf)
				c.wbuf = nil
			}
			c.wcond.Wait()
		}
		if len(c.wbuf) == 0 {
			c.mu.Unlock()
			return
		}
		buf := c.wbuf
		c.wbuf = getLeanBuf()
		c.queuedControl = 0
		c.roomCond.Broadcast()
		c.mu.Unlock()

		err := c.bc.batch(func() error {
			_, err := c.conn.Write(buf)
			return err
		})
		putLeanBuf(buf)
		if err != nil {
			c.close()
			return
		}
	}
}

// close ends the connection: every stream's reads and writes fail and every
// handler's context ends.
func (c *leanConn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	for _, st := range c.streams {
		st.cond.Broadcast()
	}
	c.wcond.Broadcast()
	c.roomCond.Broadcast()
	c.mu.Unlock()
	c.cancel()
	c.conn.Close()
}

// waitForRoom blocks until the write buffer can take more frames. c.mu must
// be held.
func (c *leanConn) waitForRoom() error {
	for len(c.wbuf) >= leanMaxWriteBuffer && !c.closed {
		c.roomCond.Wait()
	}
	if c.closed {
		return errLeanConnClosed
	}
	return nil
}

// leanStream is one CONNECT tunnel. Its fields are guarded by c.mu.
type leanStream struct {
	c      *leanConn
	id     uint32
	cond   *sync.Cond // signalled on data, END_STREAM, reset, close and window updates
	ctx    context.Context
	cancel context.CancelFunc

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
func (st *leanStream) run(method, authority, scheme, path string) {
	c := st.c
	defer st.finish()
	// x/net's server rejects a malformed request with RST_STREAM before any
	// handler sees it: a CONNECT must have :authority and neither :scheme nor
	// :path, and any other request needs a :path and an http or https
	// :scheme.
	connect := method == http.MethodConnect
	malformed := connect && (authority == "" || scheme != "" || path != "") ||
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
	// closes normally rather than with RST_STREAM, as serveH2 does. Data
	// still arriving is dropped meanwhile, and writes from goroutines the
	// handler left behind still go through.
	c.mu.Lock()
	st.draining = true
	st.dropUnreadLocked()
	timedOut := false
	timer := time.AfterFunc(leanDrainTimeout, func() {
		c.mu.Lock()
		timedOut = true
		st.cond.Broadcast()
		c.mu.Unlock()
	})
	for !st.remoteDone && !st.reset && !c.closed && !timedOut {
		st.cond.Wait()
	}
	timer.Stop()
	st.closed = true
	st.cond.Broadcast()
	c.roomCond.Broadcast()
	st.endLocked(nil)
	c.mu.Unlock()
}

// runHandler runs the Handler on the stream. A handler that panics resets
// only its own stream, as x/net's server does, rather than ending the
// process and every tunnel in it.
func (st *leanStream) runHandler(conn net.Conn, destination string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[samizdat] panic in handler for stream %d: %v\n%s", st.id, r, debug.Stack())
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
	if st.reset || c.waitForRoom() != nil {
		return
	}
	c.wbuf = appendFrameHeader(c.wbuf, len(body), http2.FrameData, http2.FlagDataEndStream, st.id)
	c.wbuf = append(c.wbuf, body...)
	if !st.remoteDone {
		c.wbuf = appendRSTStream(c.wbuf, st.id, http2.ErrCodeNo)
		st.markResetLocked()
	}
	c.queued()
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
	st.dropUnreadLocked()
	st.cond.Broadcast()
	c.roomCond.Broadcast()
	c.mu.Unlock()
	st.cancel()
}

func (st *leanStream) replyError(status int, msg string) {
	body := msg + "\n"
	if err := st.writeHeaders(status, []hpack.HeaderField{
		{Name: "content-type", Value: "text/plain; charset=utf-8"},
		{Name: "x-content-type-options", Value: "nosniff"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	}); err != nil {
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
	if err := c.waitForRoom(); err != nil {
		return err
	}
	if st.reset {
		return errLeanStreamReset
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
	c.mu.Lock()
	defer c.mu.Unlock()
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
			if len(c.wbuf) >= leanMaxWriteBuffer {
				c.roomCond.Wait()
				continue
			}
			if st.sendWin <= 0 || c.connSendWin <= 0 {
				st.cond.Wait()
				continue
			}
			break
		}
		n := min(len(b)-written, c.peerMaxFrame, int(st.sendWin), int(c.connSendWin))
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
	st.cond.Broadcast()
	st.c.roomCond.Broadcast()
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
}

func (bc *batchConn) Write(b []byte) (int, error) {
	bc.mu.Lock()
	if bc.pending {
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
	bc.buf = getLeanBuf()
	bc.mu.Unlock()
	err := write()
	for {
		bc.mu.Lock()
		buf := bc.buf
		if len(buf) == 0 {
			bc.pending = false
			bc.buf = nil
			bc.mu.Unlock()
			putLeanBuf(buf)
			return err
		}
		bc.buf = nil
		bc.mu.Unlock()
		_, werr := bc.Conn.Write(buf)
		putLeanBuf(buf)
		if werr != nil {
			bc.mu.Lock()
			bc.pending = false
			bc.buf = nil
			bc.mu.Unlock()
			return errors.Join(err, werr)
		}
	}
}

// leanBufPool holds write buffers between bursts, so an idle connection
// holds none and a busy one doesn't allocate a new one per write.
var leanBufPool sync.Pool

func getLeanBuf() []byte {
	if b, ok := leanBufPool.Get().(*[]byte); ok {
		return (*b)[:0]
	}
	return nil
}

func putLeanBuf(b []byte) {
	if b == nil || cap(b) > 4*leanMaxWriteBuffer {
		return
	}
	b = b[:0]
	leanBufPool.Put(&b)
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
