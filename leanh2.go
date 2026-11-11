package samizdat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
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
	leanReadBuffer        = 64 << 10
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
	spare  []byte // the writer's previous buffer, for reuse
	closed bool

	streams      map[uint32]*leanStream
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
				c.resetStream(se.StreamID, se.Code)
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
			c.queued()
			c.mu.Unlock()
		}
	case *http2.RSTStreamFrame:
		c.mu.Lock()
		if st := c.streams[f.StreamID]; st != nil && !st.reset {
			st.reset = true
			st.cond.Broadcast()
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
	c.queued()
	return nil
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
	if c.goingAway || len(c.streams) >= c.maxStreams {
		c.wbuf = appendRSTStream(c.wbuf, id, http2.ErrCodeRefusedStream)
		c.queued()
		c.mu.Unlock()
		return nil
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
	c.mu.Unlock()

	go st.run(f.PseudoValue("method"), f.PseudoValue("authority"),
		f.PseudoValue("scheme") != "" && f.PseudoValue("path") != "")
	return nil
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
			c.queued()
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
	if st.closed {
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

func (c *leanConn) resetStream(id uint32, code http2.ErrCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.streams[id]; st != nil {
		c.resetStreamLocked(st, code)
		return
	}
	c.wbuf = appendRSTStream(c.wbuf, id, code)
	c.queued()
}

// resetStreamLocked ends st with RST_STREAM. c.mu must be held.
func (c *leanConn) resetStreamLocked(st *leanStream, code http2.ErrCode) {
	if st.reset {
		return
	}
	st.reset = true
	c.wbuf = appendRSTStream(c.wbuf, st.id, code)
	c.queued()
	st.cond.Broadcast()
	st.cancel()
}

// writeLoop sends everything queued, all at once, until the connection
// closes.
func (c *leanConn) writeLoop() {
	for {
		c.mu.Lock()
		for len(c.wbuf) == 0 && !c.closed {
			c.wcond.Wait()
		}
		if len(c.wbuf) == 0 {
			c.mu.Unlock()
			return
		}
		buf := c.wbuf
		c.wbuf, c.spare = c.spare[:0], nil
		c.roomCond.Broadcast()
		c.mu.Unlock()

		err := c.bc.batch(func() error {
			_, err := c.conn.Write(buf)
			return err
		})

		c.mu.Lock()
		if cap(buf) <= 2*leanMaxWriteBuffer {
			c.spare = buf[:0]
		}
		c.mu.Unlock()
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
	closed      bool // the handler closed the stream or returned
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
// as serveH2's handler does with x/net's server. hasPath reports whether the
// request carried both :scheme and :path.
func (st *leanStream) run(method, authority string, hasPath bool) {
	c := st.c
	defer st.finish()
	// x/net's server rejects a malformed request with RST_STREAM before any
	// handler sees it: a CONNECT must have :authority and no :scheme or
	// :path, and any other request must have both.
	connect := method == http.MethodConnect
	if connect && (authority == "" || hasPath) || !connect && !hasPath {
		c.resetStream(st.id, http2.ErrCodeProtocol)
		return
	}
	if !connect {
		st.replyError(http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if err := st.writeHeaders(http.StatusOK, nil); err != nil {
		return
	}

	conn := &leanStreamConn{st: st}
	c.s.config.Handler(st.ctx, conn, authority)
	conn.Close()

	// Wait for the client's END_STREAM before ending the stream, so it
	// closes normally rather than with RST_STREAM, as serveH2 does.
	c.mu.Lock()
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
	st.endLocked(nil)
	c.mu.Unlock()
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
		st.reset = true
	}
	c.queued()
}

// finish forgets the stream, returning anything the handler left unread to
// the client's connection window.
func (st *leanStream) finish() {
	c := st.c
	c.mu.Lock()
	delete(c.streams, st.id)
	st.closed = true
	if unread := int64(len(st.rbuf)); unread > 0 {
		st.rbuf = nil
		c.creditConn(unread)
	}
	st.cond.Broadcast()
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
		case st.closed:
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
	st.cond.Broadcast()
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
// sends on its own, such as an alert, are not held back.
type batchConn struct {
	net.Conn
	mu       sync.Mutex
	batching bool
	buf      []byte
}

func (bc *batchConn) Write(b []byte) (int, error) {
	bc.mu.Lock()
	if bc.batching {
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
	bc.batching = true
	bc.mu.Unlock()
	err := write()
	bc.mu.Lock()
	bc.batching = false
	buf := bc.buf
	bc.buf = nil
	bc.mu.Unlock()
	if len(buf) == 0 {
		return err
	}
	_, werr := bc.Conn.Write(buf)
	bc.mu.Lock()
	if bc.buf == nil && cap(buf) <= 2*leanMaxWriteBuffer {
		bc.buf = buf[:0]
	}
	bc.mu.Unlock()
	return errors.Join(err, werr)
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
