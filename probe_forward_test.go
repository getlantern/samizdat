package samizdat

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// recordingOrigin is a cover site that echoes what it receives and reports,
// when the connection ends, every byte that reached it.
func recordingOrigin(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var all bytes.Buffer
		buf := make([]byte, 4096)
		for {
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := c.Read(buf)
			if n > 0 {
				all.Write(buf[:n])
				c.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		got <- all.Bytes()
	}()
	return ln.Addr().String(), got
}

// TestUncheckableFirstRecordGoesToCoverSite: a connection whose first record
// the server can't check is passed to the cover site with every byte it sent,
// so the cover site, not the server, decides how to answer it.
func TestUncheckableFirstRecordGoesToCoverSite(t *testing.T) {
	oversized := []byte{22, 3, 1, 0x7f, 0xff} // a handshake record claiming 32 KiB
	oversized = append(oversized, bytes.Repeat([]byte{0xab}, 64)...)
	cutOff := buildFakeTLSRecord()
	cutOff = cutOff[:len(cutOff)/2]
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"not TLS", []byte("GET / HTTP/1.1\r\nHost: cover.example\r\n\r\n")},
		{"oversized record", oversized},
		{"cut-off header", []byte{22, 3}},
		{"cut-off record", cutOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin, got := recordingOrigin(t)
			_, addr, _, _ := newCloseTestServer(t, ServerConfig{
				MasqueradeDomain: "cover.example",
				MasqueradeAddr:   origin,
			})
			probe, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("probe dial: %v", err)
			}
			defer probe.Close()
			if _, err := probe.Write(tc.bytes); err != nil {
				t.Fatalf("probe write: %v", err)
			}
			// The peer stops sending, so the server's read ends early with
			// what it has.
			probe.(*net.TCPConn).CloseWrite()

			probe.SetReadDeadline(time.Now().Add(5 * time.Second))
			echoed, err := io.ReadAll(probe)
			if err != nil {
				t.Fatalf("reading the cover site's answer: %v", err)
			}
			if !bytes.Equal(echoed, tc.bytes) {
				t.Errorf("probe got %q back, want the cover site's echo of %q", echoed, tc.bytes)
			}
			select {
			case b := <-got:
				if !bytes.Equal(b, tc.bytes) {
					t.Errorf("cover site received %q, want %q", b, tc.bytes)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the connection never reached the cover site")
			}
		})
	}
}

// TestSilentPeerGoesToCoverSite: a peer that sends nothing before the
// ClientHello timeout is passed to the cover site, not closed, and what it
// sends afterwards reaches the cover site.
func TestSilentPeerGoesToCoverSite(t *testing.T) {
	old := clientHelloTimeout
	clientHelloTimeout = 200 * time.Millisecond
	defer func() { clientHelloTimeout = old }()

	origin, got := recordingOrigin(t)
	_, addr, _, _ := newCloseTestServer(t, ServerConfig{
		MasqueradeDomain: "cover.example",
		MasqueradeAddr:   origin,
	})
	probe, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()
	time.Sleep(3 * clientHelloTimeout)

	late := []byte("late bytes")
	if _, err := probe.Write(late); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	probe.(*net.TCPConn).CloseWrite()
	probe.SetReadDeadline(time.Now().Add(5 * time.Second))
	echoed, err := io.ReadAll(probe)
	if err != nil {
		t.Fatalf("reading the cover site's answer: %v", err)
	}
	if !bytes.Equal(echoed, late) {
		t.Errorf("probe got %q back, want the cover site's echo of %q", echoed, late)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, late) {
			t.Errorf("cover site received %q, want %q", b, late)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection never reached the cover site")
	}
}
