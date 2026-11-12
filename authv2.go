package samizdat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Version 2 auth binds the SessionID to the ClientHello it travels in, as
// REALITY does. The client takes an X25519 shared secret between its own
// key share and the server's static key, derives an AES-256-GCM key from it
// and the ClientHello's random, and seals
//
//	version (2) | 3 zero bytes | Unix time (uint32) | shortID (8)
//
// with the random's last 12 bytes as nonce and the whole ClientHello, its
// SessionID zeroed, as additional data. The 16-byte ciphertext and 16-byte
// tag are the SessionID.
//
// Against version 1 (auth.go): a SessionID copied into another ClientHello
// fails to open, since the copier has neither the key share's private key
// nor the same ClientHello; and no part of it is the same from one
// connection to the next, where version 1 starts with the shortID in the
// clear. A server accepts both versions, so older clients keep working.

const (
	authV2Label   = "SAMIZDAT-v2"
	authV2Version = 2
	// sessionIDOffset is where a ClientHello handshake message holds its
	// SessionID: type (1), length (3), version (2), random (32), SessionID
	// length (1).
	sessionIDOffset = 1 + 3 + 2 + 32 + 1
	// DefaultMaxClockSkew is how far a version 2 SessionID's time may be
	// from the server's. It's generous because a phone's clock can be far
	// off and a client refused for it gets no useful error; the replay
	// filter covers the window.
	DefaultMaxClockSkew = 12 * time.Hour
	extKeyShare         = 51
	groupX25519         = 0x001d
	groupX25519MLKEM768 = 0x11ec
)

// authNow is the clock version 2 auth uses. A variable for tests.
var authNow = time.Now

// clientHello is what version 2 auth reads from a ClientHello handshake
// message.
type clientHello struct {
	random    []byte
	sessionID []byte
	// x25519 is the client's X25519 public key: its X25519 key share, or
	// the X25519 half of its X25519MLKEM768 share if it has no X25519 one.
	x25519 []byte
}

var errHello = errors.New("samizdat: malformed ClientHello")

// parseClientHello reads a ClientHello handshake message, starting with its
// type and length.
func parseClientHello(msg []byte) (*clientHello, error) {
	if len(msg) < sessionIDOffset || msg[0] != 1 {
		return nil, errHello
	}
	ch := &clientHello{random: msg[6:38]}
	b := msg[sessionIDOffset-1:]
	var ok bool
	if ch.sessionID, b, ok = readVec8(b); !ok {
		return nil, errHello
	}
	if _, b, ok = readVec16(b); !ok { // cipher suites
		return nil, errHello
	}
	if _, b, ok = readVec8(b); !ok { // compression methods
		return nil, errHello
	}
	exts, _, ok := readVec16(b)
	if !ok {
		return nil, errHello
	}
	var hybrid []byte
	for len(exts) > 0 {
		if len(exts) < 2 {
			return nil, errHello
		}
		typ := binary.BigEndian.Uint16(exts)
		var data []byte
		if data, exts, ok = readVec16(exts[2:]); !ok {
			return nil, errHello
		}
		if typ != extKeyShare {
			continue
		}
		shares, _, ok := readVec16(data)
		if !ok {
			return nil, errHello
		}
		for len(shares) > 0 {
			if len(shares) < 2 {
				return nil, errHello
			}
			group := binary.BigEndian.Uint16(shares)
			var key []byte
			if key, shares, ok = readVec16(shares[2:]); !ok {
				return nil, errHello
			}
			switch {
			case group == groupX25519 && len(key) == 32 && ch.x25519 == nil:
				ch.x25519 = key
			case group == groupX25519MLKEM768 && len(key) > 32 && hybrid == nil:
				hybrid = key[len(key)-32:]
			}
		}
	}
	if ch.x25519 == nil {
		ch.x25519 = hybrid
	}
	return ch, nil
}

func readVec8(b []byte) ([]byte, []byte, bool) {
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, nil, false
	}
	n := int(b[0])
	return b[1 : 1+n], b[1+n:], true
}

func readVec16(b []byte) ([]byte, []byte, bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// authV2AEAD derives the AEAD for a ClientHello from the X25519 shared
// secret and the ClientHello's random.
func authV2AEAD(shared, random []byte) (cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, random[:20], []byte(authV2Label)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealSessionIDv2 returns the version 2 SessionID for a ClientHello whose
// message, with a zero 32-byte SessionID, is raw.
func sealSessionIDv2(shared, raw []byte, shortID [shortIDLen]byte, now time.Time) ([sessionIDLen]byte, error) {
	var sid [sessionIDLen]byte
	if len(raw) < sessionIDOffset+sessionIDLen || raw[sessionIDOffset-1] != sessionIDLen {
		return sid, errHello
	}
	random := raw[6:38]
	aead, err := authV2AEAD(shared, random)
	if err != nil {
		return sid, err
	}
	var plain [16]byte
	plain[0] = authV2Version
	binary.BigEndian.PutUint32(plain[4:], uint32(now.Unix()))
	copy(plain[8:], shortID[:])
	aead.Seal(sid[:0], random[20:], plain[:], raw)
	return sid, nil
}

// verifyClientHelloV2 checks a version 2 SessionID in the ClientHello
// message msg against the server's private key, and returns its shortID.
func verifyClientHelloV2(msg []byte, ch *clientHello, privateKey []byte, shortIDs [][shortIDLen]byte, maxSkew time.Duration, now time.Time) ([shortIDLen]byte, bool) {
	var zero [shortIDLen]byte
	if ch.x25519 == nil || len(ch.sessionID) != sessionIDLen {
		return zero, false
	}
	shared, err := curve25519.X25519(privateKey, ch.x25519)
	if err != nil {
		return zero, false
	}
	aead, err := authV2AEAD(shared, ch.random)
	if err != nil {
		return zero, false
	}
	aad := bytes.Clone(msg)
	clear(aad[sessionIDOffset : sessionIDOffset+sessionIDLen])
	plain, err := aead.Open(nil, ch.random[20:], ch.sessionID, aad)
	if err != nil || len(plain) != 16 || plain[0] != authV2Version {
		return zero, false
	}
	t := time.Unix(int64(binary.BigEndian.Uint32(plain[4:])), 0)
	if d := now.Sub(t); d > maxSkew || d < -maxSkew {
		return zero, false
	}
	var id [shortIDLen]byte
	copy(id[:], plain[8:])
	if !slices.Contains(shortIDs, id) {
		return zero, false
	}
	return id, true
}

// AuthenticateClientHello checks a ClientHello handshake message, as read
// from its TLS record (starting with its type and length), for a version 2
// or version 1 SessionID under the server's X25519 private key and one of
// shortIDs. It returns the shortID and true if either authenticates. It
// doesn't remember SessionIDs: a caller that admits connections itself
// must refuse repeats, as Server does.
func AuthenticateClientHello(msg, privateKey []byte, shortIDs [][shortIDLen]byte, maxSkew time.Duration) ([shortIDLen]byte, bool) {
	ch, err := parseClientHello(msg)
	if err != nil {
		return [shortIDLen]byte{}, false
	}
	if id, ok := verifyClientHelloV2(msg, ch, privateKey, shortIDs, maxSkew, authNow()); ok {
		return id, true
	}
	pub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return [shortIDLen]byte{}, false
	}
	id, ok, err := VerifySessionID(ch.sessionID, pub, shortIDs)
	return id, ok && err == nil
}
