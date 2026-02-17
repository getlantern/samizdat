package samizdat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// authLabel is the HKDF info string for deriving the auth key.
	authLabel = "SAMIZDAT"
	// authKeyLen is the length of the derived HMAC key.
	authKeyLen = 32
	// sessionIDLen is the TLS SessionID field length.
	sessionIDLen = 32
	// hmacTagLen is the truncated HMAC-SHA256 tag length in the SessionID.
	hmacTagLen = 16
	// shortIDLen is the length of the pre-shared short identifier.
	shortIDLen = 8
	// nonceLen is the auth nonce length (8 bytes to fit in SessionID layout:
	// 8 shortID + 8 nonce + 16 HMAC tag = 32 bytes).
	nonceLen = 8
)

// GenerateKeyPair generates a new X25519 keypair for use as server credentials.
// Returns (privateKey, publicKey, error).
func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("computing public key: %w", err)
	}
	return privateKey, publicKey, nil
}

// GenerateShortID generates a random 8-byte short identifier.
func GenerateShortID() ([shortIDLen]byte, error) {
	var id [shortIDLen]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf("generating short ID: %w", err)
	}
	return id, nil
}

// derivePSK derives a pre-shared authentication key from the server's public key
// and a short ID using HKDF-SHA256. Both client and server can independently
// compute this value.
func derivePSK(serverPubKey []byte, shortID [shortIDLen]byte) ([]byte, error) {
	// salt = shortID, ikm = serverPubKey, info = authLabel
	hkdfReader := hkdf.New(sha256.New, serverPubKey, shortID[:], []byte(authLabel))
	key := make([]byte, authKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return key, nil
}

// BuildSessionID constructs a 32-byte TLS SessionID that embeds an
// authentication tag. Layout:
//
//	[0:8]   = shortID (plaintext, allows server to look up the PSK)
//	[8:16]  = random nonce
//	[16:32] = HMAC-SHA256(PSK, nonce) truncated to 16 bytes
//
// The PSK is derived from the server's public key and the short ID.
func BuildSessionID(serverPubKey []byte, shortID [shortIDLen]byte) ([sessionIDLen]byte, error) {
	var sessionID [sessionIDLen]byte

	psk, err := derivePSK(serverPubKey, shortID)
	if err != nil {
		return sessionID, err
	}

	// Place shortID in [0:8]
	copy(sessionID[:shortIDLen], shortID[:])

	// Generate random nonce in [8:16]
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return sessionID, fmt.Errorf("generating nonce: %w", err)
	}

	// Compute HMAC-SHA256(PSK, nonce) and truncate to 16 bytes
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	tag := mac.Sum(nil)[:hmacTagLen]
	copy(sessionID[shortIDLen+nonceLen:], tag)

	return sessionID, nil
}

// VerifySessionID checks whether the given 32-byte SessionID contains a valid
// authentication tag for any of the allowed short IDs.
// Returns the matching shortID and true if authentication succeeds.
//
// serverPubKey is the server's X25519 public key (derived from the private key).
func VerifySessionID(sessionID []byte, serverPubKey []byte, allowedShortIDs [][shortIDLen]byte) ([shortIDLen]byte, bool, error) {
	var zero [shortIDLen]byte

	if len(sessionID) != sessionIDLen {
		return zero, false, nil
	}

	// Extract fields from SessionID
	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]

	// Check if the candidateShortID is in the allowed list
	found := false
	for _, allowed := range allowedShortIDs {
		if candidateShortID == allowed {
			found = true
			break
		}
	}
	if !found {
		return zero, false, nil
	}

	// Derive the same PSK
	psk, err := derivePSK(serverPubKey, candidateShortID)
	if err != nil {
		return zero, false, err
	}

	// Compute expected HMAC
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	expectedTag := mac.Sum(nil)[:hmacTagLen]

	// Constant-time comparison
	if !hmac.Equal(tag, expectedTag) {
		return zero, false, nil
	}

	return candidateShortID, true, nil
}

// derivePublicKey computes the X25519 public key from a private key.
// Returns both the original private key and the derived public key.
func derivePublicKey(privateKey []byte) ([]byte, []byte, error) {
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("computing public key: %w", err)
	}
	return privateKey, publicKey, nil
}

// ExtractSessionID extracts the session_id field from raw ClientHello bytes.
func ExtractSessionID(clientHello []byte) ([]byte, error) {
	if len(clientHello) < 6 {
		return nil, errors.New("ClientHello too short")
	}

	pos := 0
	if clientHello[0] == 0x01 { // HandshakeTypeClientHello
		if len(clientHello) < 4 {
			return nil, errors.New("ClientHello too short for handshake header")
		}
		pos = 4
	}

	// Skip client_version(2) + random(32)
	pos += 2 + 32
	if pos >= len(clientHello) {
		return nil, errors.New("ClientHello too short for session_id length")
	}

	sessionIDLength := int(clientHello[pos])
	pos++
	if pos+sessionIDLength > len(clientHello) {
		return nil, errors.New("ClientHello session_id exceeds data")
	}

	sessionID := make([]byte, sessionIDLength)
	copy(sessionID, clientHello[pos:pos+sessionIDLength])
	return sessionID, nil
}
