package samizdat

import (
	"context"
	"net"
	"testing"
)

func TestNewServerNeedsAHandler(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	if _, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{sid}}); err == nil {
		t.Fatal("expected error with neither Handler nor SessionHandler")
	}
	h := func(context.Context, net.Conn, [8]byte) {}
	if _, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{sid}, SessionHandler: h}); err != nil {
		t.Fatalf("SessionHandler alone: %v", err)
	}
}
