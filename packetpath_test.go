// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailcat_webrtc

// These tests need tailscale.com with the magicsock packet path patch;
// run them with the go test invocation that internal/wasmbuild's
// TestPacketPathModfile logs, or via that test itself.

package tailcat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
)

// memPath links a server and a client packet path in memory, like a
// DataChannel between them, counting what it carries.
type memPath struct {
	toServer, toClient chan []byte
	server, client     atomic.Pointer[PacketPath]
	carried            atomic.Int64 // datagram bytes taken by either side's send
	carriedToServer    atomic.Int64 // of which the client sent
	accept             atomic.Bool  // whether send takes datagrams
	done               chan struct{}
	wg                 sync.WaitGroup
}

func newMemPath(t *testing.T) *memPath {
	m := &memPath{
		toServer: make(chan []byte, 512),
		toClient: make(chan []byte, 512),
		done:     make(chan struct{}),
	}
	m.accept.Store(true)
	pump := func(ch chan []byte, dst *atomic.Pointer[PacketPath]) {
		defer m.wg.Done()
		for {
			select {
			case pkt := <-ch:
				if p := dst.Load(); p != nil {
					p.Deliver(pkt)
				}
			case <-m.done:
				return
			}
		}
	}
	m.wg.Add(2)
	go pump(m.toServer, &m.server)
	go pump(m.toClient, &m.client)
	t.Cleanup(func() {
		close(m.done)
		m.wg.Wait()
	})
	return m
}

// sendTo returns a PacketPath send func that queues datagrams on ch.
func (m *memPath) sendTo(ch chan []byte) func([]byte) bool {
	return func(pkt []byte) bool {
		if !m.accept.Load() {
			return false
		}
		select {
		case ch <- bytes.Clone(pkt):
		default: // full: drop, like a UDP socket
		}
		m.carried.Add(int64(len(pkt)))
		if ch == m.toServer {
			m.carriedToServer.Add(int64(len(pkt)))
		}
		return true
	}
}

// startPacketPathPair starts a server whose port 80 streams size
// random bytes per connection and a connected client, and returns
// them with the SHA-256 the client should receive.
func startPacketPathPair(t *testing.T, size int) (*Server, *Client, [32]byte) {
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	payload := make([]byte, size)
	rand.Read(payload)
	s := &Server{Logf: mkLogger(t, "server"), Region: dm.Regions[1]}
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != 80 {
			return nil
		}
		return func(c net.Conn) {
			defer c.Close()
			c.Write(payload)
		}
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := &Client{Server: s.TailcatAddr(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)
	return s, c, sha256.Sum256(payload)
}

// fetch dials port 80 and returns the SHA-256 of what it reads,
// calling midway (if non-nil) once half the payload has arrived.
func fetch(t *testing.T, c *Client, size int, midway func()) [32]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	h := sha256.New()
	if midway != nil {
		if _, err := io.CopyN(h, conn, int64(size/2)); err != nil {
			t.Fatalf("reading first half: %v", err)
		}
		midway()
	}
	if _, err := io.Copy(h, conn); err != nil {
		t.Fatalf("reading: %v", err)
	}
	return [32]byte(h.Sum(nil))
}

func installMemPath(t *testing.T, s *Server, c *Client, m *memPath) {
	t.Helper()
	sp, err := s.NewPacketPath(c.PublicKey(), m.sendTo(m.toClient))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := c.NewPacketPath(m.sendTo(m.toServer))
	if err != nil {
		t.Fatal(err)
	}
	m.server.Store(sp)
	m.client.Store(cp)
}

// TestPacketPathCarriesTraffic checks that an installed packet path
// carries the tunnel's WireGuard datagrams in both directions.
func TestPacketPathCarriesTraffic(t *testing.T) {
	const size = 4 << 20
	s, c, want := startPacketPathPair(t, size)
	m := newMemPath(t)
	installMemPath(t, s, c, m)
	if got := fetch(t, c, size, nil); got != want {
		t.Fatal("payload corrupted over packet path")
	}
	// Every WireGuard data datagram carries its plaintext plus
	// overhead, so a path that carried the transfer moved more bytes
	// than the payload itself from the server; the client's TCP
	// acknowledgements went the other way.
	up := m.carriedToServer.Load()
	if down := m.carried.Load() - up; down < size {
		t.Fatalf("packet path carried %d bytes of a %d-byte transfer to the client", down, size)
	}
	if up == 0 {
		t.Fatal("packet path carried nothing from the client to the server")
	}
}

// TestPacketPathFallback checks that closing both packet paths in the
// middle of a transfer moves its traffic back to the ordinary path
// without breaking the connection, and that a path declining
// datagrams leaves them on the ordinary path.
func TestPacketPathFallback(t *testing.T) {
	const size = 4 << 20
	s, c, want := startPacketPathPair(t, size)
	m := newMemPath(t)
	installMemPath(t, s, c, m)
	got := fetch(t, c, size, func() {
		m.server.Load().Close()
		m.client.Load().Close()
	})
	if got != want {
		t.Fatal("payload corrupted across fallback")
	}

	// A closed path takes no new datagrams.
	if m.client.Load().Deliver([]byte{1}) {
		t.Error("closed path accepted a datagram")
	}

	// A declining path carries nothing, and traffic still flows.
	m2 := newMemPath(t)
	m2.accept.Store(false)
	installMemPath(t, s, c, m2)
	if got := fetch(t, c, size, nil); got != want {
		t.Fatal("payload corrupted with a declining path")
	}
	if n := m2.carried.Load(); n != 0 {
		t.Errorf("declining path carried %d bytes", n)
	}
}

// TestPacketPathReplace checks that a replaced path stops carrying
// traffic and that closing it doesn't uninstall its replacement.
func TestPacketPathReplace(t *testing.T) {
	const size = 1 << 20
	s, c, want := startPacketPathPair(t, size)
	old := newMemPath(t)
	installMemPath(t, s, c, old)
	oldServer, oldClient := old.server.Load(), old.client.Load()

	cur := newMemPath(t)
	installMemPath(t, s, c, cur)
	oldServer.Close()
	oldClient.Close()
	before := old.carried.Load()
	if got := fetch(t, c, size, nil); got != want {
		t.Fatal("payload corrupted")
	}
	if n := old.carried.Load() - before; n != 0 {
		t.Errorf("replaced path carried %d bytes", n)
	}
	if n := cur.carried.Load(); n < size {
		t.Errorf("current path carried %d bytes of a %d-byte transfer", n, size)
	}
}

func TestPacketPathNotStarted(t *testing.T) {
	if _, err := (&Server{}).NewPacketPath(NewPrivateKey().Private.Public(), nil); err == nil {
		t.Error("Server.NewPacketPath before Start succeeded")
	}
	if _, err := NewClient("tcx").NewPacketPath(nil); err == nil {
		t.Error("Client.NewPacketPath before connecting succeeded")
	}
}
