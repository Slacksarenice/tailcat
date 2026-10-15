// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tag means the build has wasmbuild's patched dependencies (its
// -modfile); TestPacketPathModfile runs this so. Built with the plain
// go.mod, gVisor is unpatched and the test fails, or takes minutes.

//go:build tailcat_webrtc

// Package gvisortest tests the gVisor fixes that internal/wasmbuild
// applies to browser builds.
package gvisortest

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	mtu      = 9000
	oneWay   = 10 * time.Millisecond
	transfer = 64 << 20
)

func newStack(t *testing.T, addr tcpip.Address) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(s.Close)
	// As tailscale's netstack, with the browser's window sizes.
	cc := tcpip.CongestionControlOption("cubic")
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: 8 << 20}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: 6 << 20}
	for _, opt := range []tcpip.SettableTransportProtocolOption{&cc, &rcv, &snd} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatal(err)
		}
	}
	ep := channel.New(4096, mtu, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	return s, ep
}

// link carries packets from one stack's endpoint to another's after
// oneWay, in order, dropping them while drop is set.
func link(ctx context.Context, from, to *channel.Endpoint, drop *atomic.Bool) {
	type held struct {
		pkt *stack.PacketBuffer
		due time.Time
	}
	line := make(chan held, 1<<16)
	go func() {
		for h := range line {
			time.Sleep(time.Until(h.due))
			to.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(h.pkt.ToView().AsSlice()),
			}))
			h.pkt.DecRef()
		}
	}()
	go func() {
		defer close(line)
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			if drop != nil && drop.Load() {
				pkt.DecRef()
				continue
			}
			line <- held{pkt, time.Now().Add(oneWay)}
		}
	}()
}

// TestRTORecoveryAfterTailLoss loses everything a TCP sender sends for
// a while in mid-transfer, as a browser path does whose SCTP stops, or
// that ends with datagrams queued, and checks the transfer then
// finishes promptly. Unpatched, RACK took the sender out of RTO
// recovery into a fast recovery that resent a segment per RTO, for
// minutes (see wasmbuild's gvisorpatch.go).
func TestRTORecoveryAfterTailLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrA := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	addrB := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	sa, epA := newStack(t, addrA)
	sb, epB := newStack(t, addrB)
	// All of each stack's traffic goes over its one link.
	sa.SetRouteTable([]tcpip.Route{{Destination: addrB.WithPrefix().Subnet(), NIC: 1}})
	sb.SetRouteTable([]tcpip.Route{{Destination: addrA.WithPrefix().Subnet(), NIC: 1}})
	var drop atomic.Bool
	link(ctx, epA, epB, &drop)
	link(ctx, epB, epA, nil)

	ln, err := gonet.ListenTCP(sb, tcpip.FullAddress{NIC: 1, Addr: addrB, Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int64, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		n, _ := io.Copy(io.Discard, c)
		c.Close()
		got <- n
	}()
	c, err := gonet.DialContextTCP(ctx, sa, tcpip.FullAddress{NIC: 1, Addr: addrB, Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for sent := 0; sent < transfer; sent += len(buf) {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
		c.Close()
	}()

	// Let the window grow, then lose everything for longer than an RTO.
	time.Sleep(300 * time.Millisecond)
	drop.Store(true)
	time.Sleep(1500 * time.Millisecond)
	drop.Store(false)
	restored := time.Now()

	select {
	case n := <-got:
		if n != transfer {
			t.Fatalf("received %d bytes; want %d", n, transfer)
		}
		t.Logf("transfer finished %v after the link came back", time.Since(restored).Round(time.Millisecond))
	case <-time.After(20 * time.Second):
		t.Fatalf("transfer not finished 20s after the link came back")
	}
}
