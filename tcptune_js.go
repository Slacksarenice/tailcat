// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package tailcat

import (
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/envknob"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/netstack"
)

// browserMinRTO is the shortest retransmission timeout of the tunnel's
// TCP connections in a browser: RFC 6298's one second, not gVisor's
// 200 ms. A page's ACKs wait on its main thread, which a download's
// writes or a hidden tab's throttling can hold for a few hundred
// milliseconds, so the round trip of a busy transfer jumps well past
// its smoothed value. At 200 ms that fires the timer though nothing was
// lost: TCP resends its whole window and starts again from one segment.
// Real loss is still repaired by SACK and RACK within a round trip; the
// timer is only the last resort.
const browserMinRTO = time.Second

// browserMaxWindow caps the send and receive buffers of the tunnel's TCP
// connections in a browser, and so what one can have in flight, below
// tailscale's 6 MiB (send) and 8 MiB (receive). A browser's paths queue
// whatever TCP gives them: a WebSocket to DERP has no backpressure, and
// the hop behind it is itself TCP, so it never drops for the tunnel's
// TCP to slow down. Its window grew until the WebSocket held seconds of
// data: a round trip over DERP read 1.4 s, and after a loss, 10 s, with
// a 33 s timeout. 2 MiB still covers what a browser can move (about
// 13 MB/s, on its one thread) out to a 150 ms round trip.
const browserMaxWindow = 2 << 20

// browserMTU is the tunnel's MTU in a browser, where tailscale's 1280
// costs most of a transfer's time. A browser's paths are a WebRTC
// DataChannel, whose SCTP splits a message into chunks itself, and a
// DERP WebSocket, which takes frames up to 64 KiB: neither has an IP
// path MTU to fit, so the tunnel's packets needn't be small. And in a
// browser nearly every cost is per packet, not per byte: Chrome's
// DataChannel delivers a few thousand messages a second whatever their
// size, and gVisor's TCP, WireGuard and every crossing between Go and
// JavaScript are paid packet by packet on the page's one thread. A
// 300 MB transfer between two Chromes on loopback took 19.4 s at 1280
// (15.5 MB/s), 7.4 s at 4096, 5.2 s at 9000 (58 MB/s), and 4.6 s at
// 32768: little more is won above 9000, while the memory a full queue
// holds and the chunks a lost message takes with it keep growing.
//
// A peer with a smaller MTU, a tailcat CLI's 1280 say, is unaffected:
// TCP sends it segments no larger than the MSS it announces.
const browserMTU = 9000

// tuneMTU sets the tunnel's MTU for the browser, unless TS_DEBUG_MTU
// sets one already. tailscale reads it (tstun.DefaultTUNMTU) as the
// engine and its netstack are created, so it runs before them.
func tuneMTU() {
	if _, ok := envknob.LookupUintSized("TS_DEBUG_MTU", 10, 32); !ok {
		envknob.Setenv("TS_DEBUG_MTU", strconv.Itoa(browserMTU))
	}
}

// tuneTCP adjusts ns's TCP for the browser.
func tuneTCP(logf logger.Logf, ns *netstack.Impl) {
	opt := tcpip.TCPMinRTOOption(browserMinRTO)
	if err := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		logf("tailcat: setting TCP's minimum RTO: %v", err)
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: browserMaxWindow}
	if err := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		logf("tailcat: setting TCP's send buffer sizes: %v", err)
	}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: browserMaxWindow}
	if err := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		logf("tailcat: setting TCP's receive buffer sizes: %v", err)
	}
}
