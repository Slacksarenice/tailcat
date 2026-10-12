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
//
// Its windows are tailscale's own: gVisor sizes each connection's
// buffers to it, the send buffer to twice its congestion window and the
// receive buffer to what it measures arriving per round trip, up to
// tailscale's 6 MiB (send) and 8 MiB (receive). So a connection's window
// grows as far as its path allows, and no further. That needs the
// browser's paths to tell TCP when they are full: neither a DataChannel's
// buffer nor a WebSocket's pushes back, and unbounded, either would hold
// whatever TCP has in flight. Each path drops a packet when its queue
// holds more than a few tens of milliseconds at the rate it drains
// (rtcpolicy.Shedder; web/webrtc_js.go, derpws_js.go), which TCP answers
// by slowing down, so the queues, and the round trips through them,
// stay short whatever the window. A build without them caps the windows
// instead (browserMaxWindow).
func tuneTCP(logf logger.Logf, ns *netstack.Impl) {
	opt := tcpip.TCPMinRTOOption(browserMinRTO)
	if err := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		logf("tailcat: setting TCP's minimum RTO: %v", err)
	}
	if browserMaxWindow == 0 {
		return
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
