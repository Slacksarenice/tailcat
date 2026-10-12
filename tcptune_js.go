// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package tailcat

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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
