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

// tuneTCP adjusts ns's TCP for the browser.
func tuneTCP(logf logger.Logf, ns *netstack.Impl) {
	opt := tcpip.TCPMinRTOOption(browserMinRTO)
	if err := ns.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		logf("tailcat: setting TCP's minimum RTO: %v", err)
	}
}
