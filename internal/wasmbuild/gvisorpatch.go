// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wasmbuild

// gvisorEdits keep gVisor's TCP sender in RTO recovery once its
// retransmission timer has fired, rather than letting RACK start fast
// recovery on the ACKs that follow. RTO recovery resends the window from
// its first unacknowledged byte, skipping what was SACKed, in slow start.
// Fast recovery started from it resends only what lies before the next
// segment to send, which an RTO has just reset to the first, while its
// pipe counts every unSACKed segment not marked lost as in flight, so it
// sends nothing more until the next RTO. A window whose tail was lost
// (a burst loss, or a browser path ending with datagrams queued) then
// recovered a segment or two a second, for minutes, on any path. RFC
// 6582's guard against fast retransmit during RTO recovery, which gVisor
// applies to duplicate ACKs, is what these add to RACK's two entry
// points.
//
// The browser build alone needs them: it is where a WebRTC path's SCTP,
// or the end of one, loses a window at once.
var gvisorEdits = []moduleEdit{
	{
		// Loss that RACK detects on an ACK.
		file:   "pkg/tcpip/transport/tcp/snd.go",
		anchor: "if numLost := s.rc.detectLoss(rcvdSeg.rcvdTime); numLost > 0 && !s.FastRecovery.Active",
		text:   " && s.state != tcpip.RTORecovery",
	},
	{
		// Loss that RACK's reorder timer detects.
		file:   "pkg/tcpip/transport/tcp/rack.go",
		anchor: "\tif !rc.snd.FastRecovery.Active {\n\t\trc.snd.cc.HandleLossDetected()\n\t\trc.snd.enterRecovery()\n\t\tfastRetransmit = true\n\t}\n",
		text:   "\tif rc.snd.state == tcpip.RTORecovery {\n\t\treturn nil // see tailcat's internal/wasmbuild/gvisorpatch.go\n\t}\n",
		before: true,
	},
}
