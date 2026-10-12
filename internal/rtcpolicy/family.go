// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rtcpolicy

import (
	"net/netip"
	"strings"
)

// CandidateFamily returns the address family of an ICE candidate line
// ("candidate:<foundation> <component> <transport> <priority> <address>
// <port> typ ..."; the "a=" of SDP is optional): "4" or "6", or "" if
// its address is no IP, as for a host candidate a browser hides behind
// an mDNS name.
//
// ICE pairs only candidates of one family, so a dual-stack browser
// offers both, and reaches a peer that has either one; a peer with only
// IPv4 and one with only IPv6 share no pair, and stay on the relay.
func CandidateFamily(line string) string {
	f := strings.Fields(strings.TrimPrefix(line, "a="))
	if len(f) < 5 || !strings.HasPrefix(f[0], "candidate:") {
		return ""
	}
	return AddrFamily(f[4])
}

// AddrFamily returns the family of the IP address s, "4" or "6", or ""
// if s is no IP address.
func AddrFamily(s string) string {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	switch {
	case err != nil:
		return ""
	case a.Unmap().Is4():
		return "4"
	}
	return "6"
}
