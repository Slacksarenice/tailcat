// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rtcpolicy

import "testing"

func TestCandidateFamily(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{"candidate:2607957092 1 udp 1677729535 96.248.10.20 52318 typ srflx raddr 0.0.0.0 rport 0 generation 0", "4"},
		{"candidate:3915430039 1 udp 1677732095 2600:4040:15a5:1::7 52319 typ srflx raddr :: rport 0", "6"},
		{"a=candidate:1 1 udp 2113937151 192.168.1.5 52318 typ host", "4"},
		{"candidate:1 1 tcp 1518280447 fe80::1 9 typ host tcptype active", "6"},
		{"candidate:1 1 udp 2113937151 ::ffff:10.0.0.1 1 typ host", "4"},
		// A host candidate a browser hides behind an mDNS name.
		{"candidate:2071478094 1 udp 2113937151 6eb08ebb-55af-4285-a13a-1a01d547d79e.local 52318 typ host", ""},
		{"", ""},
		{"candidate:1 1 udp", ""},
		{"not a candidate at all, but five fields", ""},
	} {
		if got := CandidateFamily(tc.line); got != tc.want {
			t.Errorf("CandidateFamily(%q) = %q; want %q", tc.line, got, tc.want)
		}
	}
}

func TestAddrFamily(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":   "4",
		"2001:db8::1":   "6",
		"[2001:db8::1]": "6",
		"x.local":       "",
		"":              "",
	} {
		if got := AddrFamily(in); got != want {
			t.Errorf("AddrFamily(%q) = %q; want %q", in, got, want)
		}
	}
}
