// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"net"
	"strconv"

	"tailscale.com/tailcfg"
)

// derpProbeURL returns the URL of node's /derp/probe, on the port its
// DERP connections use: DERPPort when set, as derphttp's client dials
// it, else HTTPS's 443.
func derpProbeURL(node *tailcfg.DERPNode) string {
	host := node.HostName
	if node.DERPPort != 0 && node.DERPPort != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(node.DERPPort))
	}
	return "https://" + host + "/derp/probe"
}
