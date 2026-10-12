// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestDERPProbeURL(t *testing.T) {
	for _, tt := range []struct {
		node tailcfg.DERPNode
		want string
	}{
		{tailcfg.DERPNode{HostName: "derp.example.com"}, "https://derp.example.com/derp/probe"},
		{tailcfg.DERPNode{HostName: "derp.example.com", DERPPort: 443}, "https://derp.example.com/derp/probe"},
		{tailcfg.DERPNode{HostName: "derp.example.com", DERPPort: 8443}, "https://derp.example.com:8443/derp/probe"},
		{tailcfg.DERPNode{HostName: "127.0.0.1", DERPPort: 57356}, "https://127.0.0.1:57356/derp/probe"},
		{tailcfg.DERPNode{HostName: "::1", DERPPort: 8443}, "https://[::1]:8443/derp/probe"},
	} {
		if got := derpProbeURL(&tt.node); got != tt.want {
			t.Errorf("derpProbeURL(%+v) = %q; want %q", tt.node, got, tt.want)
		}
	}
}
