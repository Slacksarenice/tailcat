// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package tailcat

import (
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/netstack"
)

// tuneTCP keeps gVisor's TCP defaults outside the browser.
func tuneTCP(logf logger.Logf, ns *netstack.Impl) {}
