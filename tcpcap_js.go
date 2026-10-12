// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && !tailcat_webrtc

package tailcat

// browserMaxWindow caps the send and receive buffers of the tunnel's TCP
// connections in a browser build without tailcat_webrtc, and so what
// one can have in flight. Such a build relays everything over DERP
// through tailscale's own WebSocket, which has no backpressure and no
// shedding (derpws_js.go, which sheds, needs the build's tailscale
// patch), and the hop behind it is itself TCP, so it never drops for the
// tunnel's TCP to slow down. Uncapped, the window grows until the
// WebSocket holds seconds of data: a round trip over DERP read 1.4 s,
// and after a loss, 10 s. 2 MiB still covers what a relay carries out
// to a 150 ms round trip.
const browserMaxWindow = 2 << 20
