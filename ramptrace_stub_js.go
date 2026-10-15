// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_webrtc && !tailcat_ramptrace

package tailcat

// traceDERP does nothing outside the stress test's ramp-trace build (see
// ramptrace_js.go).
func traceDERP(*derpWebSocket) {}
