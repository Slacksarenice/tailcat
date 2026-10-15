// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && !tailcat_ramptrace

package main

import "encoding/json"

// traceRTC does nothing outside the stress test's ramp-trace build (see
// ramptrace_js.go).
func traceRTC(*rtcSession) {}

// relayCandidate returns the remote candidate unchanged outside the
// stress test's ramp-trace build (see ramptrace_js.go).
func relayCandidate(_ *rtcSession, cand json.RawMessage) json.RawMessage { return cand }
