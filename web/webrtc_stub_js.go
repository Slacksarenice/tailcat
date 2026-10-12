// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && !tailcat_webrtc

package main

// Without the tailcat_webrtc build tag (which the dist build sets; see
// internal/wasmbuild), the web app relays everything over DERP and
// ignores the "webrtc" options.

import (
	"context"
	"net"
	"syscall/js"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type rtcServer struct{}

func newRTCServer(*tailcat.Server, js.Value, *tailcfg.DERPRegion, logger.Logf) *rtcServer {
	return nil
}

func (*rtcServer) handleSignal(c net.Conn)                                 { c.Close() }
func (*rtcServer) disconnect(key.NodePublic)                               {}
func (*rtcServer) close()                                                  {}
func runRTCClient(context.Context, *tailcat.Client, js.Value, logger.Logf) {}
func watchListenerNetwork(*tailcat.Server, *rtcServer) (stop func())       { return func() {} }
