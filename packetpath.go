// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailcat_webrtc

package tailcat

import (
	"errors"

	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// This file is compiled only with the tailcat_webrtc build tag, which
// requires building with the patched tailscale.com whose magicsock adds
// magicsock.PacketPath; see internal/wasmbuild. tailcat's browser
// build uses it to carry WireGuard traffic over WebRTC.

// PacketPath is an alternate transport for one peer's WireGuard
// datagrams, such as a WebRTC DataChannel between two browsers. While
// installed, it carries every datagram it accepts, and the rest take
// the ordinary direct UDP or DERP path, so closing it (or declining
// datagrams) falls back without disturbing connections in progress.
// The datagrams are WireGuard-encrypted and authenticated, so the
// transport needs no security of its own.
type PacketPath = magicsock.PacketPath

// NewPacketPath installs a packet path to the connected client with
// node key peer, replacing any previous one. See
// [magicsock.Conn.NewPacketPath] for the contract of send. Received
// datagrams are passed to the returned path's Deliver method.
//
// The caller must have bound the transport to peer through an
// authenticated channel, such as a TCP connection from that client
// (see [Server.PeerKey]).
func (s *Server) NewPacketPath(peer key.NodePublic, send func(pkt []byte) bool) (*PacketPath, error) {
	s.startMu.Lock()
	lb := s.lb
	s.startMu.Unlock()
	if lb == nil {
		return nil, errors.New("tailcat: NewPacketPath on a Server that isn't started")
	}
	return lb.sys.MagicSock.Get().NewPacketPath(peer, send), nil
}

// NewPacketPath installs a packet path to the client's server,
// replacing any previous one. See [Server.NewPacketPath]. The client
// must already be connected, by a successful Ping or Dial call.
func (c *Client) NewPacketPath(send func(pkt []byte) bool) (*PacketPath, error) {
	c.startMu.Lock()
	lb, started := c.lb, c.started
	c.startMu.Unlock()
	if !started {
		return nil, errors.New("tailcat: NewPacketPath on a Client that isn't connected")
	}
	return lb.sys.MagicSock.Get().NewPacketPath(lb.serverPub, send), nil
}

// ServerPublicKey returns the node key of the server the client
// connects to, which identifies it as the peer of the client's
// packet path.
func (c *Client) ServerPublicKey() (key.NodePublic, error) {
	ci, err := ParseAddr(c.Server)
	if err != nil {
		return key.NodePublic{}, err
	}
	return ci.ServerPublic.NodePublic, nil
}
