// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_webrtc

package main

// WebRTC upgrade for browser-to-browser tunnels.
//
// Browsers can't open UDP sockets, so on its own the web app relays
// all of its WireGuard traffic through DERP. When both ends of a
// tunnel are this web app with WebRTC enabled, the dialing side opens
// a signaling stream to the listener's port 65534 inside the tunnel,
// and the two exchange an SDP offer, answer and ICE candidates over it
// to open an RTCPeerConnection with one unordered, unreliable
// DataChannel. Once the channel proves it carries full-sized
// datagrams in a round trip, each side installs it as the peer's
// tailcat.PacketPath, and the tunnel's WireGuard datagrams flow over it
// peer to peer instead of through DERP.
//
// The signaling stream runs inside the WireGuard tunnel, so only the
// two tunnel endpoints can take part, and the channel carries only
// WireGuard ciphertext, which each end authenticates as it would from
// DERP. If the channel stalls or closes, its path is withdrawn and the
// tunnel falls back to DERP without breaking connections in progress;
// the dialer then renegotiates with backoff.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// signalPreamble opens a signaling stream, from the dialer, and
	// signalAccept answers it. A peer that answers anything else (or
	// resets the connection, as a web server with WebRTC disabled
	// does) doesn't do WebRTC, and the tunnel stays on DERP.
	signalPreamble = "tailcat-webrtc/1\n"
	signalAccept   = "tailcat-webrtc/1 ok\n"

	signalTimeout   = 10 * time.Second // to dial and complete the preamble
	maxSignalLine   = 256 << 10
	dataChannelName = "tailcat-wg"

	// DataChannel frame types: the first byte of every message.
	frameWG        = 0 // a WireGuard datagram follows
	frameProbe     = 1 // u32 sequence, padded to probeSize
	frameProbeAck  = 2 // u32 sequence of the probe received
	framePing      = 3 // u32 sequence
	framePong      = 4 // u32 sequence of the ping received
	frameHeaderLen = 1

	// probeSize is the size of the qualification probes: larger than
	// any WireGuard datagram for the tunnel's 1280-byte MTU (1280 plus
	// 32 bytes of WireGuard overhead), so a path that drops large
	// messages never qualifies.
	probeSize     = 1400
	probesNeeded  = 2
	probeInterval = 250 * time.Millisecond
	probeTimeout  = 10 * time.Second

	pingInterval = 2 * time.Second
	// pingTimeout is how long a ping may go unanswered before the
	// channel is considered dead and traffic returns to DERP.
	pingTimeout = 10 * time.Second

	// maxBuffered is how much a DataChannel may hold unsent before
	// datagrams are dropped, as a full UDP socket would; inner TCP
	// then slows down.
	maxBuffered = 1 << 20
	maxFrame    = frameHeaderLen + 65535

	minRetry = 2 * time.Second
	maxRetry = 60 * time.Second
)

// rtcOptions is the parsed "webrtc" option of tailcatListen and
// tailcatDial: false/absent, true, or {iceServers: [...]}.
type rtcOptions struct {
	enabled    bool
	iceServers js.Value // a JS array, or undefined to use the DERP region's STUN servers
}

func parseRTCOptions(opts js.Value) rtcOptions {
	v := opts.Get("webrtc")
	switch v.Type() {
	case js.TypeBoolean:
		return rtcOptions{enabled: v.Bool(), iceServers: js.Undefined()}
	case js.TypeObject:
		return rtcOptions{enabled: true, iceServers: v.Get("iceServers")}
	}
	return rtcOptions{iceServers: js.Undefined()}
}

// iceServersFor returns o's ICE servers, defaulting to the STUN servers
// that DERP region reg's relays run.
func (o rtcOptions) iceServersFor(reg *tailcfg.DERPRegion) js.Value {
	if o.iceServers.Type() == js.TypeObject {
		return o.iceServers
	}
	var urls []any
	if reg != nil {
		for _, n := range reg.Nodes {
			if n.STUNPort < 0 || n.HostName == "" {
				continue
			}
			port := n.STUNPort
			if port == 0 {
				port = 3478
			}
			urls = append(urls, fmt.Sprintf("stun:%s:%d", n.HostName, port))
		}
	}
	if len(urls) == 0 {
		return js.ValueOf([]any{})
	}
	return js.ValueOf([]any{map[string]any{"urls": urls}})
}

// pathNotifier reports a peer's data path ("webrtc" or "derp") to the
// page's onPathChange callback, if any.
type pathNotifier func(peer key.NodePublic, path string)

func newPathNotifier(opts js.Value) pathNotifier {
	f := opts.Get("onPathChange")
	if f.Type() != js.TypeFunction {
		return func(key.NodePublic, string) {}
	}
	return func(peer key.NodePublic, path string) {
		f.Invoke(js.ValueOf(map[string]any{"peerKey": peer.String(), "path": path}))
	}
}

// awaitPromise blocks the calling goroutine (never a JS callback)
// until the JavaScript promise p settles.
func awaitPromise(p js.Value) (js.Value, error) {
	type result struct {
		v   js.Value
		err error
	}
	ch := make(chan result, 1)
	then := js.FuncOf(func(this js.Value, args []js.Value) any {
		v := js.Undefined()
		if len(args) > 0 {
			v = args[0]
		}
		ch <- result{v: v}
		return nil
	})
	catch := js.FuncOf(func(this js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 {
			msg = jsErrorString(args[0])
		}
		ch <- result{err: errors.New(msg)}
		return nil
	})
	defer then.Release()
	defer catch.Release()
	p.Call("then", then, catch)
	r := <-ch
	return r.v, r.err
}

func jsErrorString(v js.Value) string {
	if v.Type() == js.TypeObject && v.Get("message").Type() == js.TypeString {
		return v.Get("message").String()
	}
	return v.String()
}

// jsCall calls method on v, turning a thrown JavaScript exception into
// an error rather than a panic.
func jsCall(v js.Value, method string, args ...any) (ret js.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: %v", method, r)
		}
	}()
	return v.Call(method, args...), nil
}

// signalMsg is one line of the signaling stream after the preamble.
type signalMsg struct {
	T    string          `json:"t"` // "offer", "answer" or "cand"
	SDP  string          `json:"sdp,omitempty"`
	Cand json.RawMessage `json:"cand,omitempty"` // RTCIceCandidateInit
}

// rtcSession is one RTCPeerConnection to a peer and the packet path
// over its DataChannel. Its signaling stream lives as long as it does:
// closing either ends both.
type rtcSession struct {
	logf    logger.Logf
	peer    key.NodePublic
	notify  pathNotifier
	signal  net.Conn
	newPath func(send func([]byte) bool) (*tailcat.PacketPath, error)

	pc     js.Value
	funcs  []js.Func
	outc   chan []byte // signaling lines to write
	ctx    context.Context
	cancel context.CancelFunc

	// The fields below are only touched from JS callbacks and the
	// session's goroutines, which js/wasm runs one at a time, but mu
	// keeps them correct regardless.
	mu            sync.Mutex
	dc            js.Value
	path          *tailcat.PacketPath
	qualified     bool
	probeAcks     int
	pingSeq       uint32
	pingSentAt    time.Time // of the oldest unanswered ping; zero if none
	remoteSet     bool
	pendingCands  []json.RawMessage
	sendScratch   []byte
	sendBuf       js.Value // reusable Uint8Array for outgoing frames
	recvScratch   []byte
	everQualified bool
}

func newRTCSession(parent context.Context, logf logger.Logf, peer key.NodePublic, signal net.Conn, iceServers js.Value, notify pathNotifier,
	newPath func(send func([]byte) bool) (*tailcat.PacketPath, error)) (*rtcSession, error) {
	ctor := js.Global().Get("RTCPeerConnection")
	if ctor.Type() != js.TypeFunction {
		return nil, errors.New("this browser has no RTCPeerConnection")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &rtcSession{
		logf:        logf,
		peer:        peer,
		notify:      notify,
		signal:      signal,
		newPath:     newPath,
		outc:        make(chan []byte, 256),
		ctx:         ctx,
		cancel:      cancel,
		sendScratch: make([]byte, maxFrame),
		sendBuf:     js.Global().Get("Uint8Array").New(maxFrame),
		recvScratch: make([]byte, maxFrame),
		dc:          js.Undefined(),
	}
	pc, err := func() (pc js.Value, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("RTCPeerConnection: %v", r)
			}
		}()
		return ctor.New(map[string]any{"iceServers": iceServers}), nil
	}()
	if err != nil {
		cancel()
		return nil, err
	}
	s.pc = pc
	s.on(pc, "onicecandidate", func(ev js.Value) {
		c := ev.Get("candidate")
		if c.IsNull() || c.IsUndefined() {
			return
		}
		j := js.Global().Get("JSON").Call("stringify", c)
		s.sendSignal(signalMsg{T: "cand", Cand: json.RawMessage(j.String())})
	})
	s.on(pc, "onconnectionstatechange", func(js.Value) {
		switch st := pc.Get("connectionState").String(); st {
		case "failed", "closed":
			s.logf("webrtc: peer connection %s", st)
			go s.close()
		}
	})
	go s.writeLoop()
	go func() {
		<-ctx.Done()
		s.teardown()
	}()
	return s, nil
}

// on sets an event handler property, remembering it for release.
func (s *rtcSession) on(target js.Value, prop string, fn func(ev js.Value)) {
	f := js.FuncOf(func(this js.Value, args []js.Value) any {
		ev := js.Undefined()
		if len(args) > 0 {
			ev = args[0]
		}
		fn(ev)
		return nil
	})
	s.mu.Lock()
	s.funcs = append(s.funcs, f)
	s.mu.Unlock()
	target.Set(prop, f)
}

// sendSignal queues a signaling line without blocking, since it is
// called from JS callbacks.
func (s *rtcSession) sendSignal(m signalMsg) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	select {
	case s.outc <- append(b, '\n'):
	default:
		s.logf("webrtc: signaling queue full; dropping %q", m.T)
	}
}

func (s *rtcSession) writeLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case b := <-s.outc:
			if _, err := s.signal.Write(b); err != nil {
				s.close()
				return
			}
		}
	}
}

// readSignals handles signaling lines until the stream ends, then
// closes the session. answer is whether this side answers offers (the
// listener) rather than making them.
func (s *rtcSession) readSignals(br *bufio.Reader, answerer bool) {
	defer s.close()
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64<<10), maxSignalLine)
	for sc.Scan() {
		var m signalMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			s.logf("webrtc: bad signaling message: %v", err)
			return
		}
		if err := s.handleSignal(m, answerer); err != nil {
			s.logf("webrtc: %s: %v", m.T, err)
			return
		}
	}
}

func (s *rtcSession) handleSignal(m signalMsg, answerer bool) error {
	switch {
	case m.T == "offer" && answerer, m.T == "answer" && !answerer:
		desc := js.ValueOf(map[string]any{"type": m.T, "sdp": m.SDP})
		p, err := jsCall(s.pc, "setRemoteDescription", desc)
		if err != nil {
			return err
		}
		if _, err := awaitPromise(p); err != nil {
			return err
		}
		s.mu.Lock()
		s.remoteSet = true
		pending := s.pendingCands
		s.pendingCands = nil
		s.mu.Unlock()
		for _, c := range pending {
			s.addCandidate(c)
		}
		if answerer {
			p, err := jsCall(s.pc, "setLocalDescription")
			if err != nil {
				return err
			}
			if _, err := awaitPromise(p); err != nil {
				return err
			}
			s.sendSignal(signalMsg{T: "answer", SDP: s.pc.Get("localDescription").Get("sdp").String()})
		}
		return nil
	case m.T == "cand":
		s.mu.Lock()
		if !s.remoteSet {
			// Candidates can overtake the description they follow.
			s.pendingCands = append(s.pendingCands, m.Cand)
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		s.addCandidate(m.Cand)
		return nil
	}
	return fmt.Errorf("unexpected signaling message %q", m.T)
}

func (s *rtcSession) addCandidate(c json.RawMessage) {
	init, err := jsCall(js.Global().Get("JSON"), "parse", string(c))
	if err != nil {
		return
	}
	p, err := jsCall(s.pc, "addIceCandidate", init)
	if err != nil {
		return
	}
	if _, err := awaitPromise(p); err != nil {
		s.logf("webrtc: addIceCandidate: %v", err)
	}
}

// offer creates the DataChannel and sends an offer; the dialer calls it.
func (s *rtcSession) offer() error {
	dc, err := jsCall(s.pc, "createDataChannel", dataChannelName, map[string]any{
		"ordered": false,
		// SCTP splits datagrams larger than its path MTU into
		// fragments; a couple of retransmissions repair a lost
		// fragment without the head-of-line blocking of a reliable
		// channel. Inner TCP handles anything still lost.
		"maxRetransmits": 2,
	})
	if err != nil {
		return err
	}
	s.attachChannel(dc)
	p, err := jsCall(s.pc, "setLocalDescription")
	if err != nil {
		return err
	}
	if _, err := awaitPromise(p); err != nil {
		return err
	}
	s.sendSignal(signalMsg{T: "offer", SDP: s.pc.Get("localDescription").Get("sdp").String()})
	return nil
}

// acceptChannel waits for the dialer's DataChannel; the listener calls it.
func (s *rtcSession) acceptChannel() {
	s.on(s.pc, "ondatachannel", func(ev js.Value) {
		dc := ev.Get("channel")
		if dc.Get("label").String() != dataChannelName {
			dc.Call("close")
			return
		}
		s.attachChannel(dc)
	})
}

func (s *rtcSession) attachChannel(dc js.Value) {
	dc.Set("binaryType", "arraybuffer")
	s.mu.Lock()
	s.dc = dc
	s.mu.Unlock()
	s.on(dc, "onopen", func(js.Value) { go s.qualify() })
	s.on(dc, "onclose", func(js.Value) { go s.close() })
	s.on(dc, "onmessage", func(ev js.Value) { s.onMessage(ev.Get("data")) })
	if dc.Get("readyState").String() == "open" {
		go s.qualify()
	}
}

// sendFrame sends frame on the DataChannel. It reports false if the
// channel isn't open.
func (s *rtcSession) sendFrameLocked(frame []byte) bool {
	if s.dc.IsUndefined() || s.dc.Get("readyState").String() != "open" {
		return false
	}
	n := js.CopyBytesToJS(s.sendBuf, frame)
	_, err := jsCall(s.dc, "send", s.sendBuf.Call("subarray", 0, n))
	return err == nil
}

func (s *rtcSession) sendControl(typ byte, seq uint32, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.sendScratch[:max(size, frameHeaderLen+4)]
	clear(b)
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], seq)
	s.sendFrameLocked(b)
}

// sendWG is the PacketPath send function. Until the channel qualifies
// it declines, so datagrams keep using DERP.
func (s *rtcSession) sendWG(pkt []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.qualified || frameHeaderLen+len(pkt) > maxFrame {
		return false
	}
	if s.dc.Get("bufferedAmount").Int() > maxBuffered {
		return true // drop, like a full UDP socket
	}
	b := s.sendScratch[:frameHeaderLen+len(pkt)]
	b[0] = frameWG
	copy(b[frameHeaderLen:], pkt)
	if !s.sendFrameLocked(b) {
		s.qualified = false
		return false
	}
	return true
}

// onMessage handles a DataChannel message. It runs in a JS callback,
// so it must not block.
func (s *rtcSession) onMessage(data js.Value) {
	u8 := js.Global().Get("Uint8Array").New(data)
	n := u8.Get("length").Int()
	if n < frameHeaderLen || n > maxFrame {
		return
	}
	b := s.recvScratch[:n]
	js.CopyBytesToGo(b, u8)
	switch b[0] {
	case frameWG:
		s.mu.Lock()
		p := s.path
		s.mu.Unlock()
		if p != nil {
			p.Deliver(b[frameHeaderLen:])
		}
	case frameProbe, framePing:
		if n < frameHeaderLen+4 {
			return
		}
		reply := byte(frameProbeAck)
		if b[0] == framePing {
			reply = framePong
		}
		s.sendControl(reply, binary.BigEndian.Uint32(b[1:]), 0)
	case frameProbeAck:
		s.mu.Lock()
		s.probeAcks++
		s.mu.Unlock()
	case framePong:
		if n < frameHeaderLen+4 {
			return
		}
		s.mu.Lock()
		if binary.BigEndian.Uint32(b[1:]) == s.pingSeq {
			s.pingSentAt = time.Time{}
		}
		s.mu.Unlock()
	}
}

// qualify runs once the DataChannel opens: it installs the packet path
// (declining datagrams for now, but delivering any the peer sends),
// proves the channel round-trips full-sized messages, switches this
// side's sending to it, and then watches it with pings.
func (s *rtcSession) qualify() {
	s.mu.Lock()
	if s.path != nil {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	path, err := s.newPath(s.sendWG)
	if err != nil {
		s.logf("webrtc: NewPacketPath: %v", err)
		s.close()
		return
	}
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	deadline := time.Now().Add(probeTimeout)
	for seq := uint32(1); ; seq++ {
		s.mu.Lock()
		acks := s.probeAcks
		s.mu.Unlock()
		if acks >= probesNeeded {
			break
		}
		if time.Now().After(deadline) {
			s.logf("webrtc: channel to %v never carried full-sized probes; staying on DERP", s.peer.ShortString())
			s.close()
			return
		}
		s.sendControl(frameProbe, seq, probeSize)
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(probeInterval):
		}
	}
	s.mu.Lock()
	s.qualified = true
	s.everQualified = true
	s.mu.Unlock()
	s.logf("webrtc: direct path to %v up", s.peer.ShortString())
	s.notify(s.peer, "webrtc")
	s.watch()
}

// watch pings the peer over the channel until it stops answering or
// the session ends. A gap in its own ticks (a hidden tab's throttled
// timers) restarts the wait rather than counting against the peer.
func (s *rtcSession) watch() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			if now.Sub(last) > 3*pingInterval {
				s.pingSentAt = time.Time{} // we were asleep, not the peer
			}
			last = now
			if !s.pingSentAt.IsZero() && now.Sub(s.pingSentAt) > pingTimeout {
				s.mu.Unlock()
				s.logf("webrtc: direct path to %v stopped answering; falling back to DERP", s.peer.ShortString())
				s.close()
				return
			}
			s.pingSeq++
			seq := s.pingSeq
			if s.pingSentAt.IsZero() {
				s.pingSentAt = now
			}
			s.mu.Unlock()
			s.sendControl(framePing, seq, 0)
		}
	}
}

// close ends the session. It is idempotent.
func (s *rtcSession) close() { s.cancel() }

// teardown runs once, when the session's context ends.
func (s *rtcSession) teardown() {
	s.mu.Lock()
	path, wasUp := s.path, s.qualified
	s.path, s.qualified = nil, false
	dc := s.dc
	funcs := s.funcs
	s.funcs = nil
	s.mu.Unlock()
	if path != nil {
		path.Close()
	}
	if wasUp {
		s.notify(s.peer, "derp")
	}
	s.signal.Close()
	for _, target := range []js.Value{dc, s.pc} {
		if target.IsUndefined() {
			continue
		}
		for _, prop := range []string{"onopen", "onclose", "onmessage", "onicecandidate", "onconnectionstatechange", "ondatachannel"} {
			target.Set(prop, js.Null())
		}
		jsCall(target, "close")
	}
	for _, f := range funcs {
		f.Release()
	}
}

// rtcServer answers WebRTC signaling from the listener's clients.
type rtcServer struct {
	srv    *tailcat.Server
	opts   rtcOptions
	region *tailcfg.DERPRegion
	logf   logger.Logf
	notify pathNotifier
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	sessions map[key.NodePublic]*rtcSession
}

// newRTCServer returns srv's WebRTC signaling handler, or nil if the
// page didn't enable WebRTC.
func newRTCServer(srv *tailcat.Server, opts js.Value, region *tailcfg.DERPRegion, logf logger.Logf) *rtcServer {
	o := parseRTCOptions(opts)
	if !o.enabled {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &rtcServer{
		srv:      srv,
		opts:     o,
		region:   region,
		logf:     logf,
		notify:   newPathNotifier(opts),
		ctx:      ctx,
		cancel:   cancel,
		sessions: map[key.NodePublic]*rtcSession{},
	}
}

// handleSignal serves one signaling stream from a client.
func (r *rtcServer) handleSignal(c net.Conn) {
	peer, ok := r.srv.PeerKey(c.RemoteAddr())
	if !ok {
		c.Close()
		return
	}
	c.SetDeadline(time.Now().Add(signalTimeout))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || line != signalPreamble {
		c.Close()
		return
	}
	if _, err := io.WriteString(c, signalAccept); err != nil {
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})

	sess, err := newRTCSession(r.ctx, r.logf, peer, c, r.opts.iceServersFor(r.region), r.notify,
		func(send func([]byte) bool) (*tailcat.PacketPath, error) {
			return r.srv.NewPacketPath(peer, send)
		})
	if err != nil {
		r.logf("webrtc: %v", err)
		c.Close()
		return
	}
	r.mu.Lock()
	if old := r.sessions[peer]; old != nil {
		old.close() // the client renegotiated
	}
	r.sessions[peer] = sess
	r.mu.Unlock()
	sess.acceptChannel()
	sess.readSignals(br, true)
	<-sess.ctx.Done()
	r.mu.Lock()
	if r.sessions[peer] == sess {
		delete(r.sessions, peer)
	}
	r.mu.Unlock()
}

// disconnect ends any WebRTC session with peer.
func (r *rtcServer) disconnect(peer key.NodePublic) {
	r.mu.Lock()
	sess := r.sessions[peer]
	r.mu.Unlock()
	if sess != nil {
		sess.close()
	}
}

func (r *rtcServer) close() { r.cancel() }

// errNoWebRTCPeer means the server doesn't do WebRTC: it isn't this web
// app, or it is with WebRTC disabled.
var errNoWebRTCPeer = errors.New("peer doesn't support WebRTC")

// runRTCClient keeps a WebRTC session to cl's server for as long as
// ctx lasts, renegotiating with backoff when one fails, unless the
// server turns out not to support WebRTC.
func runRTCClient(ctx context.Context, cl *tailcat.Client, opts js.Value, logf logger.Logf) {
	o := parseRTCOptions(opts)
	if !o.enabled {
		return
	}
	peer, err := cl.ServerPublicKey()
	if err != nil {
		return
	}
	notify := newPathNotifier(opts)
	backoff := minRetry
	for ctx.Err() == nil {
		start := time.Now()
		err := rtcClientSession(ctx, cl, peer, o, notify, logf)
		if errors.Is(err, errNoWebRTCPeer) {
			logf("webrtc: %v; staying on DERP", err)
			return
		}
		if err != nil && ctx.Err() == nil {
			logf("webrtc: %v", err)
		}
		if time.Since(start) > 2*maxRetry {
			backoff = minRetry // the last session was healthy for a while
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxRetry)
	}
}

// rtcClientSession runs one WebRTC session to cl's server until it ends.
func rtcClientSession(ctx context.Context, cl *tailcat.Client, peer key.NodePublic, o rtcOptions, notify pathNotifier, logf logger.Logf) error {
	dctx, cancel := context.WithTimeout(ctx, signalTimeout)
	c, err := cl.DialTCPPort(dctx, webrtcSignalPort)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A refused or unanswered dial over a working tunnel means
		// the server doesn't serve signaling.
		return fmt.Errorf("%w (dialing signaling port: %v)", errNoWebRTCPeer, err)
	}
	// Any failure of the preamble exchange (a reset, an early close,
	// a reply that isn't ours, or no reply from, say, a native tailcat
	// server piping connections to its output) also means the server
	// doesn't do WebRTC. A WebRTC-capable web server answers at once;
	// retrying anything else would only repeat the preamble at it.
	c.SetDeadline(time.Now().Add(signalTimeout))
	br := bufio.NewReader(c)
	_, err = io.WriteString(c, signalPreamble)
	var line string
	if err == nil {
		line, err = br.ReadString('\n')
	}
	if err != nil || line != signalAccept {
		c.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errNoWebRTCPeer
	}
	c.SetDeadline(time.Time{})

	sess, err := newRTCSession(ctx, logf, peer, c, o.iceServersFor(cl.DERPRegion()), notify, cl.NewPacketPath)
	if err != nil {
		c.Close()
		return err
	}
	if err := sess.offer(); err != nil {
		sess.close()
		return fmt.Errorf("offer: %w", err)
	}
	go sess.readSignals(br, false)

	// Give up on a session whose channel never qualifies.
	go func() {
		select {
		case <-sess.ctx.Done():
		case <-time.After(signalTimeout + probeTimeout + 5*time.Second):
			sess.mu.Lock()
			up := sess.everQualified
			sess.mu.Unlock()
			if !up {
				logf("webrtc: no direct path to %v; staying on DERP for now", peer.ShortString())
				sess.close()
			}
		}
	}()
	<-sess.ctx.Done()
	return nil
}
