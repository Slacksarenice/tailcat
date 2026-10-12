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
// DERP.
//
// Each side pings the other over the channel. A few seconds without an
// answer (or ICE reporting the path disconnected) and it sends over
// DERP instead, still pinging; an answer moves traffic back. If the
// outage lasts, the dialer restarts ICE on the same connection, and if
// the path stays silent the session ends and the dialer negotiates a
// new one with backoff. None of this breaks connections in progress:
// WireGuard and the TCP inside it don't care which way a datagram goes.
// When the browser reports a network change, the tunnel checks its DERP
// connection and replaces it if the change left it dead, and each side
// checks the path while the dialer restarts ICE (or negotiates at
// once), rather than waiting for the old paths to time out.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat"
	"github.com/tailscale/tailcat/internal/rtcpolicy"
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
	// How long the oldest unanswered ping may wait before traffic moves
	// to DERP (suspectAfter), the dialer restarts ICE (restartAfter),
	// and the session ends (deadAfter). An answer before the end moves
	// traffic back. A gap of more than maxTickGap between pings means
	// this side's timers were throttled (a hidden tab), and isn't held
	// against the peer.
	suspectAfter = 4 * time.Second
	restartAfter = 6 * time.Second
	deadAfter    = 15 * time.Second
	maxTickGap   = 3 * pingInterval

	// maxBuffered is how much a DataChannel may hold unsent before
	// datagrams are dropped, as a full UDP socket would; inner TCP
	// then slows down. It is kept small because pings queue behind it.
	maxBuffered = 256 << 10
	maxFrame    = frameHeaderLen + 65535

	// qualifyTimeout is how long, from the start of signaling, a
	// session may take to qualify its channel before either side gives
	// up on it.
	qualifyTimeout = signalTimeout + probeTimeout + 5*time.Second
	// maxPendingCands caps the ICE candidates held while waiting for
	// the description they follow.
	maxPendingCands = 64
	// minSessionGap paces how often one peer may start a signaling
	// session with a listener; a client renegotiates no more often than
	// every minRetry. A stream that would wait longer than
	// maxSessionWait for its turn is refused.
	minSessionGap  = minRetry / 2
	maxSessionWait = 5 * time.Second

	// The dialer's wait between negotiations starts at minRetry and
	// doubles up to maxRetry, or up to maxRetryAfterUp once a path has
	// carried traffic on this connection (the two networks can reach
	// each other, so a lost path is worth winning back sooner). A path
	// that lasted healthyFor starts the wait over.
	minRetry        = 2 * time.Second
	maxRetry        = 60 * time.Second
	maxRetryAfterUp = 15 * time.Second
	healthyFor      = 30 * time.Second
	// maxDropped is how many signaling streams a server may drop
	// unanswered before the dialer stops asking, until it has answered
	// one.
	maxDropped = 3

	// minNetChangeGap is the least time between the network changes the
	// tunnels act on: a flapping network shouldn't reset them nonstop.
	minNetChangeGap = 5 * time.Second
)

var (
	jsArrayBuffer = js.Global().Get("ArrayBuffer")
	jsUint8Array  = js.Global().Get("Uint8Array")
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
			// JoinHostPort brackets an IPv6 literal.
			urls = append(urls, "stun:"+net.JoinHostPort(n.HostName, strconv.Itoa(port)))
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
		invokeSafely("onPathChange", f, map[string]any{"peerKey": peer.String(), "path": path})
	}
}

// awaitPromise blocks the calling goroutine (never a JS callback)
// until the JavaScript promise p settles or ctx ends. An
// RTCPeerConnection may leave its operations' promises pending forever
// once closed, so callers pass the session's context. The callbacks
// release themselves when the promise settles, so an abandoned one
// keeps only them alive, and only until then.
func awaitPromise(ctx context.Context, p js.Value) (js.Value, error) {
	type result struct {
		v   js.Value
		err error
	}
	ch := make(chan result, 1) // the promise settles at most once
	var then, catch js.Func
	settle := func(r result) {
		then.Release()
		catch.Release()
		ch <- r
	}
	then = js.FuncOf(func(this js.Value, args []js.Value) any {
		v := js.Undefined()
		if len(args) > 0 {
			v = args[0]
		}
		settle(result{v: v})
		return nil
	})
	catch = js.FuncOf(func(this js.Value, args []js.Value) any {
		msg := "promise rejected"
		if len(args) > 0 {
			msg = jsErrorString(args[0])
		}
		settle(result{err: errors.New(msg)})
		return nil
	})
	p.Call("then", then, catch)
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return js.Undefined(), ctx.Err()
	}
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
	offerer bool     // this side makes the offers (the dialer), and so restarts ICE
	hooks   js.Value // the page's tailcatTestHooks object, if it has one

	pc     js.Value
	funcs  []js.Func
	outc   chan []byte // signaling lines to write
	ctx    context.Context
	cancel context.CancelFunc

	// notifyMu orders the "webrtc" and "derp" path notifications, so
	// the page never hears them out of order.
	notifyMu sync.Mutex

	// mu guards the fields below, which JS callbacks and the session's
	// goroutines share.
	mu            sync.Mutex
	dc            js.Value
	path          *tailcat.PacketPath
	qualifying    bool // qualify has started
	qualified     bool
	probeAcks     int
	live          rtcpolicy.Liveness
	restarting    bool // an ICE restart's offer is being made
	remoteSet     bool
	pendingCands  []json.RawMessage
	holdCands     bool        // a local description is being made; hold its candidates
	heldCands     []signalMsg // and send them after it
	sendScratch   []byte
	sendBuf       js.Value // reusable Uint8Array for outgoing frames
	recvScratch   []byte   // used only by onMessage, a JS callback
	everQualified bool
}

func newRTCSession(parent context.Context, logf logger.Logf, peer key.NodePublic, signal net.Conn, iceServers js.Value, notify pathNotifier,
	newPath func(send func([]byte) bool) (*tailcat.PacketPath, error), offerer bool) (*rtcSession, error) {
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
		offerer:     offerer,
		hooks:       testHooks(),
		outc:        make(chan []byte, 256),
		ctx:         ctx,
		cancel:      cancel,
		sendScratch: make([]byte, maxFrame),
		sendBuf:     jsUint8Array.New(maxFrame),
		recvScratch: make([]byte, maxFrame),
		dc:          js.Undefined(),
		live: rtcpolicy.Liveness{
			SuspectAfter: suspectAfter,
			RestartAfter: restartAfter,
			DeadAfter:    deadAfter,
			MaxTickGap:   maxTickGap,
		},
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
		m := signalMsg{T: "cand", Cand: json.RawMessage(j.String())}
		s.mu.Lock()
		if s.holdCands {
			s.heldCands = append(s.heldCands, m)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		s.sendSignal(m)
	})
	s.on(pc, "onconnectionstatechange", func(js.Value) {
		st := pc.Get("connectionState").String()
		s.mu.Lock()
		up := s.qualified
		switch {
		case st == "disconnected" && up:
			// ICE lost the path, maybe for a moment: keep traffic off it
			// until a ping is answered again.
			s.live.MarkSuspect(time.Now())
			s.mu.Unlock()
			s.setHookState()
			return
		case st == "failed" && up:
			restart := s.offerer && s.live.TakeRestart(time.Now())
			s.mu.Unlock()
			s.setHookState()
			switch {
			case restart:
				go s.restartICE("ICE failed")
			case !s.offerer:
				// The dialer restarts ICE; if the path stays silent,
				// the pings end the session.
			default:
				s.logf("webrtc: peer connection failed again after an ICE restart")
				go s.close()
			}
			return
		}
		s.mu.Unlock()
		switch st {
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

// on sets an event handler property, remembering it for release. A
// panic in fn, which would otherwise end the program and every tunnel
// in it, ends just this session.
func (s *rtcSession) on(target js.Value, prop string, fn func(ev js.Value)) {
	f := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				s.logf("webrtc: %s handler: %v", prop, r)
				s.close()
			}
		}()
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
		if _, err := awaitPromise(s.ctx, p); err != nil {
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
			// The first offer or one restarting ICE: answer either.
			return s.describe()
		}
		s.countHook("answers")
		return nil
	case m.T == "cand":
		s.mu.Lock()
		if !s.remoteSet {
			// Candidates can overtake the description they follow.
			if len(s.pendingCands) >= maxPendingCands {
				s.mu.Unlock()
				return errors.New("too many candidates before the description")
			}
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
	if _, err := awaitPromise(s.ctx, p); err != nil && s.ctx.Err() == nil {
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
	return s.describe()
}

// describe sets the session's local description (an offer, or the
// answer to the remote one) and sends it. The ICE candidates gathered
// meanwhile are held and sent after it, so the peer never gets one
// before the description it belongs to. After an ICE restart, the peer
// already has a description, and would try a candidate of the
// restarted ICE that overtook its own against the old one.
func (s *rtcSession) describe() error {
	s.mu.Lock()
	s.holdCands = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		held := s.heldCands
		s.holdCands, s.heldCands = false, nil
		s.mu.Unlock()
		for _, m := range held {
			s.sendSignal(m)
		}
	}()
	p, err := jsCall(s.pc, "setLocalDescription")
	if err != nil {
		return err
	}
	if _, err := awaitPromise(s.ctx, p); err != nil {
		return err
	}
	desc := s.pc.Get("localDescription")
	s.sendSignal(signalMsg{T: desc.Get("type").String(), SDP: desc.Get("sdp").String()})
	return nil
}

// acceptChannel waits for the dialer's DataChannel; the listener calls
// it. A session carries one channel, so any others are closed.
func (s *rtcSession) acceptChannel() {
	s.on(s.pc, "ondatachannel", func(ev js.Value) {
		dc := ev.Get("channel")
		s.mu.Lock()
		taken := !s.dc.IsUndefined()
		s.mu.Unlock()
		if taken || dc.Get("label").String() != dataChannelName {
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

// sendWG is the PacketPath send function. Until the channel qualifies,
// and while it is suspect, it declines, so datagrams use DERP.
func (s *rtcSession) sendWG(pkt []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.qualified || s.live.Suspect() || frameHeaderLen+len(pkt) > maxFrame {
		return false
	}
	if s.dc.Get("bufferedAmount").Int() > maxBuffered {
		return true // drop, like a full UDP socket
	}
	b := s.sendScratch[:frameHeaderLen+len(pkt)]
	b[0] = frameWG
	copy(b[frameHeaderLen:], pkt)
	if !s.sendFrameLocked(b) {
		// The channel is gone; end the session, which withdraws the
		// path and tells the page, rather than leave it half up.
		s.qualified = false
		s.close()
		return false
	}
	return true
}

// onMessage handles a DataChannel message. It runs in a JS callback,
// so it must not block.
func (s *rtcSession) onMessage(data js.Value) {
	// binaryType governs only binary messages, and the peer can send
	// text too. Text must not reach the Uint8Array constructor, which
	// would read a numeric string as a length to allocate (or throw).
	if !data.InstanceOf(jsArrayBuffer) {
		return
	}
	n := data.Get("byteLength").Int()
	if n < frameHeaderLen || n > maxFrame {
		return
	}
	if s.hooks.Truthy() && s.hooks.Get("dropRTC").Truthy() {
		return // a test is simulating a path that carries nothing
	}
	b := s.recvScratch[:n]
	js.CopyBytesToGo(b, jsUint8Array.New(data))
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
		recovered := s.live.Pong(binary.BigEndian.Uint32(b[1:]))
		s.mu.Unlock()
		if recovered {
			s.logf("webrtc: direct path to %v answering again", s.peer.ShortString())
			s.setHookState()
		}
	}
}

// qualify runs once the DataChannel opens: it installs the packet path
// (declining datagrams for now, but delivering any the peer sends),
// proves the channel round-trips full-sized messages, switches this
// side's sending to it, and then watches it with pings.
func (s *rtcSession) qualify() {
	s.mu.Lock()
	if s.qualifying {
		s.mu.Unlock()
		return
	}
	s.qualifying = true
	s.mu.Unlock()
	path, err := s.newPath(s.sendWG)
	if err != nil {
		s.logf("webrtc: NewPacketPath: %v", err)
		s.close()
		return
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		// teardown has run or will find no path; don't leave this
		// one installed.
		s.mu.Unlock()
		path.Close()
		return
	}
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
	s.notifyMu.Lock()
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		s.notifyMu.Unlock()
		return
	}
	s.qualified = true
	s.everQualified = true
	s.mu.Unlock()
	s.logf("webrtc: direct path to %v up", s.peer.ShortString())
	s.notify(s.peer, "webrtc")
	s.notifyMu.Unlock()
	s.setHookState()
	s.watch()
}

// giveUpUnlessQualified ends the session if its channel hasn't
// qualified within qualifyTimeout.
func (s *rtcSession) giveUpUnlessQualified() {
	select {
	case <-s.ctx.Done():
	case <-time.After(qualifyTimeout):
		s.mu.Lock()
		up := s.everQualified
		s.mu.Unlock()
		if !up {
			s.logf("webrtc: no direct path to %v; staying on DERP for now", s.peer.ShortString())
			s.close()
		}
	}
}

// watch pings the peer over the channel until the session ends, moving
// traffic to DERP while the pings go unanswered, restarting ICE (on the
// dialer) if that lasts, and ending the session if it lasts longer
// still; see rtcpolicy.Liveness.
func (s *rtcSession) watch() {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			wasSuspect := s.live.Suspect()
			st, seq := s.live.Tick(now)
			s.mu.Unlock()
			switch st {
			case rtcpolicy.Dead:
				s.logf("webrtc: direct path to %v stopped answering; ending it", s.peer.ShortString())
				s.close()
				return
			case rtcpolicy.Restart:
				if s.offerer {
					go s.restartICE("pings unanswered")
				}
			}
			if !wasSuspect && st != rtcpolicy.Healthy {
				s.logf("webrtc: direct path to %v not answering; sending over DERP meanwhile", s.peer.ShortString())
				s.setHookState()
			}
			s.sendControl(framePing, seq, 0)
		}
	}
}

// restartICE makes a new offer that restarts ICE on the session's
// connection, keeping its DataChannel, as after the network changed
// under it. Only the offerer calls it; the answerer answers the new
// offer like the first. It does nothing while another offer is under
// way.
func (s *rtcSession) restartICE(why string) {
	s.mu.Lock()
	if s.restarting || !s.offerer {
		s.mu.Unlock()
		return
	}
	s.restarting = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.restarting = false
		s.mu.Unlock()
	}()
	if s.ctx.Err() != nil || s.pc.Get("signalingState").String() != "stable" {
		return
	}
	s.logf("webrtc: restarting ICE to %v (%s)", s.peer.ShortString(), why)
	s.countHook("iceRestarts")
	if _, err := jsCall(s.pc, "restartIce"); err != nil {
		s.logf("webrtc: %v", err)
		return
	}
	// Hold the answerer's candidates until its answer is set: they
	// belong to it, not to the description set now.
	s.mu.Lock()
	s.remoteSet = false
	s.mu.Unlock()
	if err := s.describe(); err != nil {
		if s.ctx.Err() == nil {
			s.logf("webrtc: ICE restart: %v", err)
		}
		s.close() // no offer went out; renegotiate from scratch
	}
}

// networkChanged checks the session's path at once, as the browser
// reported a network change that may have broken it: traffic goes over
// DERP until a ping sent now is answered, and the offerer restarts ICE,
// which finds a path over the new network sooner than the pings would
// notice the old one gone. It reports false if the session has no path
// to check: it is still negotiating, over the old network.
func (s *rtcSession) networkChanged() bool {
	s.mu.Lock()
	up := s.qualified
	var seq uint32
	if up {
		s.live.MarkSuspect(time.Now())
		seq = s.live.NextSeq()
	}
	s.mu.Unlock()
	if !up {
		return false
	}
	s.countHook("netChecks")
	s.setHookState()
	s.sendControl(framePing, seq, 0)
	if s.offerer {
		s.restartICE("network changed")
	}
	return true
}

// setHookState tells a test page (one with tailcatTestHooks) the path's
// state: "healthy", "suspect" or "down".
func (s *rtcSession) setHookState() {
	if !s.hooks.Truthy() {
		return
	}
	s.mu.Lock()
	st := "down"
	switch {
	case s.qualified && s.live.Suspect():
		st = "suspect"
	case s.qualified:
		st = "healthy"
	}
	s.mu.Unlock()
	s.hooks.Set("state", st)
}

// countHook adds one to the counter name on a test page's
// tailcatTestHooks: "answers" the offerer has applied, "iceRestarts" it
// has begun, and "netChecks", network changes a path was checked for.
func (s *rtcSession) countHook(name string) {
	if !s.hooks.Truthy() {
		return
	}
	n := 0
	if v := s.hooks.Get(name); v.Type() == js.TypeNumber {
		n = v.Int()
	}
	s.hooks.Set(name, n+1)
}

// testHooks returns the page's tailcatTestHooks object, which the tests'
// pages set to watch and steer the WebRTC path, or undefined.
func testHooks() js.Value {
	h := js.Global().Get("tailcatTestHooks")
	if h.Type() != js.TypeObject {
		return js.Undefined()
	}
	return h
}

// close ends the session. It is idempotent.
func (s *rtcSession) close() { s.cancel() }

// teardown runs once, when the session's context ends.
func (s *rtcSession) teardown() {
	s.notifyMu.Lock()
	s.mu.Lock()
	// The page heard "webrtc" if and only if the session ever
	// qualified, even if a failed send has since unqualified it.
	path, wasUp := s.path, s.everQualified
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
	s.notifyMu.Unlock()
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

	mu        sync.Mutex
	sessions  map[key.NodePublic]*rtcSession
	nextStart map[key.NodePublic]time.Time // earliest each peer's next session may start
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
		srv:       srv,
		opts:      o,
		region:    region,
		logf:      logf,
		notify:    newPathNotifier(opts),
		ctx:       ctx,
		cancel:    cancel,
		sessions:  map[key.NodePublic]*rtcSession{},
		nextStart: map[key.NodePublic]time.Time{},
	}
}

// waitTurn paces peer's signaling sessions to one per minSessionGap,
// since each builds an RTCPeerConnection. It reports false if the
// stream should be refused instead: its turn is too far off, or the
// server closed while it waited.
func (r *rtcServer) waitTurn(peer key.NodePublic) bool {
	now := time.Now()
	r.mu.Lock()
	for k, t := range r.nextStart {
		if t.Before(now) {
			delete(r.nextStart, k)
		}
	}
	start := now
	if t, ok := r.nextStart[peer]; ok && t.After(now) {
		start = t
	}
	wait := start.Sub(now)
	if wait > maxSessionWait {
		r.mu.Unlock()
		return false
	}
	r.nextStart[peer] = start.Add(minSessionGap)
	r.mu.Unlock()
	if wait == 0 {
		return true
	}
	select {
	case <-time.After(wait):
		return true
	case <-r.ctx.Done():
		return false
	}
}

// readPreambleLine reads one line of the preamble exchange. A line
// longer than br's buffer (bufio's default 4 KiB, far more than either
// preamble line) comes back cut short, to be rejected, rather than read
// without bound.
func readPreambleLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		err = nil
	}
	return string(line), err
}

// handleSignal serves one signaling stream from a client.
func (r *rtcServer) handleSignal(c net.Conn) {
	peer, ok := r.srv.PeerKey(c.RemoteAddr())
	if !ok || !r.waitTurn(peer) {
		c.Close()
		return
	}
	c.SetDeadline(time.Now().Add(signalTimeout))
	br := bufio.NewReader(c)
	line, err := readPreambleLine(br)
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
		}, false)
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
	go sess.giveUpUnlessQualified()
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

// networkChanged passes a network change on to every session.
func (r *rtcServer) networkChanged() {
	r.mu.Lock()
	sessions := make([]*rtcSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		go s.networkChanged()
	}
}

// watchListenerNetwork passes the browser's network changes on to a
// listener's tunnel, which checks its DERP connection, and to its WebRTC
// sessions (rtc may be nil), until the returned stop func is called.
func watchListenerNetwork(srv *tailcat.Server, rtc *rtcServer) (stop func()) {
	return onNetworkChange(func() {
		srv.NetworkChanged()
		if rtc != nil {
			rtc.networkChanged()
		}
	})
}

// netWatch passes the browser's reports that the network may have
// changed on to the tunnels that subscribe: the window's online event,
// and a change in navigator.connection's type, where the browser
// reports one (Chrome on Android, not on desktops). A report less than
// minNetChangeGap after the last is held until the gap has passed.
var netWatch struct {
	mu        sync.Mutex
	subs      map[*func()]struct{}
	listeners []func() // remove the page's event listeners
	connType  string
	last      time.Time
	timer     *time.Timer
}

// onNetworkChange calls f, on a goroutine of its own, whenever the
// browser reports that the network may have changed, until the returned
// stop func is called.
func onNetworkChange(f func()) (stop func()) {
	netWatch.mu.Lock()
	defer netWatch.mu.Unlock()
	if netWatch.subs == nil {
		netWatch.subs = map[*func()]struct{}{}
	}
	k := &f
	netWatch.subs[k] = struct{}{}
	if len(netWatch.subs) == 1 {
		addNetListenersLocked()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			netWatch.mu.Lock()
			defer netWatch.mu.Unlock()
			delete(netWatch.subs, k)
			if len(netWatch.subs) == 0 {
				for _, remove := range netWatch.listeners {
					remove()
				}
				netWatch.listeners = nil
			}
		})
	}
}

func addNetListenersLocked() {
	listen := func(target js.Value, event string, fn func()) {
		if target.Type() != js.TypeObject || target.Get("addEventListener").Type() != js.TypeFunction {
			return
		}
		f := js.FuncOf(func(js.Value, []js.Value) any {
			fn()
			return nil
		})
		target.Call("addEventListener", event, f)
		netWatch.listeners = append(netWatch.listeners, func() {
			target.Call("removeEventListener", event, f)
			f.Release()
		})
	}
	listen(js.Global(), "online", netChanged)
	nav := js.Global().Get("navigator")
	if nav.Type() != js.TypeObject {
		return
	}
	if conn := nav.Get("connection"); conn.Type() == js.TypeObject {
		connType := func() string {
			if t := conn.Get("type"); t.Type() == js.TypeString {
				return t.String()
			}
			return ""
		}
		netWatch.connType = connType()
		listen(conn, "change", func() {
			// The event also fires when the browser's bandwidth and
			// latency estimates change, which says nothing of the network.
			t := connType()
			netWatch.mu.Lock()
			changed := t != netWatch.connType
			netWatch.connType = t
			netWatch.mu.Unlock()
			if changed {
				netChanged()
			}
		})
	}
}

// netChanged tells every subscriber that the network may have changed,
// or holds the news until minNetChangeGap has passed since the last.
// It is called from JS event handlers, so it must not block.
func netChanged() {
	netWatch.mu.Lock()
	defer netWatch.mu.Unlock()
	if wait := time.Until(netWatch.last.Add(minNetChangeGap)); wait > 0 {
		if netWatch.timer == nil {
			netWatch.timer = time.AfterFunc(wait, func() {
				netWatch.mu.Lock()
				netWatch.timer = nil
				netWatch.mu.Unlock()
				netChanged()
			})
		}
		return
	}
	netWatch.last = time.Now()
	for f := range netWatch.subs {
		go (*f)()
	}
}

var (
	// errNoWebRTCPeer means the server answered signaling with
	// something other than this web app's reply.
	errNoWebRTCPeer = errors.New("peer doesn't support WebRTC")
	// errNoSignaling means the server didn't complete the signaling
	// preamble; rtcAttempt.failure says how.
	errNoSignaling = errors.New("peer didn't answer WebRTC signaling")
)

// rtcClient keeps a WebRTC session to a client's server; see
// runRTCClient.
type rtcClient struct {
	cl     *tailcat.Client
	peer   key.NodePublic
	opts   rtcOptions
	notify pathNotifier
	logf   logger.Logf
	hooks  js.Value      // the page's tailcatTestHooks object, if it has one
	wake   chan struct{} // a network change: negotiate now

	mu  sync.Mutex
	cur *rtcSession // the session under way, if any
}

// rtcAttempt is how one attempt at a session went.
type rtcAttempt struct {
	answered bool                    // the server completed the preamble
	up       bool                    // the session's path carried traffic
	failure  rtcpolicy.SignalFailure // if it didn't answer, how
	err      error
}

// runRTCClient keeps a WebRTC session to cl's server for as long as ctx
// lasts, negotiating a new one when one ends, with backoff, unless the
// server shows it doesn't do WebRTC before ever answering: it refuses
// the signaling port, accepts it but never answers the preamble, or
// answers it wrongly, or drops the stream unanswered maxDropped times
// in a row. A failure to reach it at all says nothing of the server, and
// is retried; so, once it has answered, is every failure but a wrong
// answer. Whether or not WebRTC is on, it passes the browser's network
// changes on to the tunnel until ctx ends.
func runRTCClient(ctx context.Context, cl *tailcat.Client, opts js.Value, logf logger.Logf) {
	c := &rtcClient{
		cl:     cl,
		opts:   parseRTCOptions(opts),
		notify: newPathNotifier(opts),
		logf:   logf,
		hooks:  testHooks(),
		wake:   make(chan struct{}, 1),
	}
	stop := onNetworkChange(c.networkChanged)
	defer stop()
	peer, err := cl.ServerPublicKey()
	if !c.opts.enabled || err != nil {
		<-ctx.Done()
		return
	}
	c.peer = peer
	backoff := rtcpolicy.Backoff{
		Min:        minRetry,
		Max:        maxRetry,
		MaxAfterUp: maxRetryAfterUp,
		HealthyFor: healthyFor,
	}
	answered, dropped := false, 0
	for {
		c.setHookState("negotiating")
		start := time.Now()
		a := c.attempt(ctx)
		if ctx.Err() != nil {
			return
		}
		answered = answered || a.answered
		var stopWhy string
		switch {
		case errors.Is(a.err, errNoWebRTCPeer):
			stopWhy = "wrong answer"
		case answered:
			dropped = 0
		case a.failure == rtcpolicy.Refused, a.failure == rtcpolicy.Silent:
			stopWhy = a.failure.String()
		case a.failure == rtcpolicy.Dropped:
			if dropped++; dropped >= maxDropped {
				stopWhy = a.failure.String()
			}
		}
		if stopWhy != "" {
			logf("webrtc: %v; staying on DERP", a.err)
			c.setHookState("stopped: " + stopWhy)
			<-ctx.Done() // still passing network changes on
			return
		}
		if a.err != nil {
			logf("webrtc: %v", a.err)
		}
		wait := backoff.Next(a.up, time.Since(start))
		c.setHookState("waiting")
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-c.wake:
			backoff.Reset()
		}
	}
}

// attempt runs one session to the server until it ends.
func (c *rtcClient) attempt(ctx context.Context) rtcAttempt {
	dctx, cancel := context.WithTimeout(ctx, signalTimeout)
	conn, err := c.cl.DialTCPPort(dctx, webrtcSignalPort)
	cancel()
	if err != nil {
		f := rtcpolicy.ClassifyDial(err)
		return rtcAttempt{failure: f, err: fmt.Errorf("%w (dialing signaling port, %v: %v)", errNoSignaling, f, err)}
	}
	// A WebRTC-capable web server answers the preamble at once, unless
	// it drops the stream (it is pacing its sessions, say). No reply at
	// all means it isn't one (a native tailcat server piping connections
	// to its output, say), and so does any other reply.
	conn.SetDeadline(time.Now().Add(signalTimeout))
	br := bufio.NewReader(conn)
	_, err = io.WriteString(conn, signalPreamble)
	var line string
	if err == nil {
		line, err = readPreambleLine(br)
	}
	if err != nil {
		conn.Close()
		f := rtcpolicy.ClassifyPreamble(err)
		return rtcAttempt{failure: f, err: fmt.Errorf("%w (preamble, %v: %v)", errNoSignaling, f, err)}
	}
	if line != signalAccept {
		conn.Close()
		return rtcAttempt{err: errNoWebRTCPeer}
	}
	conn.SetDeadline(time.Time{})

	sess, err := newRTCSession(ctx, c.logf, c.peer, conn, c.opts.iceServersFor(c.cl.DERPRegion()), c.notify, c.cl.NewPacketPath, true)
	if err != nil {
		conn.Close()
		return rtcAttempt{answered: true, err: err}
	}
	c.mu.Lock()
	c.cur = sess
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cur = nil
		c.mu.Unlock()
	}()
	if err := sess.offer(); err != nil {
		sess.close()
		return rtcAttempt{answered: true, err: fmt.Errorf("offer: %w", err)}
	}
	go sess.readSignals(br, false)
	go sess.giveUpUnlessQualified()
	<-sess.ctx.Done()
	sess.mu.Lock()
	up := sess.everQualified
	sess.mu.Unlock()
	return rtcAttempt{answered: true, up: up}
}

// networkChanged passes a network change on: the tunnel checks its DERP
// connection, and the session's path is checked at once. A session
// still negotiating, over the old network, starts over, and between
// sessions the next starts now.
func (c *rtcClient) networkChanged() {
	c.cl.NetworkChanged()
	c.mu.Lock()
	sess := c.cur
	c.mu.Unlock()
	if sess != nil && sess.networkChanged() {
		return
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	if sess != nil {
		sess.close()
	}
}

// setHookState tells a test page (one with tailcatTestHooks) what the
// client is doing: "negotiating", "waiting" or "stopped: <why>".
func (c *rtcClient) setHookState(st string) {
	if c.hooks.Truthy() {
		c.hooks.Set("client", st)
	}
}
