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
// DataChannel for the datagrams and a small reliable one for pings.
// The connection is data only: each side refuses a description with any
// media section but the one data section, and never adds a track, so
// no camera, microphone or media transport is ever involved. Once the
// datagrams' channel proves it carries full-sized datagrams in a round
// trip, each side installs it as the peer's tailcat.PacketPath, and the
// tunnel's WireGuard datagrams flow over it peer to peer instead of
// through DERP.
//
// The signaling stream runs inside the WireGuard tunnel, so only the
// two tunnel endpoints can take part, and the channel carries only
// WireGuard ciphertext, which each end authenticates as it would from
// DERP.
//
// Each side pings the other over the ping channel, which doesn't queue
// behind the datagrams. A few seconds without an answer (scaled to the
// measured round trip; datagrams arriving count as signs of life, but
// only an answer ends a suspicion), or ICE reporting the path
// disconnected, and it sends over DERP instead, still pinging; an
// answer moves traffic back, after a hold if the path keeps relapsing,
// so a flapping path settles on DERP. If the outage lasts, the dialer
// restarts ICE on the same connection (the listener asks it to when its
// own pings go unanswered), and if the path stays silent the session
// ends and the dialer negotiates a new one with backoff. None of this
// breaks connections in progress: WireGuard and the TCP inside it don't
// care which way a datagram goes. The page hears each move
// (onPathChange) and, if it asks, the path's stats (onPathStats).
// When the browser reports a network change, the tunnel checks its DERP
// connection and replaces it if the change left it dead, and each side
// checks the path while the dialer restarts ICE (or negotiates at
// once), rather than waiting for the old paths to time out.

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall/js"
	"time"
	"unsafe"

	"github.com/tailscale/tailcat"
	"github.com/tailscale/tailcat/internal/rtcpolicy"
	"tailscale.com/net/tstun"
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
	// ctlChannelName is a second, reliable DataChannel for the pings and
	// their answers, so they don't wait behind the datagrams queued on
	// the first: on a busy, slow uplink that queue holds seconds of
	// traffic, and pings stuck in it would make a working path look
	// dead. A peer that doesn't open or accept it has the pings share
	// the datagrams' channel instead.
	ctlChannelName = "tailcat-ctl"

	// DataChannel frame types: the first byte of every message.
	frameWG        = 0 // a WireGuard datagram follows
	frameProbe     = 1 // u32 sequence, padded to probeSize
	frameProbeAck  = 2 // u32 sequence of the probe received
	framePing      = 3 // u32 sequence
	framePong      = 4 // u32 sequence of the ping received
	frameHeaderLen = 1

	probesNeeded  = 2
	probeInterval = 250 * time.Millisecond
	probeTimeout  = 10 * time.Second

	pingInterval = 2 * time.Second
	// How long the oldest unanswered ping may wait before traffic moves
	// to DERP (suspectAfter, until a round trip is measured; then six
	// round trips plus a second, within minSuspectAfter and
	// maxSuspectAfter), the dialer restarts ICE (restartAfter, or two
	// seconds past suspicion), and the session ends (deadAfter). An
	// answer before the end moves traffic back. Datagrams arriving over
	// the path postpone suspicion. A gap of more than maxTickGap between
	// pings means this side's timers were throttled (a hidden tab), and
	// isn't held against the peer.
	suspectAfter    = 4 * time.Second
	minSuspectAfter = 3 * time.Second
	maxSuspectAfter = 8 * time.Second
	restartAfter    = 6 * time.Second
	deadAfter       = 15 * time.Second
	maxTickGap      = 3 * pingInterval
	// A path that goes quiet again within stableFor of recovering must
	// keep answering for a hold (minHold, doubling to maxHold) before
	// traffic returns to it, so a flapping path settles on DERP.
	minHold   = 5 * time.Second
	maxHold   = 30 * time.Second
	stableFor = 60 * time.Second
	// minPeerRestartGap paces the ICE restarts the answerer asks for.
	minPeerRestartGap = 5 * time.Second

	// Above shedTarget of queue in the DataChannel, at the rate it is
	// measured draining (within minBuffered and hardBuffered bytes, and
	// initBuffered until measured), one datagram is dropped every
	// shedEvery, which inner TCP answers by halving its window; above
	// hardBuffered, every datagram is (see rtcpolicy.Shedder).
	// hardBuffered is above the 6 MiB a tailscale netstack TCP
	// connection can have in flight, and well under the 16 MiB at which
	// Chrome closes a channel. Pings travel on the control channel, so
	// they don't wait behind the datagrams.
	shedTarget   = 20 * time.Millisecond
	minBuffered  = 64 << 10
	initBuffered = 256 << 10
	hardBuffered = 8 << 20
	shedEvery    = 100 * time.Millisecond
	maxFrame     = frameHeaderLen + 65535
	// maxBufferedAge is how old a bufferedAmount that a raw I/O send
	// returned may be before the Shedder's next decision reads it afresh.
	maxBufferedAge = time.Millisecond

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

// probeSize is the size of the qualification probes: larger than any
// WireGuard datagram for the tunnel's MTU (the MTU plus 32 bytes of
// WireGuard overhead; the wire MTU adds IP and UDP headers besides), so
// a path that drops large messages never qualifies. It is no larger
// than a frame can be, which a WireGuard datagram never exceeds.
func probeSize() int { return min(frameHeaderLen+int(tstun.DefaultWireMTU()), maxFrame) }

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

// pathStats is what a session reports to the page's onPathStats
// callback, every ping interval while it lasts:
//
//	{
//	  peerKey: string,
//	  path: "webrtc" | "derp", // where this side sends the tunnel's datagrams now
//	  rttMs: number,           // smoothed round trip of the pings; 0 until measured
//	  sentBytes: number,       // datagram bytes sent over the WebRTC path
//	  receivedBytes: number,   // and received over it
//	  dropped: number,         // datagrams dropped because the channel's buffer was full
//	  recvDropped: number,     // datagrams received but dropped because WireGuard was behind
//	  local: string,           // the selected ICE candidate pair's types ("host",
//	  remote: string,          // "srflx", "prflx" or "relay"), "" until known
//	  protocol: string,        // "udp" or "tcp", "" until known
//	  family: string,          // the pair's address family, "IPv4" or "IPv6"; "" until known
//	  iceRttMs?: number,       // the pair's round trip as ICE measures it, once it has
//	}
type pathStatsFunc func(m map[string]any)

func newPathStatsFunc(opts js.Value) pathStatsFunc {
	f := opts.Get("onPathStats")
	if f.Type() != js.TypeFunction {
		return nil
	}
	return func(m map[string]any) { invokeSafely("onPathStats", f, m) }
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
	// "offer", "answer" or "cand"; or "restart", from the answerer:
	// its pings go unanswered, so the offerer should restart ICE.
	T    string          `json:"t"`
	SDP  string          `json:"sdp,omitempty"`
	Cand json.RawMessage `json:"cand,omitempty"` // RTCIceCandidateInit
	// Caps, on an offer, lists what the offerer understands beyond the
	// messages above: capRestart if the answerer may send "restart". An
	// offerer that predates it ends the session on a message it doesn't
	// know, so the answerer sends one only to an offerer that lists it.
	Caps []string `json:"caps,omitempty"`
}

const capRestart = "restart"

// rtcSession is one RTCPeerConnection to a peer and the packet path
// over its DataChannel. Its signaling stream lives as long as it does:
// closing either ends both.
type rtcSession struct {
	logf    logger.Logf
	peer    key.NodePublic
	notify  pathNotifier
	stats   pathStatsFunc // nil if the page didn't ask for stats
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
	// the page never hears them out of order, and guards reported, the
	// last one it heard ("" for none).
	notifyMu sync.Mutex
	reported string
	// pair is the selected candidate pair as last read, reported again
	// when a read of the browser's stats fails or comes too late, rather
	// than blanking the page's view of the path for a report.
	pair selectedPair

	// mu guards the fields below, which JS callbacks and the session's
	// goroutines share.
	mu             sync.Mutex
	dc             js.Value
	ctl            js.Value // the control channel, while open; undefined otherwise
	ctlSeen        bool     // a control channel was attached: a session takes one
	path           *tailcat.PacketPath
	sentBytes      int64
	recvBytes      int64
	dropped        int64
	recvDropped    int64
	lastRestartAt  time.Time // when the last ICE restart began (offerer)
	lastRestartAsk time.Time // when this side last asked for one (answerer)
	peerRestarts   bool      // the offerer takes "restart" (answerer; see signalMsg.Caps)
	qualifying     bool      // qualify has started
	qualified      bool
	probeAcks      int
	live           rtcpolicy.Liveness
	shed           rtcpolicy.Shedder
	restarting     bool   // an ICE restart's offer is being made
	restartAgain   string // why to restart ICE again once the offer under way is answered
	remoteSet      bool
	pendingCands   []json.RawMessage
	holdCands      bool        // a local description is being made; hold its candidates
	heldCands      []signalMsg // and send them after it
	sendScratch    []byte
	sendBuf        js.Value // reusable Uint8Array for outgoing frames
	// dcRaw and ctlRaw are the channels' raw I/O handles (rawio_js.go),
	// or 0 to use syscall/js. dcBuffered is the datagrams' channel's
	// bufferedAmount as its last raw call returned it, at dcBufferedAt.
	dcRaw, ctlRaw  int32
	dcBuffered     int
	dcBufferedAt   time.Time
	recvScratch    []byte   // used only by onMessage, a JS callback
	everQualified  bool
	qualifiedAt    time.Time
}

func newRTCSession(parent context.Context, logf logger.Logf, peer key.NodePublic, signal net.Conn, iceServers js.Value, notify pathNotifier,
	stats pathStatsFunc, newPath func(send func([]byte) bool) (*tailcat.PacketPath, error), offerer bool) (*rtcSession, error) {
	ctor := peerConnectionCtor()
	if ctor.Type() != js.TypeFunction {
		return nil, errors.New("this browser has no RTCPeerConnection")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &rtcSession{
		logf:        logf,
		peer:        peer,
		notify:      notify,
		stats:       stats,
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
		ctl:         js.Undefined(),
		live: rtcpolicy.Liveness{
			SuspectAfter:    suspectAfter,
			MinSuspectAfter: minSuspectAfter,
			MaxSuspectAfter: maxSuspectAfter,
			RestartAfter:    restartAfter,
			DeadAfter:       deadAfter,
			MaxTickGap:      maxTickGap,
			MinHold:         minHold,
			MaxHold:         maxHold,
			StableFor:       stableFor,
		},
		shed: rtcpolicy.Shedder{
			Target:       shedTarget,
			MinLimit:     minBuffered,
			InitialLimit: initBuffered,
			HardLimit:    hardBuffered,
			Every:        shedEvery,
		},
	}
	pc, err := func() (pc js.Value, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("RTCPeerConnection: %v", r)
			}
		}()
		// One transport for everything, and no media: the session
		// negotiates a single data section (see rtcpolicy.CheckDataOnly).
		return ctor.New(map[string]any{
			"iceServers":    iceServers,
			"bundlePolicy":  "max-bundle",
			"rtcpMuxPolicy": "require",
		}), nil
	}()
	if err != nil {
		cancel()
		return nil, err
	}
	s.pc = pc
	s.on(pc, "ontrack", func(js.Value) {
		// No description that adds media is ever applied, so this can't
		// happen; if a browser ever did it, end the session.
		s.logf("webrtc: peer connection offered a media track; ending it")
		go s.close()
	})
	s.on(pc, "onicecandidate", func(ev js.Value) {
		c := ev.Get("candidate")
		if c.IsNull() || c.IsUndefined() {
			return
		}
		// Every candidate goes to the peer, of either address family:
		// ICE pairs only candidates of one family, so a dual-stack
		// browser's peer can have IPv4 only, or IPv6 only, and still
		// find a pair.
		if s.hooks.Truthy() {
			fam := rtcpolicy.CandidateFamily(c.Get("candidate").String())
			if s.hookDropsFamily(fam) {
				return
			}
			s.countHook("cands" + cmp.Or(fam, "Hidden"))
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
			go s.syncReport() // off this JS callback: it takes notifyMu
			return
		case st == "failed" && up:
			now := time.Now()
			restart, offerOut := false, false
			if s.offerer {
				restart = s.live.TakeRestart(now)
				offerOut = s.offerOutLocked()
			} else {
				s.live.MarkSuspect(now)
			}
			s.mu.Unlock()
			s.setHookState()
			go s.syncReport()
			switch {
			case restart:
				go s.restartICE("ICE failed", false)
			case !s.offerer:
				// Only the dialer can restart ICE: ask it to. If the
				// path stays silent, the pings end the session.
				s.askRestart("ICE failed")
			case offerOut:
				// The failure may be the old network's, under the
				// restart's offer; if that doesn't bring the path back,
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

// peerConnectionCtor returns the RTCPeerConnection constructor. A Worker
// has none: there it is worker.js's stand-in, tailcatPeerConnection,
// whose connections the page holds (tailcat.js) and whose DataChannels
// it hands to the Worker as it creates them, so that the tunnel's
// datagrams don't cross the page's thread.
func peerConnectionCtor() js.Value {
	if c := js.Global().Get("tailcatPeerConnection"); c.Type() == js.TypeFunction {
		return c
	}
	return js.Global().Get("RTCPeerConnection")
}

// createDataChannel creates a DataChannel on the session's peer
// connection. The stand-in of a Worker (see peerConnectionCtor) returns
// a Promise of it: the page creates the channel and hands it over.
func (s *rtcSession) createDataChannel(label string, opts map[string]any) (js.Value, error) {
	ch, err := jsCall(s.pc, "createDataChannel", label, opts)
	if err != nil || ch.Type() != js.TypeObject || ch.Get("then").Type() != js.TypeFunction {
		return ch, err
	}
	return awaitPromise(s.ctx, ch)
}

// on sets an event handler property, remembering it for release. A
// panic in fn, which would otherwise end the program and every tunnel
// in it, ends just this session.
func (s *rtcSession) on(target js.Value, prop string, fn func(ev js.Value)) {
	target.Set(prop, s.handler(prop, fn))
}

// handler returns a JS function that calls fn with its first argument,
// remembered for release; see on.
func (s *rtcSession) handler(name string, fn func(arg js.Value)) js.Func {
	f := js.FuncOf(func(this js.Value, args []js.Value) any {
		defer func() {
			if r := recover(); r != nil {
				s.logf("webrtc: %s handler: %v", name, r)
				s.close()
			}
		}()
		arg := js.Undefined()
		if len(args) > 0 {
			arg = args[0]
		}
		fn(arg)
		return nil
	})
	s.mu.Lock()
	s.funcs = append(s.funcs, f)
	s.mu.Unlock()
	return f
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
		if err := rtcpolicy.CheckDataOnly(m.SDP); err != nil {
			return err
		}
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
		if answerer {
			s.peerRestarts = slices.Contains(m.Caps, capRestart)
		}
		restarts := s.peerRestarts
		s.mu.Unlock()
		if answerer && s.hooks.Truthy() {
			s.hooks.Set("peerRestarts", restarts)
		}
		for _, c := range pending {
			s.addCandidate(c)
		}
		if answerer {
			// The first offer or one restarting ICE: answer either.
			return s.describe()
		}
		s.countHook("answers")
		s.mu.Lock()
		again := s.restartAgain
		s.restartAgain = ""
		s.mu.Unlock()
		if again != "" {
			go s.restartICE(again, false)
		}
		return nil
	case m.T == "cand":
		if s.hooks.Truthy() {
			var c struct{ Candidate string }
			if json.Unmarshal(m.Cand, &c) == nil && s.hookDropsFamily(rtcpolicy.CandidateFamily(c.Candidate)) {
				return nil
			}
		}
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
	case m.T == "restart" && !answerer:
		now := time.Now()
		s.mu.Lock()
		soon := now.Sub(s.lastRestartAt) < minPeerRestartGap
		up := s.qualified && s.ctx.Err() == nil
		if !soon && up {
			// The restart is this outage's, as for a network change:
			// traffic goes over DERP meanwhile, and this side's pings
			// don't start another restart on top of it.
			s.live.Restarted(now)
		}
		s.mu.Unlock()
		if !soon {
			if up {
				s.setHookState()
				go s.syncReport()
			}
			go s.restartICE("the peer's pings go unanswered", false)
		}
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

// offer creates the DataChannels and sends an offer; the dialer calls
// it.
func (s *rtcSession) offer() error {
	dc, err := s.createDataChannel(dataChannelName, map[string]any{
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
	// Reliable and ordered: a ping is tiny, and one lost is repaired
	// rather than counted against the path. "high" asks browsers that
	// weigh channels to send it ahead of the datagrams.
	if ctl, err := s.createDataChannel(ctlChannelName, map[string]any{
		"priority": "high",
	}); err == nil {
		s.attachControl(ctl)
	}
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
	sdp := desc.Get("sdp").String()
	if err := rtcpolicy.CheckDataOnly(sdp); err != nil {
		return fmt.Errorf("local description: %w", err)
	}
	if s.hooks.Truthy() {
		s.hooks.Set("localSDP", sdp)
	}
	m := signalMsg{T: desc.Get("type").String(), SDP: sdp}
	if s.offerer {
		m.Caps = []string{capRestart}
	}
	s.sendSignal(m)
	return nil
}

// acceptChannel waits for the dialer's DataChannels; the listener calls
// it. A session carries one of each kind, so any others are closed,
// including a control channel opened after the first one closed: each
// attached channel's handlers last as long as the session.
func (s *rtcSession) acceptChannel() {
	s.on(s.pc, "ondatachannel", func(ev js.Value) {
		dc := ev.Get("channel")
		s.mu.Lock()
		dataTaken, ctlTaken := !s.dc.IsUndefined(), s.ctlSeen
		s.mu.Unlock()
		switch label := dc.Get("label").String(); {
		case label == dataChannelName && !dataTaken:
			s.attachChannel(dc)
		case label == ctlChannelName && !ctlTaken:
			s.attachControl(dc)
		default:
			dc.Call("close")
		}
	})
}

func (s *rtcSession) attachChannel(dc js.Value) {
	dc.Set("binaryType", "arraybuffer")
	h := rawAttach(dc)
	s.mu.Lock()
	s.dc, s.dcRaw = dc, h
	s.mu.Unlock()
	s.on(dc, "onopen", func(js.Value) { go s.qualify() })
	s.on(dc, "onclose", func(js.Value) { go s.close() })
	s.onMessages(dc, h)
	if dc.Get("readyState").String() == "open" {
		go s.qualify()
	}
}

// attachControl attaches the control channel. Losing it doesn't end the
// session: the pings go over the datagrams' channel instead, for the
// rest of the session.
func (s *rtcSession) attachControl(ctl js.Value) {
	ctl.Set("binaryType", "arraybuffer")
	h := rawAttach(ctl)
	s.mu.Lock()
	s.ctl, s.ctlRaw = ctl, h
	s.ctlSeen = true
	s.mu.Unlock()
	s.onMessages(ctl, h)
	opened := func() {
		if s.hooks.Truthy() {
			s.hooks.Set("ctlOpen", true)
		}
	}
	s.on(ctl, "onopen", func(js.Value) { opened() })
	if isOpen(ctl) {
		opened()
	}
	s.on(ctl, "onclose", func(js.Value) {
		s.mu.Lock()
		if s.ctl.Equal(ctl) {
			s.ctl, s.ctlRaw = js.Undefined(), 0
		}
		s.mu.Unlock()
		rawDetach(h)
	})
}

func isOpen(ch js.Value) bool {
	return !ch.IsUndefined() && ch.Get("readyState").String() == "open"
}

// sendFrameLocked sends frame on channel ch, whose raw I/O handle is h
// (0 for none). It reports false if the channel isn't open.
func (s *rtcSession) sendFrameLocked(ch js.Value, h int32, frame []byte, now time.Time) bool {
	if h != 0 {
		r := rawSend(h, frame)
		if r < 0 {
			return false
		}
		if h == s.dcRaw {
			s.dcBuffered, s.dcBufferedAt = int(r), now
		}
		return true
	}
	if !isOpen(ch) {
		return false
	}
	n := js.CopyBytesToJS(s.sendBuf, frame)
	_, err := jsCall(ch, "send", s.sendBuf.Call("subarray", 0, n))
	return err == nil
}

// bufferedLocked returns the datagrams' channel's bufferedAmount. With
// raw I/O, that is what the last send returned, unless older than
// maxBufferedAge: the queue has only drained since, so the Shedder sees
// at most that long's drain more than is there.
func (s *rtcSession) bufferedLocked(now time.Time) int {
	if s.dcRaw == 0 {
		return s.dc.Get("bufferedAmount").Int()
	}
	if now.Sub(s.dcBufferedAt) > maxBufferedAge {
		s.refreshBufferedLocked(now)
	}
	return s.dcBuffered
}

// refreshBufferedLocked reads the datagrams' channel's bufferedAmount
// afresh, with raw I/O.
func (s *rtcSession) refreshBufferedLocked(now time.Time) {
	if r := rawSend(s.dcRaw, nil); r >= 0 {
		s.dcBuffered, s.dcBufferedAt = int(r), now
	}
}

// sendControl sends a probe, ping or answer. Probes and their answers
// go over the datagrams' channel, whose ability to carry full-sized
// messages they test; pings and theirs over the control channel while
// it is open.
func (s *rtcSession) sendControl(typ byte, seq uint32, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.sendScratch[:max(size, frameHeaderLen+4)]
	clear(b)
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], seq)
	ch, h := s.dc, s.dcRaw
	if (typ == framePing || typ == framePong) && isOpen(s.ctl) {
		ch, h = s.ctl, s.ctlRaw
	}
	s.sendFrameLocked(ch, h, b, time.Now())
}

// sendWG is the PacketPath send function. Until the channel qualifies,
// and while it is suspect, it declines, so datagrams use DERP.
func (s *rtcSession) sendWG(pkt []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.qualified || s.live.Suspect() || frameHeaderLen+len(pkt) > maxFrame {
		return false
	}
	now := time.Now()
	if s.shed.Drop(s.bufferedLocked(now), frameHeaderLen+len(pkt), now) {
		s.dropped++
		if s.dcRaw != 0 {
			// Nothing was sent to bring back the channel's bufferedAmount.
			s.refreshBufferedLocked(now)
		}
		return true // dropped: inner TCP slows down
	}
	b := s.sendScratch[:frameHeaderLen+len(pkt)]
	b[0] = frameWG
	copy(b[frameHeaderLen:], pkt)
	if !s.sendFrameLocked(s.dc, s.dcRaw, b, now) {
		// The channel is gone; end the session, which withdraws the
		// path and tells the page, rather than leave it half up.
		s.qualified = false
		s.close()
		return false
	}
	s.sentBytes += int64(len(pkt))
	return true
}

// onMessages handles channel ch's messages. With raw I/O (handle h),
// its onmessage is tailcatRawIO's: that copies each message into
// recvScratch and calls Go with its length, rather than Go reading the
// event through syscall/js, and hands Go the event only for what it
// can't take that way.
func (s *rtcSession) onMessages(ch js.Value, h int32) {
	slow := s.handler("onmessage", func(ev js.Value) { s.onMessage(ev.Get("data")) })
	var err error
	switch {
	case h == 0 || rawIOMode == "send":
		ch.Set("onmessage", slow)
		return
	case rawIOMode == "func":
		got := s.handler("raw onmessage", func(n js.Value) {
			if n := n.Int(); n >= frameHeaderLen && n <= len(s.recvScratch) {
				s.onFrame(s.recvScratch[:n], false)
			}
		})
		_, err = jsCall(rawIO, "recv", h, uintptr(unsafe.Pointer(unsafe.SliceData(s.recvScratch))), len(s.recvScratch), got, slow)
	default:
		in := &rawInbox{buf: make([]byte, rawInboxHeader+maxFrame), wake: make(chan struct{}, 1)}
		rawInboxes[h] = in
		go s.drain(in)
		_, err = jsCall(rawIO, "recvInbox", h, uintptr(unsafe.Pointer(unsafe.SliceData(in.buf))), maxFrame, slow)
	}
	if err != nil {
		ch.Set("onmessage", slow)
	}
}

// drain handles the messages tailcatRecv puts in inbox in (see
// rawInbox), until the session ends.
func (s *rtcSession) drain(in *rawInbox) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("webrtc: raw onmessage: %v", r)
			s.close()
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-in.wake:
		}
		if n := int(binary.LittleEndian.Uint32(in.buf)); n >= frameHeaderLen {
			s.onFrame(in.buf[rawInboxHeader:rawInboxHeader+n], false)
		}
		binary.LittleEndian.PutUint32(in.buf, 0)
	}
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
	s.onFrame(b, true)
}

// onFrame handles frame b, a message received. delayHook is whether the
// test hook delayMs may apply; raw I/O hands messages it would delay to
// onMessage instead. It runs in a JS callback, so it must not block.
func (s *rtcSession) onFrame(b []byte, delayHook bool) {
	n := len(b)
	switch b[0] {
	case frameWG:
		s.mu.Lock()
		p := s.path
		s.recvBytes += int64(n - frameHeaderLen)
		s.live.Heard(time.Now())
		s.mu.Unlock()
		if p != nil && delayHook && s.hooks.Truthy() {
			// A test simulating a longer path: hold each datagram
			// delayMs before WireGuard sees it. Only the tunnel's TCP
			// sees the longer round trip; the DataChannel's SCTP, and
			// the pings, see the real one.
			if d := s.hooks.Get("delayMs"); d.Type() == js.TypeNumber && d.Float() > 0 {
				pkt := append([]byte(nil), b[frameHeaderLen:]...)
				time.AfterFunc(time.Duration(d.Float()*float64(time.Millisecond)), func() {
					if !p.Deliver(pkt) {
						s.mu.Lock()
						s.recvDropped++
						s.mu.Unlock()
					}
				})
				return
			}
		}
		if p != nil && !p.Deliver(b[frameHeaderLen:]) {
			s.mu.Lock()
			s.recvDropped++
			s.mu.Unlock()
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
		recovered := s.live.Pong(binary.BigEndian.Uint32(b[1:]), time.Now())
		s.mu.Unlock()
		if recovered {
			s.logf("webrtc: direct path to %v answering again", s.peer.ShortString())
			s.setHookState()
			go s.syncReport() // off this JS callback: it takes notifyMu
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
		s.sendControl(frameProbe, seq, probeSize())
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(probeInterval):
		}
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.qualified = true
	s.everQualified = true
	s.qualifiedAt = time.Now()
	s.mu.Unlock()
	s.logf("webrtc: direct path to %v up", s.peer.ShortString())
	s.countHook("qualified")
	s.syncReport()
	s.setHookState()
	s.watch()
}

// syncReport tells the page where this side now sends the tunnel's
// datagrams, if that changed since it last heard: "webrtc" while the
// path carries them, "derp" while it is suspect and once the session
// ends. Before the path first carries anything, the page has heard
// nothing, which means DERP. It is safe to call from any goroutine, any
// number of times, in any order: it reports the state at the time.
func (s *rtcSession) syncReport() {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	s.mu.Lock()
	want := "derp"
	if s.qualified && !s.live.Suspect() && s.ctx.Err() == nil {
		want = "webrtc"
	}
	s.mu.Unlock()
	if want == s.reported || (want == "derp" && s.reported == "") {
		return
	}
	s.reported = want
	s.notify(s.peer, want)
}

// reportStats passes the session's stats to the page, if it asked for
// them. It reads the selected ICE candidate pair from the browser, so it
// runs on a goroutine of its own.
func (s *rtcSession) reportStats() {
	if s.stats == nil {
		return
	}
	pair, ok := s.readSelectedPair()
	s.mu.Lock()
	switch {
	case !ok:
		// The browser's stats failed or came too late: the pair is as
		// last read, rather than gone for a report.
		pair = s.pair
	case pair.rtt < 0 && pair.id == s.pair.id:
		pair.rtt = s.pair.rtt
	}
	s.pair = pair
	path := "derp"
	if s.qualified && !s.live.Suspect() {
		path = "webrtc"
	}
	m := map[string]any{
		"peerKey":       s.peer.String(),
		"path":          path,
		"rttMs":         float64(s.live.RTT()) / float64(time.Millisecond),
		"sentBytes":     float64(s.sentBytes),
		"receivedBytes": float64(s.recvBytes),
		"dropped":       float64(s.dropped),
		"recvDropped":   float64(s.recvDropped),
		"local":         pair.local,
		"remote":        pair.remote,
		"protocol":      pair.proto,
		"family":        pair.family,
	}
	if pair.id != "" && pair.rtt >= 0 {
		m["iceRttMs"] = float64(pair.rtt) / float64(time.Millisecond)
	}
	s.mu.Unlock()
	if s.ctx.Err() == nil {
		s.stats(m)
	}
}

// selectedPair is what a session reports of its selected ICE candidate
// pair.
type selectedPair struct {
	id string // the pair's stats id; "" if there is none yet
	// local and remote are the candidates' types ("host", "srflx",
	// "prflx" or "relay"), and proto the local one's protocol ("udp"
	// or "tcp").
	local, remote, proto string
	// family is the pair's address family, "IPv4" or "IPv6": ICE pairs
	// only candidates of one family. "" if the browser hides it.
	family string
	// rtt is the pair's round trip as ICE measures it, -1 if unknown:
	// the network's own, timed by the browser off the page's thread,
	// where the pings' (rttMs) include the time each side's page took
	// to answer, and the queue a busy transfer builds ahead of them.
	rtt time.Duration
}

// readSelectedPair reads the selected ICE candidate pair from the peer
// connection's stats: the zero pair, with an rtt of -1, if there is
// none yet. It reports false if the stats could not be read in time.
func (s *rtcSession) readSelectedPair() (pair selectedPair, ok bool) {
	pair.rtt = -1
	p, err := jsCall(s.pc, "getStats")
	if err != nil {
		return pair, false
	}
	ctx, cancel := context.WithTimeout(s.ctx, pingInterval)
	defer cancel()
	report, err := awaitPromise(ctx, p)
	if err != nil {
		return pair, false
	}
	byID := map[string]js.Value{}
	var pairID string
	each := js.FuncOf(func(this js.Value, args []js.Value) any {
		st := args[0]
		id := st.Get("id").String()
		byID[id] = st
		switch st.Get("type").String() {
		case "transport":
			if v := st.Get("selectedCandidatePairId"); v.Type() == js.TypeString {
				pairID = v.String()
			}
		case "candidate-pair":
			// Firefox has no transport stats; it marks the pair.
			if pairID == "" && st.Get("selected").Truthy() {
				pairID = id
			}
		}
		return nil
	})
	_, err = jsCall(report, "forEach", each)
	each.Release()
	if err != nil {
		return pair, false
	}
	st, found := byID[pairID]
	if !found {
		return pair, true
	}
	pair.id = pairID
	str := func(v js.Value, prop string) string {
		if p := v.Get(prop); p.Type() == js.TypeString {
			return p.String()
		}
		return ""
	}
	// A candidate's address: "address", or "ip" in older browsers. A
	// remote host candidate's may be an mDNS name, which has no family;
	// the local candidate's is the browser's own.
	family := func(c js.Value) string {
		switch rtcpolicy.AddrFamily(cmp.Or(str(c, "address"), str(c, "ip"))) {
		case "4":
			return "IPv4"
		case "6":
			return "IPv6"
		}
		return ""
	}
	if c, ok := byID[str(st, "localCandidateId")]; ok {
		pair.local, pair.proto, pair.family = str(c, "candidateType"), str(c, "protocol"), family(c)
	}
	if c, ok := byID[str(st, "remoteCandidateId")]; ok {
		pair.remote = str(c, "candidateType")
		if pair.family == "" {
			pair.family = family(c)
		}
	}
	if v := st.Get("currentRoundTripTime"); v.Type() == js.TypeNumber {
		pair.rtt = time.Duration(v.Float() * float64(time.Second))
	}
	return pair, true
}

// askRestart asks the offerer to restart ICE, as only it can, at most
// once per minPeerRestartGap, if the offerer said it understands the
// request.
func (s *rtcSession) askRestart(why string) {
	s.mu.Lock()
	soon := !s.peerRestarts || time.Since(s.lastRestartAsk) < minPeerRestartGap
	if !soon {
		s.lastRestartAsk = time.Now()
	}
	s.mu.Unlock()
	if soon {
		return
	}
	s.logf("webrtc: asking %v to restart ICE (%s)", s.peer.ShortString(), why)
	s.countHook("restartAsks")
	s.sendSignal(signalMsg{T: "restart"})
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
		case <-t.C:
			// Not the tick's own time, which is when it was due: a tick
			// the browser held back would then hide the gap from Tick and
			// date this ping's round trip from before it was sent.
			now := time.Now()
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
					go s.restartICE("pings unanswered", false)
				} else {
					s.askRestart("pings unanswered")
				}
			}
			switch {
			case !wasSuspect && st != rtcpolicy.Healthy:
				s.logf("webrtc: direct path to %v not answering; sending over DERP meanwhile", s.peer.ShortString())
				s.setHookState()
				s.syncReport()
			case wasSuspect && st == rtcpolicy.Healthy:
				// A recovery that waited out its hold.
				s.logf("webrtc: direct path to %v answering steadily again", s.peer.ShortString())
				s.setHookState()
				s.syncReport()
			}
			s.sendControl(framePing, seq, 0)
			go s.reportStats()
		}
	}
}

// restartICE makes a new offer that restarts ICE on the session's
// connection, keeping its DataChannel, as after the network changed
// under it. Only the offerer calls it; the answerer answers the new
// offer like the first. While another offer is under way it does
// nothing, unless renew is set, as for a network change: that offer's
// candidates may be the old network's, so ICE restarts again once it is
// answered.
func (s *rtcSession) restartICE(why string, renew bool) {
	if !s.offerer {
		return
	}
	s.mu.Lock()
	if s.offerOutLocked() {
		if renew {
			s.restartAgain = why
		}
		s.mu.Unlock()
		return
	}
	s.restarting = true
	s.lastRestartAt = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.restarting = false
		s.mu.Unlock()
	}()
	if s.ctx.Err() != nil {
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

// offerOutLocked reports whether an offer of this side's is under way:
// being made, or waiting for its answer.
func (s *rtcSession) offerOutLocked() bool {
	return s.restarting || s.pc.Get("signalingState").String() != "stable"
}

// networkChanged checks the session's path at once, as the browser
// reported a network change that may have broken it: traffic goes over
// DERP until a ping sent now is answered, and the offerer restarts ICE,
// which finds a path over the new network sooner than the pings would
// notice the old one gone. That restart is the outage's, so the pings
// don't start another over it. It reports false if the session has no
// path to check: it is still negotiating, over the old network, or it is
// ending.
func (s *rtcSession) networkChanged() bool {
	now := time.Now()
	s.mu.Lock()
	up := s.qualified && s.ctx.Err() == nil
	var seq uint32
	if up {
		if s.offerer {
			s.live.Restarted(now)
		} else {
			s.live.MarkSuspect(now)
		}
		seq = s.live.NextSeq()
	}
	s.mu.Unlock()
	if !up {
		return false
	}
	s.countHook("netChecks")
	s.setHookState()
	go s.syncReport()
	s.sendControl(framePing, seq, 0)
	if s.offerer {
		s.restartICE("network changed", true)
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

// hookDropsFamily reports whether a test page that has only one address
// family (tailcatTestHooks.family, "4" or "6") drops a candidate of
// family fam: it neither sends its own of the other family nor takes
// the peer's, so neither side ever tries a pair of it, as between a
// host that has that family and one that hasn't.
func (s *rtcSession) hookDropsFamily(fam string) bool {
	if !s.hooks.Truthy() || fam == "" {
		return false
	}
	only := s.hooks.Get("family")
	return only.Type() == js.TypeString && only.String() != "" && only.String() != fam
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
	s.mu.Lock()
	path := s.path
	s.path, s.qualified = nil, false
	dc, ctl := s.dc, s.ctl
	dcRaw, ctlRaw := s.dcRaw, s.ctlRaw
	s.dcRaw, s.ctlRaw = 0, 0
	funcs := s.funcs
	s.funcs = nil
	s.mu.Unlock()
	rawDetach(dcRaw)
	rawDetach(ctlRaw)
	if path != nil {
		path.Close()
	}
	s.syncReport() // "derp", if the page heard "webrtc"
	s.signal.Close()
	for _, target := range []js.Value{dc, ctl, s.pc} {
		if target.IsUndefined() {
			continue
		}
		for _, prop := range []string{"onopen", "onclose", "onmessage", "onicecandidate", "onconnectionstatechange", "ondatachannel", "ontrack"} {
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
	stats  pathStatsFunc
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
		stats:     newPathStatsFunc(opts),
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

	sess, err := newRTCSession(r.ctx, r.logf, peer, c, r.opts.iceServersFor(r.region), r.notify, r.stats,
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

// networkChanged passes a network change on to every session. One still
// negotiating, over the old network, ends, and its client negotiates
// again.
func (r *rtcServer) networkChanged() {
	r.mu.Lock()
	sessions := make([]*rtcSession, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		go func() {
			if !s.networkChanged() {
				s.close()
			}
		}()
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
// changed on to the tunnels that subscribe: the page's online event,
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
	target, nav := js.Global(), js.Global().Get("navigator")
	if fwd := js.Global().Get("tailcatNetwork"); fwd.Type() == js.TypeObject {
		// In a Worker (worker.js): the page's online events and its
		// navigator.connection's changes, which tailcat.js forwards. The
		// Worker's own would report each change a second time.
		target, nav = fwd, fwd
	}
	listen(target, "online", netChanged)
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
	stats  pathStatsFunc
	logf   logger.Logf
	hooks  js.Value      // the page's tailcatTestHooks object, if it has one
	wake   chan struct{} // a network change: negotiate now

	mu    sync.Mutex
	cur   *rtcSession        // the session under way, if any
	abort context.CancelFunc // ends the attempt under way, if any
}

// rtcAttempt is how one attempt at a session went.
type rtcAttempt struct {
	answered bool                    // the server completed the preamble
	up       bool                    // the session's path carried traffic
	lasted   time.Duration           // if up, for how long, from when it came up
	failure  rtcpolicy.SignalFailure // if it didn't answer, how
	err      error
}

// errNetChanged means a network change ended an attempt before its
// session was under way, as it was negotiating over the old network.
var errNetChanged = errors.New("network changed during signaling; starting over")

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
		stats:  newPathStatsFunc(opts),
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
		wait := backoff.Next(a.up, a.lasted)
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

// attempt runs one session to the server until it ends. A network
// change before the session has a path ends it (see networkChanged):
// signaling and ICE under way are the old network's.
func (c *rtcClient) attempt(ctx context.Context) rtcAttempt {
	actx, abort := context.WithCancel(ctx)
	defer abort()
	c.mu.Lock()
	c.abort = abort
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cur, c.abort = nil, nil
		c.mu.Unlock()
	}()
	// A network change, rather than the server, ended the signaling:
	// that says nothing of the server.
	netChanged := func() bool { return actx.Err() != nil && ctx.Err() == nil }

	dctx, cancel := context.WithTimeout(actx, signalTimeout)
	conn, err := c.cl.DialTCPPort(dctx, webrtcSignalPort)
	cancel()
	if err != nil {
		if netChanged() {
			return rtcAttempt{err: errNetChanged}
		}
		f := rtcpolicy.ClassifyDial(err)
		return rtcAttempt{failure: f, err: fmt.Errorf("%w (dialing signaling port, %v: %v)", errNoSignaling, f, err)}
	}
	// A WebRTC-capable web server answers the preamble at once, unless
	// it drops the stream (it is pacing its sessions, say). No reply at
	// all means it isn't one (a native tailcat server piping connections
	// to its output, say), and so does any other reply.
	stopAbort := context.AfterFunc(actx, func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(signalTimeout))
	br := bufio.NewReader(conn)
	_, err = io.WriteString(conn, signalPreamble)
	var line string
	if err == nil {
		line, err = readPreambleLine(br)
	}
	if err != nil {
		conn.Close()
		if netChanged() {
			return rtcAttempt{err: errNetChanged}
		}
		f := rtcpolicy.ClassifyPreamble(err)
		return rtcAttempt{failure: f, err: fmt.Errorf("%w (preamble, %v: %v)", errNoSignaling, f, err)}
	}
	if line != signalAccept {
		conn.Close()
		return rtcAttempt{err: errNoWebRTCPeer}
	}
	if !stopAbort() {
		// The network changed just as the server answered, and the
		// stream is closed.
		return rtcAttempt{answered: true, err: errNetChanged}
	}
	conn.SetDeadline(time.Time{})

	// The session lives in actx, so a network change before it has a
	// path ends it too.
	sess, err := newRTCSession(actx, c.logf, c.peer, conn, c.opts.iceServersFor(c.cl.DERPRegion()), c.notify, c.stats, c.cl.NewPacketPath, true)
	if err != nil {
		conn.Close()
		return rtcAttempt{answered: true, err: err}
	}
	c.mu.Lock()
	c.cur = sess
	c.mu.Unlock()
	if err := sess.offer(); err != nil {
		sess.close()
		return rtcAttempt{answered: true, err: fmt.Errorf("offer: %w", err)}
	}
	go sess.readSignals(br, false)
	go sess.giveUpUnlessQualified()
	<-sess.ctx.Done()
	sess.mu.Lock()
	a := rtcAttempt{answered: true, up: sess.everQualified}
	if a.up {
		a.lasted = time.Since(sess.qualifiedAt)
	}
	sess.mu.Unlock()
	return a
}

// networkChanged passes a network change on: the tunnel checks its DERP
// connection, and the session's path is checked at once. An attempt
// that has no path yet, still signaling or negotiating over the old
// network, starts over now, and between attempts the next starts now.
func (c *rtcClient) networkChanged() {
	c.cl.NetworkChanged()
	c.mu.Lock()
	sess, abort := c.cur, c.abort
	c.mu.Unlock()
	if sess != nil && sess.networkChanged() {
		return
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	if abort != nil {
		abort()
	}
}

// setHookState tells a test page (one with tailcatTestHooks) what the
// client is doing: "negotiating", "waiting" or "stopped: <why>".
func (c *rtcClient) setHookState(st string) {
	if c.hooks.Truthy() {
		c.hooks.Set("client", st)
	}
}
