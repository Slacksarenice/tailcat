// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_webrtc

package tailcat

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"sync"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat/internal/jsfast"
	"github.com/tailscale/tailcat/internal/rtcpolicy"
	"tailscale.com/derp/derphttp"
)

// In a browser, DERP runs over the page's WebSocket, whose send never
// blocks: it queues whatever it is given. The tunnel's TCP learns of a
// slow relay only from loss, so unbounded, that queue grows to whatever
// TCP has in flight, and every round trip through the relay grows with
// it: seconds, once TCP's window has grown. derpWebSocket holds the
// queue to derpShedTarget of the relay's measured rate instead, dropping
// one packet at a time above it (see rtcpolicy.Shedder and
// derphttp.PacketShedder), as the WebRTC path does its DataChannel's.
// This, not a cap on TCP's window, is what keeps a relayed transfer's
// round trips short, so the window can grow as far as the path allows.
const (
	derpShedTarget   = 20 * time.Millisecond
	derpMinBuffered  = 64 << 10
	derpInitBuffered = 256 << 10
	derpHardBuffered = 8 << 20
	derpShedEvery    = 100 * time.Millisecond
	// derpFrameOverhead is what DERP adds to each packet it relays: a
	// frame header and the destination's key.
	derpFrameOverhead = 5 + 32
	// derpShedLogEvery paces the log line of packets shed.
	derpShedLogEvery = 10 * time.Second
	// derpWSBuf is the size of each direction's reusable JS buffer, above
	// a DERP frame's 64 KiB packet and header; a larger write or message
	// takes a buffer of its own.
	derpWSBuf = 128 << 10

	// browserMaxWindow is 0: with every path's queue held short, the
	// tunnel's TCP windows needn't be capped (see tuneTCP).
	browserMaxWindow = 0
)

func init() {
	derphttp.SetWebsocketDialer(dialDERPWebSocket)
}

// derpWebSocket is a net.Conn over a browser WebSocket, for DERP. Its
// writes never block; see ShedPacket.
type derpWebSocket struct {
	ws      js.Value
	url     string
	funcs   []js.Func
	fast    *jsfast.Helpers // nil if the page can't make them
	recvBuf js.Value        // with fast, the Uint8Array each message is copied into

	sendMu  sync.Mutex // guards sendBuf, which a write fills then sends
	sendBuf js.Value   // with fast, a reusable Uint8Array for writes

	mu       sync.Mutex
	recv     [][]byte      // messages received and not yet read
	wake     chan struct{} // signaled when recv grows, or closed or deadline changes
	closed   bool          // by either side
	deadline time.Time     // for reads; zero for none

	shedMu  sync.Mutex
	shed    rtcpolicy.Shedder
	shedN   int // packets shed since the last log line
	shedLog time.Time
}

var _ derphttp.PacketShedder = (*derpWebSocket)(nil)

// dialDERPWebSocket opens a WebSocket to the DERP server at urlStr, an
// http or https URL, and waits for it to open.
func dialDERPWebSocket(ctx context.Context, urlStr string) (_ net.Conn, err error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	c := &derpWebSocket{
		url:  u.String(),
		wake: make(chan struct{}, 1),
		shed: rtcpolicy.Shedder{
			Target:       derpShedTarget,
			MinLimit:     derpMinBuffered,
			InitialLimit: derpInitBuffered,
			HardLimit:    derpHardBuffered,
			Every:        derpShedEvery,
		},
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("WebSocket %s: %v", c.url, r)
		}
		if err != nil {
			c.Close()
		}
	}()
	c.ws = js.Global().Get("WebSocket").New(c.url, js.ValueOf([]any{"derp"}))
	c.ws.Set("binaryType", "arraybuffer")
	opened := make(chan error, 1)
	c.on("onopen", func(js.Value) {
		select {
		case opened <- nil:
		default:
		}
	})
	if c.fast = jsfast.Get(); c.fast != nil {
		u8 := js.Global().Get("Uint8Array")
		c.recvBuf, c.sendBuf = u8.New(derpWSBuf), u8.New(derpWSBuf)
		cb := js.FuncOf(func(this js.Value, args []js.Value) any {
			if n := args[0].Int(); n >= 0 {
				b := make([]byte, n)
				js.CopyBytesToGo(b, c.recvBuf)
				c.received(b)
			} else {
				c.receivedBuffer(args[1])
			}
			return nil
		})
		c.funcs = append(c.funcs, cb)
		c.ws.Set("onmessage", c.fast.BinaryHandler(c.recvBuf, cb))
	} else {
		c.on("onmessage", func(ev js.Value) {
			d := ev.Get("data")
			if !d.InstanceOf(js.Global().Get("ArrayBuffer")) {
				return // DERP is binary; the server sends no text
			}
			c.receivedBuffer(d)
		})
	}
	c.on("onclose", func(ev js.Value) {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.signal()
		select {
		case opened <- fmt.Errorf("WebSocket %s closed (code %d)", c.url, ev.Get("code").Int()):
		default:
		}
	})
	select {
	case err := <-opened:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	log.Printf("websocket: connected to %v", c.url)
	return c, nil
}

// on sets the WebSocket's event handler prop to f.
func (c *derpWebSocket) on(prop string, f func(ev js.Value)) {
	fn := js.FuncOf(func(this js.Value, args []js.Value) any {
		f(args[0])
		return nil
	})
	c.funcs = append(c.funcs, fn)
	c.ws.Set(prop, fn)
}

// receivedBuffer queues a copy of the message in the ArrayBuffer d.
func (c *derpWebSocket) receivedBuffer(d js.Value) {
	b := make([]byte, d.Get("byteLength").Int())
	js.CopyBytesToGo(b, js.Global().Get("Uint8Array").New(d))
	c.received(b)
}

// received queues the message b for Read.
func (c *derpWebSocket) received(b []byte) {
	c.mu.Lock()
	c.recv = append(c.recv, b)
	c.mu.Unlock()
	c.signal()
}

func (c *derpWebSocket) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *derpWebSocket) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.recv) > 0 {
			n := copy(p, c.recv[0])
			if n == len(c.recv[0]) {
				c.recv[0] = nil
				c.recv = c.recv[1:]
			} else {
				c.recv[0] = c.recv[0][n:]
			}
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		deadline := c.deadline
		c.mu.Unlock()
		if deadline.IsZero() {
			<-c.wake
			continue
		}
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		select {
		case <-c.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func (c *derpWebSocket) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if c.fast != nil && len(p) <= derpWSBuf {
		c.sendMu.Lock()
		defer c.sendMu.Unlock()
		js.CopyBytesToJS(c.sendBuf, p)
		if err := c.fast.Send(c.ws, c.sendBuf, len(p)); err != nil {
			return 0, fmt.Errorf("WebSocket %s: send: %v", c.url, err)
		}
		return len(p), nil
	}
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, fmt.Errorf("WebSocket %s: send: %v", c.url, r)
		}
	}()
	b := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(b, p)
	c.ws.Call("send", b)
	return len(p), nil
}

// ShedPacket reports whether to drop a packet of size bytes rather than
// send it, by the queue already in the WebSocket's send buffer; see
// rtcpolicy.Shedder.
func (c *derpWebSocket) ShedPacket(size int) bool {
	c.shedMu.Lock()
	defer c.shedMu.Unlock()
	var buffered int
	if c.fast != nil {
		buffered = c.fast.Buffered(c.ws)
	} else {
		buffered = c.ws.Get("bufferedAmount").Int()
	}
	now := time.Now()
	if !c.shed.Drop(buffered, derpFrameOverhead+size, now) {
		return false
	}
	c.shedN++
	if now.Sub(c.shedLog) >= derpShedLogEvery {
		log.Printf("derp: %s: shed %d packets to keep its queue short (%d bytes queued, line %d, relay at %.1f MB/s)",
			c.url, c.shedN, buffered, c.shed.Limit(), c.shed.Rate()/1e6)
		c.shedN, c.shedLog = 0, now
	}
	return true
}

func (c *derpWebSocket) Close() error {
	c.mu.Lock()
	already := c.closed && c.funcs == nil
	c.closed = true
	funcs := c.funcs
	c.funcs = nil
	c.mu.Unlock()
	c.signal()
	if already || c.ws.IsUndefined() {
		return nil
	}
	for _, prop := range []string{"onopen", "onmessage", "onclose"} {
		c.ws.Set(prop, js.Null())
	}
	c.ws.Call("close")
	for _, f := range funcs {
		f.Release()
	}
	return nil
}

func (c *derpWebSocket) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *derpWebSocket) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	c.signal()
	return nil
}

// SetWriteDeadline does nothing: writes never block.
func (c *derpWebSocket) SetWriteDeadline(time.Time) error { return nil }

func (c *derpWebSocket) LocalAddr() net.Addr  { return wsAddr(c.url) }
func (c *derpWebSocket) RemoteAddr() net.Addr { return wsAddr(c.url) }

// wsAddr is a WebSocket's URL as a net.Addr; a browser reveals no IP
// addresses for its connections.
type wsAddr string

func (wsAddr) Network() string  { return "websocket" }
func (a wsAddr) String() string { return string(a) }
