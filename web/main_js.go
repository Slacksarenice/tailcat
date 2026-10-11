// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tailcat web app is the WebAssembly (js/wasm) build of tailcat
// for browsers. It exposes two global JavaScript functions,
// tailcatListen and tailcatDial, that app.js uses to implement
// file sharing. The browser reaches DERP relays over WebSockets,
// which tailscale.com's derphttp package does automatically under
// GOOS=js. When both ends of a tunnel are this app and enable the
// "webrtc" option, the tunnel's traffic moves to a direct WebRTC
// DataChannel between the browsers whenever one can be opened, and
// back to DERP if it fails; see webrtc_js.go.
//
// A function the page calls runs on the page's event loop, which the
// call holds until it returns. Anything that can wait on the network
// therefore runs on a goroutine and hands the page a Promise: closing a
// node, say, waits for its in-flight fetches and WebSockets to end, and
// those can only end on the event loop, so waiting for them in the
// call itself would freeze the page. A goroutine holds it too, for as
// long as it runs without blocking: Go hands the thread back to the
// page only once every goroutine waits on something. So no loop may
// retry without waiting between attempts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"syscall/js"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// webrtcSignalPort is the TCP port on a web listener's tunnel address
// where WebRTC signaling is served (see webrtc_js.go). Listeners never
// hand connections to it to the page, and the page can't dial it.
const webrtcSignalPort = 65534

func main() {
	js.Global().Set("tailcatListen", js.FuncOf(tailcatListen))
	js.Global().Set("tailcatDial", js.FuncOf(tailcatDial))
	if f := js.Global().Get("onTailcatReady"); f.Type() == js.TypeFunction {
		f.Invoke()
	}
	select {}
}

// tailcatListen starts a tailcat server in the browser.
//
// It takes one options object argument:
//
//	{
//	  derpMapURL: string,      // absolute URL of the JSON DERP map (required)
//	  privateKey: string,      // optional tailcat.PrivateKey JSON; ephemeral if empty
//	  verbose: bool,           // optional; log to the console
//	  onConnection: (conn) => {}, // called with a conn object per incoming connection
//	  webrtc: bool | {iceServers: [...]}, // optional; answer WebRTC upgrades from
//	                           // web clients that enable it. iceServers defaults to
//	                           // the DERP region's STUN servers.
//	  onPathChange: ({peerKey, path}) => {}, // optional; path is "webrtc" or "derp"
//	}
//
// It returns a Promise that resolves to:
//
//	{
//	  addr: string,           // the "tc..." address to share
//	  privateKeyJSON: string, // the key (with its DERP region pinned), for persistence
//	  // Drop a client; block refuses it from now on. Resolves to whether
//	  // it was connected.
//	  disconnect: (peerKey, {block: bool}) => Promise<bool>,
//	  close: () => Promise, // resolves once the server has shut down
//	}
func tailcatListen(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatListen requires an options object"))
	}
	opts := args[0]
	onConnection := opts.Get("onConnection")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	return makePromise(func() (any, error) {
		if onConnection.Type() != js.TypeFunction {
			return nil, errors.New("onConnection function is required")
		}
		if derpMapURL == "" {
			return nil, errors.New("derpMapURL is required")
		}
		pk := &tailcat.PrivateKey{}
		if keyJSON != "" {
			if err := json.Unmarshal([]byte(keyJSON), pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
		} else {
			pk = tailcat.NewPrivateKey()
			pk.Public.RegionID = -1 // auto-select
		}
		if pk.Public.PresharedKey.IsZero() {
			// Migrate private keys saved by versions predating WireGuard PSKs.
			// The returned privateKeyJSON persists the new address capability.
			pk.Public.PresharedKey = tailcat.NewPresharedKey()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ci := pk.Public
		if err := ci.Expand(ctx, tailcat.ExpandForServer, tailcat.DERPMapURL(derpMapURL)); err != nil {
			return nil, fmt.Errorf("Expand: %w", err)
		}
		reg := ci.Region[0]
		if keyJSON == "" {
			// Pin the picked region so a persisted key keeps the
			// same address across page loads.
			pk.Public.RegionID = reg.RegionID
		}
		addr := pk.Public.Addr()
		keyOut, err := json.Marshal(pk)
		if err != nil {
			return nil, err
		}

		srv := &tailcat.Server{Key: pk.Private, PresharedKey: pk.Public.PresharedKey, Logf: logf, Region: reg}
		var blocked tailcat.KeySet
		srv.AllowClient = func(k key.NodePublic) bool { return !blocked.Contains(k) }
		rtc := newRTCServer(srv, opts, reg, logf)
		srv.OnTCP = func(port uint16) (handler func(net.Conn)) {
			if port == webrtcSignalPort {
				if rtc == nil {
					return nil // reset: WebRTC is off
				}
				return rtc.handleSignal
			}
			// Like the CLI's default mode, accept a connection on
			// any port and hand it to the page.
			return func(c net.Conn) {
				peer, _ := srv.PeerKey(c.RemoteAddr())
				invokeSafely("onConnection", onConnection, makeJSConn(c, port, peer, nil))
			}
		}
		if err := srv.Start(); err != nil {
			srv.Close()
			return nil, fmt.Errorf("Server.Start: %w", err)
		}
		return map[string]any{
			"addr":           string(addr),
			"privateKeyJSON": string(keyOut),
			"disconnect": js.FuncOf(func(this js.Value, args []js.Value) any {
				if len(args) < 1 || args[0].Type() != js.TypeString {
					return resolvedPromise(false)
				}
				var k key.NodePublic
				if err := k.UnmarshalText([]byte(args[0].String())); err != nil {
					return resolvedPromise(false)
				}
				// The block and the WebRTC session's end take effect
				// before this returns; neither waits on anything.
				if len(args) > 1 && args[1].Type() == js.TypeObject && args[1].Get("block").Truthy() {
					blocked.Add(k)
				}
				if rtc != nil {
					rtc.disconnect(k)
				}
				return makePromise(func() (any, error) {
					return srv.DisconnectClient(k), nil
				})
			}),
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				if rtc != nil {
					rtc.close()
				}
				return makePromise(func() (any, error) {
					srv.Close()
					return js.Undefined(), nil
				})
			}),
		}, nil
	})
}

// tailcatDial connects to a tailcat server and dials one TCP stream
// over the tunnel.
//
// It takes one options object argument:
//
//	{
//	  addr: string,       // the server's "tc..." address (required)
//	  derpMapURL: string, // optional absolute URL of the JSON DERP map
//	  privateKey: string, // optional tailcat.PrivateKey JSON; ephemeral if empty
//	  port: number,       // optional TCP port; defaults to 1 like the CLI
//	  verbose: bool,
//	  webrtc: bool | {iceServers: [...]}, // optional; upgrade to a direct WebRTC path
//	                      // if the server is this web app with WebRTC enabled.
//	                      // Leave it off for native tailcat servers.
//	  onPathChange: ({peerKey, path}) => {}, // optional; path is "webrtc" or "derp"
//	}
//
// It returns a Promise that resolves to a conn object (see makeJSConn)
// as soon as the stream is open over DERP; a WebRTC upgrade, if
// enabled, happens in the background, under the open stream.
func tailcatDial(this js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return rejectedPromise(errors.New("tailcatDial requires an options object"))
	}
	opts := args[0]
	addr := optString(opts, "addr")
	derpMapURL := optString(opts, "derpMapURL")
	keyJSON := optString(opts, "privateKey")
	logf := optLogf(opts)
	port := uint16(1)
	if p := opts.Get("port"); p.Type() == js.TypeNumber {
		port = uint16(p.Int())
	}
	return makePromise(func() (any, error) {
		if addr == "" {
			return nil, errors.New("addr is required")
		}
		if port == webrtcSignalPort {
			return nil, fmt.Errorf("port %d is reserved for WebRTC signaling", port)
		}
		// A malformed address fails here, at once, rather than every
		// ping attempt failing until the timeout.
		ci, err := tailcat.ParseAddr(tailcat.Addr(addr))
		if err != nil {
			return nil, fmt.Errorf("invalid addr: %w", err)
		}
		priv := key.NewNode()
		if keyJSON != "" {
			var pk tailcat.PrivateKey
			if err := json.Unmarshal([]byte(keyJSON), &pk); err != nil {
				return nil, fmt.Errorf("parsing privateKey: %w", err)
			}
			priv = pk.Private
		}
		cl := &tailcat.Client{
			Server:     tailcat.Addr(addr),
			Key:        priv,
			Logf:       logf,
			DERPMapURL: derpMapURL,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := pingUntil(ctx, cl); err != nil {
			cl.Close()
			return nil, err
		}
		c, err := cl.DialTCPPort(ctx, port)
		if err != nil {
			cl.Close()
			return nil, fmt.Errorf("DialTCPPort: %w", err)
		}
		rtcCtx, stopRTC := context.WithCancel(context.Background())
		go runRTCClient(rtcCtx, cl, opts, logf)
		return makeJSConn(c, port, ci.ServerPublic.NodePublic, func() {
			stopRTC()
			cl.Close()
		}), nil
	})
}

// pingRetryDelay is how long pingUntil waits after a failed attempt.
const pingRetryDelay = 500 * time.Millisecond

// pingUntil retries the meow/meowed handshake until it succeeds or
// ctx expires. The first pings can be lost while either side's DERP
// connection is still coming up. It waits between attempts: one that
// fails without blocking (a client that can't start fails every time)
// would otherwise spin, holding the page's thread until ctx expires.
func pingUntil(ctx context.Context, cl *tailcat.Client) error {
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := cl.Ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("ping: %w", err)
		case <-time.After(pingRetryDelay):
		}
	}
}

// makeJSConn wraps a tunneled TCP connection as a JavaScript object:
//
//	{
//	  port: number,
//	  peerKey: string, // the other end's node key ("nodekey:..."), authenticated by the tunnel
//	  read: () => Promise<Uint8Array|null>, // null on EOF; no concurrent calls
//	  write: (Uint8Array) => Promise,
//	  closeWrite: () => Promise, // half-close, netcat style
//	  // Resolves once the connection is closed and, for a dialed one,
//	  // the client that dialed it has shut down.
//	  close: () => Promise,
//	}
//
// read is pull-based: the browser only reads from netstack when the
// page asks for more, so a fast sender stalls on TCP backpressure
// rather than filling browser memory.
func makeJSConn(c net.Conn, port uint16, peer key.NodePublic, onClose func()) js.Value {
	buf := make([]byte, 64<<10)
	peerKey := ""
	if !peer.IsZero() {
		peerKey = peer.String()
	}
	return js.ValueOf(map[string]any{
		"port":    int(port),
		"peerKey": peerKey,
		"read": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				n, err := c.Read(buf)
				if n > 0 {
					u8 := js.Global().Get("Uint8Array").New(n)
					js.CopyBytesToJS(u8, buf[:n])
					return u8, nil
				}
				if err == nil || errors.Is(err, io.EOF) {
					return js.Null(), nil
				}
				return nil, err
			})
		}),
		"write": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				return rejectedPromise(errors.New("write requires a Uint8Array"))
			}
			b := make([]byte, args[0].Get("length").Int())
			js.CopyBytesToGo(b, args[0])
			return makePromise(func() (any, error) {
				if _, err := c.Write(b); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"closeWrite": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				cw, ok := c.(interface{ CloseWrite() error })
				if !ok {
					return nil, errors.New("connection does not support half-close")
				}
				if err := cw.CloseWrite(); err != nil {
					return nil, err
				}
				return js.Undefined(), nil
			})
		}),
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				c.Close()
				if onClose != nil {
					onClose()
				}
				return js.Undefined(), nil
			})
		}),
	})
}

func optString(v js.Value, name string) string {
	if p := v.Get(name); p.Type() == js.TypeString {
		return p.String()
	}
	return ""
}

func optLogf(v js.Value) logger.Logf {
	if v.Get("verbose").Truthy() {
		return log.Printf
	}
	return logger.Discard
}

// makePromise runs f on a new goroutine and returns a JavaScript
// Promise of its result, rejected with a JavaScript Error if f
// returns an error.
func makePromise(f func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			if res, err := f(); err == nil {
				resolve.Invoke(res)
			} else {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
			}
		}()
		return nil
	})
	// The Promise constructor calls handler before it returns, and
	// never again. Released, it no longer keeps f alive, nor whatever f
	// holds: for a write, a copy of the data. Kept, every byte a page
	// writes would stay on the heap for the life of the program.
	p := js.Global().Get("Promise").New(handler)
	handler.Release()
	return p
}

func rejectedPromise(err error) js.Value {
	return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(err.Error()))
}

func resolvedPromise(v any) js.Value {
	return js.Global().Get("Promise").Call("resolve", v)
}

// invokeSafely calls the page's callback f, named name. If it throws,
// the error is logged: left to panic, it would end the program and
// every tunnel in it.
func invokeSafely(name string, f js.Value, args ...any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("tailcat: %s threw: %v", name, r)
		}
	}()
	f.Invoke(args...)
}
