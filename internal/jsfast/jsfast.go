// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

// Package jsfast moves a datagram between Go and a DataChannel or
// WebSocket in as few calls into JavaScript as it can.
//
// Each syscall/js call by name (Get, Call, Set) decodes the name from Go
// on every call, and each JavaScript object handed to Go gets a Go
// finalizer; per datagram, those were a fifth of the tunnel's time in a
// browser. The helpers here are small JavaScript functions made once,
// called with Invoke, that take and return numbers and values Go already
// holds.
//
// They are made with the Function constructor, which a page's
// Content-Security-Policy may forbid ('unsafe-eval'). Then [Get] returns
// nil, and callers keep their per-call path.
package jsfast

import (
	"errors"
	"log"
	"sync"
	"syscall/js"
)

// Helpers are the JavaScript helpers. A nil *Helpers has none.
type Helpers struct {
	buffered, send, binaryHandler js.Value
}

const source = `"use strict";
return {
  buffered: (t) => t.bufferedAmount,
  send(t, buf, n) {
    try {
      t.send(n === buf.length ? buf : buf.subarray(0, n));
      return null;
    } catch (e) {
      return String(e && e.message || e);
    }
  },
  binaryHandler(buf, cb) {
    return (ev) => {
      const d = ev.data;
      // Text never reaches the Uint8Array constructor, which would
      // read a numeric string as a length to allocate.
      if (!(d instanceof ArrayBuffer)) return;
      if (d.byteLength > buf.length) {
        cb(-1, d);
        return;
      }
      buf.set(new Uint8Array(d));
      cb(d.byteLength);
    };
  },
};`

var get = sync.OnceValue(func() (h *Helpers) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("tailcat: no fast JS helpers (%v); moving each datagram with several calls instead", r)
			h = nil // the page's CSP forbids the Function constructor
		}
	}()
	o := js.Global().Get("Function").New(source).Invoke()
	return &Helpers{
		buffered:      o.Get("buffered"),
		send:          o.Get("send"),
		binaryHandler: o.Get("binaryHandler"),
	}
})

// Get returns the helpers, or nil if the page can't make them.
func Get() *Helpers { return get() }

// Buffered returns t.bufferedAmount.
func (h *Helpers) Buffered(t js.Value) int {
	return h.buffered.Invoke(t).Int()
}

// Send sends the first n bytes of the Uint8Array buf over t, a
// DataChannel or WebSocket, which copies them. It returns the error t
// threw, if any.
func (h *Helpers) Send(t, buf js.Value, n int) error {
	if r := h.send.Invoke(t, buf, n); !r.IsNull() {
		return errors.New(r.String())
	}
	return nil
}

// BinaryHandler returns a message event handler for a DataChannel or
// WebSocket whose binaryType is "arraybuffer". For each binary message
// that fits the Uint8Array buf, it copies the message into buf and calls
// cb with its length. For one that doesn't, it calls cb with -1 and the
// message's ArrayBuffer. Text messages are ignored. cb runs before the
// handler returns, so buf is the message only until it does.
func (h *Helpers) BinaryHandler(buf js.Value, cb js.Func) js.Value {
	return h.binaryHandler.Invoke(buf, cb)
}
