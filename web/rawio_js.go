// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_webrtc

package main

// Raw I/O: the DataChannel hot path without syscall/js. Each syscall/js
// call decodes its property name from Go memory, and each JS object it
// returns costs a reference and a Go finalizer; a datagram sent that way
// crossed about six times. Here a channel is a handle in a table the
// instantiator keeps (tailcatRawIO, from worker.js or tailcat.js), and a
// datagram is one call of the module's own wasm import, with a pointer
// and a length that JS reads straight out of the module's memory.
//
// The module therefore imports "tailcat" functions, which whatever
// instantiates it must provide (WebAssembly.instantiate fails with a
// LinkError otherwise): the module and its worker.js and tailcat.js are
// a pair, and each checks the module's imports before instantiating it.
// An import changing meaning gets a new name (dcSend2), so the check
// catches a mismatched pair. Without tailcatRawIO, or built with
// TAILCAT_WASM_RAWIO=0 (rawIOOff), every channel uses syscall/js.

import (
	"syscall/js"
	"unsafe"
)

// dcSend sends the n bytes at p on the DataChannel of handle h and
// returns its bufferedAmount after the send; with n == 0 it sends
// nothing and just returns that. It returns a negative rawStatus if
// the channel can't take the message.
//
//go:wasmimport tailcat dcSend
func dcSend(h int32, p unsafe.Pointer, n int32) int32

// dcSend's negative results.
const (
	rawNotOpen   = -1 // the channel's readyState isn't "open"
	rawSendError = -2 // send threw
	rawNoChannel = -3 // no channel has the handle (detached)
)

// rawIOMode, set with -ldflags -X for A/B measurements, is "off" for no
// raw I/O, "send" for sending only, or "" for both.
var rawIOMode string

// rawIO is the instantiator's handle table, read once at start: a page
// may run several modules, one after the other, each with its own table
// in the same global.
var rawIO = func() js.Value {
	v := js.Global().Get("tailcatRawIO")
	if rawIOMode == "off" || v.Type() != js.TypeObject {
		return js.Undefined()
	}
	return v
}()

// rawAttach returns a handle for DataChannel dc, or 0 if raw I/O is
// off.
func rawAttach(dc js.Value) int32 {
	if rawIO.IsUndefined() {
		return 0
	}
	h, err := jsCall(rawIO, "attach", dc)
	if err != nil || h.Type() != js.TypeNumber {
		return 0
	}
	return int32(h.Int())
}

// rawDetach releases handle h. Handles are never reused, so a send on
// a detached one fails rather than reaching another channel.
func rawDetach(h int32) {
	if h != 0 {
		jsCall(rawIO, "detach", h)
	}
}

// rawSend sends frame on the channel of handle h; see dcSend.
func rawSend(h int32, frame []byte) int32 {
	if len(frame) == 0 {
		return dcSend(h, nil, 0)
	}
	return dcSend(h, unsafe.Pointer(unsafe.SliceData(frame)), int32(len(frame)))
}
