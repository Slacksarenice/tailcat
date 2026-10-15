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
// raw I/O, "send" for sending only, "func" for receiving through a JS
// function (a js.Func called with the length) rather than the
// tailcatRecv export, or "" for both through the export.
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
		delete(rawInboxes, h)
		jsCall(rawIO, "detach", h)
	}
}

// rawInbox is where tailcatRawIO puts a message received on a channel
// for the drainer goroutine (rtcSession.drain), when the channel
// receives through the tailcatRecv export: buf[:4] holds the length of
// the message in buf[rawInboxHeader:], little-endian, or 0 while it is
// empty. JS writes the message only while it is empty, so it never needs
// to know more of Go's state than that word.
type rawInbox struct {
	buf  []byte
	wake chan struct{} // capacity 1
}

// rawInboxHeader is the bytes before an inbox's message.
const rawInboxHeader = 8

// rawInboxes holds each handle's inbox, for tailcatRecv.
var rawInboxes = map[int32]*rawInbox{}

// tailcatRecv tells Go that JS put an n-byte message in the inbox of
// handle h, and returns 1, or returns 0 if it can't take it (JS then
// hands the message to the channel's slow onmessage). JS calls it from a
// channel's onmessage, while Go is paused, and then resumes Go
// (Go._resume) to run the drainer it wakes.
//
// It runs on the stack of whatever goroutine paused, outside the
// scheduler: it must not block or allocate (an allocation can park the
// goroutine to assist the garbage collector), which would leave its frame
// behind and return to JS. A map lookup, plain writes and a non-blocking
// send on a buffered channel of a pointer-free type do neither.
//
//go:wasmexport tailcatRecv
func tailcatRecv(h, n int32) int32 {
	in := rawInboxes[h]
	if in == nil || n <= 0 || int(n) > len(in.buf)-rawInboxHeader {
		return 0
	}
	in.buf[0], in.buf[1], in.buf[2], in.buf[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	select {
	case in.wake <- struct{}{}:
	default:
	}
	return 1
}

// rawSend sends frame on the channel of handle h; see dcSend.
func rawSend(h int32, frame []byte) int32 {
	if len(frame) == 0 {
		return dcSend(h, nil, 0)
	}
	return dcSend(h, unsafe.Pointer(unsafe.SliceData(frame)), int32(len(frame)))
}
