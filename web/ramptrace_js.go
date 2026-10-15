// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_ramptrace

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"syscall/js"
	"time"
)

// This file is the browser stress test's view of the WebRTC path during
// a transfer's ramp (TestBrowserWebRTCStress --web-stress-trace): every
// rampEvery, the DataChannel's queue, the Shedder's line, measured rate
// and drops, and the browser's byte counts for the selected candidate
// pair (what SCTP put on the wire), published as JSON in
// tailcatTestHooks.rampRTC. It is built only with the tailcat_ramptrace
// tag (TAILCAT_WASM_TAGS), never into the shipped wasm.

const rampEvery = 250 * time.Millisecond

type rampRTCSample struct {
	T           int64   `json:"t"` // Unix ms
	Up          bool    `json:"up"`
	Buffered    int     `json:"buffered"`
	Line        int     `json:"line"`
	Rate        float64 `json:"rate"` // bytes/s, 0 until measured
	Dropped     int64   `json:"dropped"`
	Sent        int64   `json:"sent"`
	Recv        int64   `json:"recv"`
	RecvDropped int64   `json:"recvDropped"`
	// From the browser's stats, -1 if unread.
	WireSent  float64 `json:"wireSent"`
	WireRecv  float64 `json:"wireRecv"`
	PktsSent  float64 `json:"pktsSent"`
	PktsRecv  float64 `json:"pktsRecv"`
	ICERTTms  float64 `json:"iceRttMs"`
	DCSent    float64 `json:"dcSent"` // the data channel's bytesSent
	DCMsgSent float64 `json:"dcMsgs"`
}

// traceRTC samples s while it lasts, if the page asked for a ramp trace
// (tailcatTestHooks.ramp).
func traceRTC(s *rtcSession) {
	if !s.hooks.Truthy() || !s.hooks.Get("ramp").Truthy() {
		return
	}
	go func() {
		var samples []rampRTCSample
		tick := time.NewTicker(rampEvery)
		defer tick.Stop()
		for n := 1; ; n++ {
			select {
			case <-s.ctx.Done():
				return
			case <-tick.C:
			}
			s.mu.Lock()
			r := rampRTCSample{
				T:           time.Now().UnixMilli(),
				Up:          s.qualified && !s.live.Suspect(),
				Line:        s.shed.Limit(),
				Rate:        s.shed.Rate(),
				Dropped:     s.dropped,
				Sent:        s.sentBytes,
				Recv:        s.recvBytes,
				RecvDropped: s.recvDropped,
			}
			if isOpen(s.dc) {
				r.Buffered = s.dc.Get("bufferedAmount").Int()
			}
			s.mu.Unlock()
			rampWireStats(s, &r)
			samples = append(samples, r)
			if n%4 == 0 {
				b, _ := json.Marshal(samples)
				s.hooks.Set("rampRTC", string(b))
			}
		}
	}()
}

// relayCandidate has the stress test's delay relay stand between this
// side and the peer's remote candidate cand, if the page asked for one
// (tailcatTestHooks.relayURL): the test returns the candidate rewritten
// to a relay's address, which forwards to the original after a delay,
// or nothing, to drop it. It runs in the signaling goroutine, which may
// block.
func relayCandidate(s *rtcSession, cand json.RawMessage) json.RawMessage {
	u := s.hooks.Get("relayURL")
	if u.Type() != js.TypeString || u.String() == "" {
		return cand
	}
	var c map[string]any
	if json.Unmarshal(cand, &c) != nil {
		return nil
	}
	str, _ := c["candidate"].(string)
	resp, err := http.Post(u.String(), "text/plain", strings.NewReader(str))
	if err != nil {
		s.logf("webrtc: relay: %v", err)
		return nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || len(b) == 0 {
		return nil
	}
	c["candidate"] = string(b)
	out, _ := json.Marshal(c)
	return out
}

// rampWireStats reads the selected candidate pair's and the datagram
// channel's counters from the browser's stats into r.
func rampWireStats(s *rtcSession, r *rampRTCSample) {
	r.WireSent, r.WireRecv, r.PktsSent, r.PktsRecv, r.ICERTTms, r.DCSent, r.DCMsgSent = -1, -1, -1, -1, -1, -1, -1
	p, err := jsCall(s.pc, "getStats")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, rampEvery)
	defer cancel()
	report, err := awaitPromise(ctx, p)
	if err != nil {
		return
	}
	num := func(v js.Value, prop string) float64 {
		if x := v.Get(prop); x.Type() == js.TypeNumber {
			return x.Float()
		}
		return -1
	}
	byID := map[string]js.Value{}
	var pairID string
	each := js.FuncOf(func(this js.Value, args []js.Value) any {
		st := args[0]
		byID[st.Get("id").String()] = st
		switch st.Get("type").String() {
		case "transport":
			if v := st.Get("selectedCandidatePairId"); v.Type() == js.TypeString {
				pairID = v.String()
			}
		case "data-channel":
			if st.Get("label").String() == dataChannelName {
				r.DCSent, r.DCMsgSent = num(st, "bytesSent"), num(st, "messagesSent")
			}
		}
		return nil
	})
	_, err = jsCall(report, "forEach", each)
	each.Release()
	if err != nil {
		return
	}
	if st, ok := byID[pairID]; ok {
		r.WireSent, r.WireRecv = num(st, "bytesSent"), num(st, "bytesReceived")
		r.PktsSent, r.PktsRecv = num(st, "packetsSent"), num(st, "packetsReceived")
		if rtt := num(st, "currentRoundTripTime"); rtt >= 0 {
			r.ICERTTms = rtt * 1000
		}
	}
}
