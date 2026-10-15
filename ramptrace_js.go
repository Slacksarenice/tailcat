// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && tailcat_webrtc && tailcat_ramptrace

package tailcat

import (
	"encoding/json"
	"log"
	"sync"
	"syscall/js"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/wgengine/netstack"
)

// This file is the browser stress test's view of a transfer's ramp
// (TestBrowserWebRTCStress --web-stress-trace): every rampEvery, the
// state of the tunnel's TCP connections and of each DERP WebSocket's
// queue, published as JSON in tailcatTestHooks.rampTCP. It is built only
// with the tailcat_ramptrace tag (TAILCAT_WASM_TAGS), never into the
// shipped wasm.

const rampEvery = 250 * time.Millisecond

// rampTCPConn is one TCP connection's state in a sample.
type rampTCPConn struct {
	LPort      uint16  `json:"lport"`
	RPort      uint16  `json:"rport"`
	State      uint32  `json:"state"`
	Cwnd       uint32  `json:"cwnd"` // segments
	Ssthresh   uint32  `json:"ssthresh"`
	SRTTms     float64 `json:"srttMs"`
	RTTVarMs   float64 `json:"rttVarMs"`
	RTOms      float64 `json:"rtoMs"`
	CcState    int     `json:"cc"` // tcpip.CongestionControlState: 0 open, 1 RTO, 2 fast, 3 SACK recovery, 4 disorder
	Reorder    bool    `json:"reorder,omitempty"`
	SegsSent   uint64  `json:"segsSent"`
	SegsRcvd   uint64  `json:"segsRcvd"`
	Retrans    uint64  `json:"retrans"`
	FastRetx   uint64  `json:"fastRetx"`
	Timeouts   uint64  `json:"timeouts"`
	SndBuf     int64   `json:"sndBuf"`
	RcvBuf     int64   `json:"rcvBuf"`
	RcvQueued  int     `json:"rcvQueued"` // received, not yet read by the app
}

// rampDERP is one DERP WebSocket's queue in a sample.
type rampDERP struct {
	Buffered int     `json:"buffered"`
	Line     int     `json:"line"`
	Rate     float64 `json:"rate"` // bytes/s
	Shed     int64   `json:"shed"`
}

type rampSample struct {
	T     int64         `json:"t"` // Unix ms
	Conns []rampTCPConn `json:"conns"`
	// Stack-wide counters.
	Retrans      uint64     `json:"retrans"`
	FastRecovery uint64     `json:"fastRecovery"`
	SACKRecovery uint64     `json:"sackRecovery"`
	TLPRecovery  uint64     `json:"tlpRecovery"`
	Timeouts     uint64     `json:"timeouts"`
	SpuriousRec  uint64     `json:"spuriousRecovery"`
	SpuriousRTO  uint64     `json:"spuriousRTO"`
	DSACK        uint64     `json:"dsack"`
	DERP         []rampDERP `json:"derp,omitempty"`
}

var rampDERPs struct {
	mu    sync.Mutex
	conns []*derpWebSocket
}

// traceDERP adds c to the DERP WebSockets the ramp trace samples.
func traceDERP(c *derpWebSocket) {
	hooks := js.Global().Get("tailcatTestHooks")
	if !hooks.Truthy() || !hooks.Get("ramp").Truthy() {
		return
	}
	// rampShed tunes the Shedder, for A/B runs (rtcpolicy.Shedder.Tune).
	if spec := hooks.Get("rampShed"); spec.Type() == js.TypeString {
		c.shedMu.Lock()
		err := c.shed.Tune(spec.String())
		c.shedMu.Unlock()
		if err != nil {
			log.Printf("derp: %v", err)
		}
	}
	rampDERPs.mu.Lock()
	rampDERPs.conns = append(rampDERPs.conns, c)
	rampDERPs.mu.Unlock()
}

// startRampTrace samples ns's TCP connections, if the page asked for a
// ramp trace (tailcatTestHooks.ramp).
func startRampTrace(ns *netstack.Impl) {
	hooks := js.Global().Get("tailcatTestHooks")
	if !hooks.Truthy() || !hooks.Get("ramp").Truthy() {
		return
	}
	st := tcpipStackOf(ns)
	// rampCC picks the tunnel's congestion control, for A/B runs.
	if cc := hooks.Get("rampCC"); cc.Type() == js.TypeString && cc.String() != "" {
		opt := tcpip.CongestionControlOption(cc.String())
		if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			js.Global().Get("console").Call("log", "rampCC: "+err.String())
		}
	}
	go func() {
		var samples []rampSample
		tick := time.NewTicker(rampEvery)
		for n := 1; ; n++ {
			<-tick.C
			samples = append(samples, sampleRamp(st))
			if n%4 == 0 {
				b, _ := json.Marshal(samples)
				hooks.Set("rampTCP", string(b))
			}
		}
	}()
}

func sampleRamp(st *stack.Stack) rampSample {
	s := rampSample{T: time.Now().UnixMilli()}
	for _, tep := range st.RegisteredEndpoints() {
		ep, ok := tep.(*tcp.Endpoint)
		if !ok {
			continue
		}
		state := ep.State()
		if tcp.EndpointState(state) != tcp.StateEstablished && tcp.EndpointState(state) != tcp.StateCloseWait &&
			tcp.EndpointState(state) != tcp.StateFinWait1 {
			continue
		}
		var info tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&info); err != nil {
			continue
		}
		c := rampTCPConn{
			State:    state,
			Cwnd:     info.SndCwnd,
			Ssthresh: info.SndSsthresh,
			SRTTms:   ms(info.RTT),
			RTTVarMs: ms(info.RTTVar),
			RTOms:    ms(info.RTO),
			CcState:  int(info.CcState),
			Reorder:  info.ReorderSeen,
			SndBuf:   ep.SocketOptions().GetSendBufferSize(),
			RcvBuf:   ep.SocketOptions().GetReceiveBufferSize(),
		}
		if ti, ok := ep.Info().(*stack.TransportEndpointInfo); ok {
			c.LPort, c.RPort = ti.ID.LocalPort, ti.ID.RemotePort
		}
		if es, ok := ep.Stats().(*tcp.Stats); ok {
			c.SegsSent, c.SegsRcvd = es.SegmentsSent.Value(), es.SegmentsReceived.Value()
			c.Retrans, c.FastRetx, c.Timeouts = es.SendErrors.Retransmits.Value(), es.SendErrors.FastRetransmit.Value(), es.SendErrors.Timeouts.Value()
		}
		if n, err := ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err == nil {
			c.RcvQueued = n
		}
		s.Conns = append(s.Conns, c)
	}
	ts := st.Stats().TCP
	s.Retrans, s.FastRecovery, s.SACKRecovery = ts.Retransmits.Value(), ts.FastRecovery.Value(), ts.SACKRecovery.Value()
	s.TLPRecovery, s.Timeouts = ts.TLPRecovery.Value(), ts.Timeouts.Value()
	s.SpuriousRec, s.SpuriousRTO, s.DSACK = ts.SpuriousRecovery.Value(), ts.SpuriousRTORecovery.Value(), ts.SegmentsAckedWithDSACK.Value()

	rampDERPs.mu.Lock()
	conns := rampDERPs.conns
	rampDERPs.mu.Unlock()
	for _, c := range conns {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			continue
		}
		c.shedMu.Lock()
		s.DERP = append(s.DERP, rampDERP{
			Buffered: c.ws.Get("bufferedAmount").Int(),
			Line:     c.shed.Limit(),
			Rate:     c.shed.Rate(),
			Shed:     c.shedTotal,
		})
		c.shedMu.Unlock()
	}
	return s
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
