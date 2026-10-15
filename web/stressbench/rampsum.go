// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// rampsum summarizes the ramp traces of TestBrowserWebRTCStress
// (--web-stress-trace; see ramp.sh):
//
//	go run web/stressbench/rampsum.go DIR             medians and ranges per variant, path and round trip
//	go run web/stressbench/rampsum.go -timeline FILE  one trace, every 250 ms
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/tailscale/tailcat/web/stressbench/rampmetric"
)

type tcpConn struct {
	LPort, RPort       uint16
	Cwnd, Ssthresh     uint32
	SRTTms             float64 `json:"srttMs"`
	RTOms              float64 `json:"rtoMs"`
	CC                 int     `json:"cc"`
	Reorder            bool
	SegsSent, SegsRcvd uint64
	Retrans, FastRetx  uint64
	Timeouts           uint64
	SndBuf, RcvBuf     int64
	RcvQueued          int64
}

type tcpSample struct {
	T                          int64
	Conns                      []tcpConn
	Retrans, FastRecovery      uint64
	SACKRecovery, TLPRecovery  uint64
	Timeouts, SpuriousRecovery uint64
	DERP                       []struct {
		Buffered, Line int
		Rate           float64
		Shed           int64
	}
}

type rtcSample struct {
	T                                    int64
	Session                              int
	Up                                   bool
	Buffered, Line                       int
	Rate                                 float64
	Dropped, Sent, Recv, RecvDropped     int64
	WireSent, WireRecv, PktsSent, DCSent float64
}

type side struct {
	Ramp       []rampmetric.Point
	PathEvents []struct {
		T    int64
		Path string
	}
	SendStart int64
	TCP       []tcpSample
	RTC       []rtcSample
}

type trace struct {
	Path    string
	NetemMs float64
	RelayMs float64
	CC      string
	Variant string
	Listen  side
	Send    side
}

// metrics measures t's ramp afresh from its pages' progress.
func (t *trace) metrics() rampmetric.Metrics {
	m := rampmetric.Compute(t.Listen.Ramp, t.Send.SendStart)
	for _, e := range t.Send.PathEvents {
		if e.Path == "webrtc" {
			m.Switch = float64(e.T-t.Send.SendStart) / 1e3
			break
		}
	}
	return m
}

func load(path string) (*trace, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t trace
	return &t, json.Unmarshal(b, &t)
}

func main() {
	timeline := flag.String("timeline", "", "print this trace's timeline")
	until := flag.Float64("until", 30, "with -timeline, up to this many seconds")
	flag.Parse()
	if *timeline != "" {
		t, err := load(*timeline)
		if err != nil {
			log.Fatal(err)
		}
		printTimeline(t, *until)
		return
	}
	summarize(flag.Arg(0))
}

func summarize(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	groups := map[string][]rampmetric.Metrics{}
	for _, f := range files {
		t, err := load(f)
		if err != nil {
			log.Printf("%s: %v", f, err)
			continue
		}
		k := fmt.Sprintf("%-8s %-6s %3.0fms", t.Variant, t.Path, t.NetemMs+t.RelayMs)
		groups[k] = append(groups[k], t.metrics())
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Times are medians (and ranges) over the runs that reached the rate
	// at all, with how many did; a stall is 2 s or more with nothing
	// received.
	fmt.Println("variant  path     rtt  n | overall MB/s       | steady MB/s        | to 10 MB/s, s         | to 20 MB/s, s         | stalled runs, s in all | WebRTC at s")
	for _, k := range keys {
		ms := groups[k]
		col := func(f func(rampmetric.Metrics) float64) string {
			var v []float64
			for _, m := range ms {
				if x := f(m); x >= 0 {
					v = append(v, x)
				}
			}
			if len(v) == 0 {
				return fmt.Sprintf("%18s", "-")
			}
			slices.Sort(v)
			return fmt.Sprintf("%5.1f (%5.1f–%5.1f)", v[len(v)/2], v[0], v[len(v)-1])
		}
		reached := func(f func(rampmetric.Metrics) float64) string {
			n := 0
			for _, m := range ms {
				if f(m) >= 0 {
					n++
				}
			}
			return fmt.Sprintf("%d/%d %s", n, len(ms), col(f))
		}
		stalled, secs := 0, 0.0
		for _, m := range ms {
			if m.Stalls > 0 {
				stalled++
			}
			secs += m.StalledSecs
		}
		fmt.Printf("%s %2d | %s | %s | %s | %s | %d, %6.1f s | %s\n", k, len(ms),
			col(func(m rampmetric.Metrics) float64 { return m.Total }),
			col(func(m rampmetric.Metrics) float64 { return m.Steady }),
			reached(func(m rampmetric.Metrics) float64 { return m.T10 }),
			reached(func(m rampmetric.Metrics) float64 { return m.T20 }),
			stalled, secs,
			col(func(m rampmetric.Metrics) float64 { return m.Switch }))
	}
}

// dataConn returns the index in s.Conns of the transfer's connection:
// the one that sent (or received) the most segments.
func dataConn(s tcpSample, sent bool) int {
	best, n := -1, uint64(0)
	for i, c := range s.Conns {
		v := c.SegsRcvd
		if sent {
			v = c.SegsSent
		}
		if v >= n {
			best, n = i, v
		}
	}
	return best
}

func printTimeline(t *trace, until float64) {
	t0 := t.Send.SendStart
	m := t.metrics()
	fmt.Printf("%s %s, %.0f ms, cc %q: steady %.1f MB/s, t50 %.2f s, t90 %.2f s, WebRTC from %.2f s\n",
		t.Variant, t.Path, t.NetemMs+t.RelayMs, t.CC, m.Steady, m.T50, m.T90, m.Switch)
	for _, e := range t.Send.PathEvents {
		fmt.Printf("sender path %s at %.2f s\n", e.Path, float64(e.T-t0)/1e3)
	}
	// Received MB/s at time ms, from the listener's progress.
	recvRate := func(ms int64) float64 {
		r := t.Listen.Ramp
		for i := 1; i < len(r); i++ {
			if r[i].T >= ms {
				return float64(r[i].Recv-r[i-1].Recv) / float64(r[i].T-r[i-1].T) / 1e3
			}
		}
		return 0
	}
	rtcAt := func(ms int64) (rtcSample, rtcSample, bool) {
		// The latest session's sample at ms, and that session's one before.
		r := t.Send.RTC
		at := -1
		for i := range r {
			if r[i].T <= ms+125 && (at < 0 || r[i].Session >= r[at].Session) {
				at = i
			}
		}
		if at < 0 {
			return rtcSample{}, rtcSample{}, false
		}
		for j := at - 1; j >= 0; j-- {
			if r[j].Session == r[at].Session {
				return r[at], r[j], true
			}
		}
		return r[at], r[at], true
	}
	rcvBufAt := func(ms int64) (int64, int64) {
		for _, s := range t.Listen.TCP {
			if s.T >= ms-125 {
				if i := dataConn(s, false); i >= 0 {
					return s.Conns[i].RcvBuf, s.Conns[i].RcvQueued
				}
				return 0, 0
			}
		}
		return 0, 0
	}
	fmt.Println("    t  recvMB/s |  cwnd ssth  srtt   rto cc retx  tmo fRec sRec | rtc buffKB lineKB rateMB drops wireMB/s | derp buffKB lineKB rateMB shed | rcvBufKB rcvQKB")
	for _, s := range t.Send.TCP {
		at := float64(s.T-t0) / 1e3
		if at < -1 || at > until {
			continue
		}
		c := tcpConn{}
		if j := dataConn(s, true); j >= 0 {
			c = s.Conns[j]
		}
		var line strings.Builder
		fmt.Fprintf(&line, "%5.2f %8.1f | %5d %4d %5.0f %5.0f %2d %4d %4d %4d %4d |", at, recvRate(s.T),
			c.Cwnd, min(c.Ssthresh, 9999), c.SRTTms, c.RTOms, c.CC, c.Retrans, c.Timeouts, s.FastRecovery, s.SACKRecovery)
		if r, prev, ok := rtcAt(s.T); ok {
			up := "dn"
			if r.Up {
				up = "up"
			}
			wire := 0.0
			if r.WireSent >= 0 && prev.WireSent >= 0 && r.T > prev.T {
				wire = (r.WireSent - prev.WireSent) / float64(r.T-prev.T) / 1e3
			}
			fmt.Fprintf(&line, " %s %6d %6d %6.1f %5d %8.1f |", up, r.Buffered>>10, r.Line>>10, r.Rate/1e6, r.Dropped, wire)
		} else {
			fmt.Fprintf(&line, " %40s |", "")
		}
		if len(s.DERP) > 0 {
			d := s.DERP[len(s.DERP)-1]
			fmt.Fprintf(&line, " %6d %6d %6.1f %4d |", d.Buffered>>10, d.Line>>10, d.Rate/1e6, d.Shed)
		} else {
			fmt.Fprintf(&line, " %30s |", "")
		}
		rb, rq := rcvBufAt(s.T)
		fmt.Fprintf(&line, " %8d %6d", rb>>10, rq>>10)
		fmt.Println(line.String())
	}
}
