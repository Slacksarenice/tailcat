// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/tailscale/tailcat/web/stressbench/rampmetric"
	"tailscale.com/tailcfg"
)

// shapeLoopback gives the stress test's paths a round trip of rtt with
// netem on Linux's loopback interface, for the rest of the test: UDP
// (the WebRTC path; ICE and STUN too) waits rtt/2 on its one pass
// through the interface, and TCP to or from derpPort (the DERP server)
// rtt/4 on each of its two, so both paths' datagrams take rtt/2 one way.
// Everything else (DevTools, the web server) is untouched. With jitter,
// each delay varies by up to that much, and netem's rate keeps the
// packets in order: jitter alone would reorder them.
func shapeLoopback(t *testing.T, derpPort int, rtt, jitter time.Duration) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatalf("--web-stress-netem needs Linux")
	}
	tc := func(args ...string) error {
		out, err := exec.Command("tc", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("tc %v: %v: %s", args, err, out)
		}
		return nil
	}
	tc("qdisc", "del", "dev", "lo", "root") // a run that didn't clean up
	usec := func(d time.Duration) string { return strconv.FormatInt(d.Microseconds(), 10) + "us" }
	netem := func(parent, handle string, d time.Duration) []string {
		// netem drops what is beyond its limit, by default 1000 packets:
		// far less than a fast path holds in a long round trip.
		a := []string{"qdisc", "add", "dev", "lo", "parent", parent, "handle", handle, "netem", "limit", "1000000", "delay", usec(d)}
		if jitter > 0 {
			a = append(a, usec(jitter), "rate", "100gbit")
		}
		return a
	}
	port := strconv.Itoa(derpPort)
	for _, args := range [][]string{
		// Three bands; whatever no filter claims goes to the third,
		// unshaped.
		{"qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3", "priomap", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2", "2"},
		netem("1:1", "10:", rtt/2),
		netem("1:2", "20:", rtt/4),
		{"filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "protocol", "17", "0xff", "flowid", "1:1"},
		{"filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "prio", "2", "u32", "match", "ip", "dport", port, "0xffff", "flowid", "1:2"},
		{"filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "prio", "3", "u32", "match", "ip", "sport", port, "0xffff", "flowid", "1:2"},
	} {
		if err := tc(args...); err != nil {
			tc("qdisc", "del", "dev", "lo", "root")
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		out, _ := exec.Command("tc", "-s", "qdisc", "show", "dev", "lo").CombinedOutput()
		t.Logf("loopback shaping at the end:\n%s", out)
		tc("qdisc", "del", "dev", "lo", "root")
	})
	t.Logf("loopback shaped: round trip %v (jitter %v) for UDP and DERP port %d", rtt, jitter, derpPort)
}

// delayed is a datagram or a stream's chunk held until due.
type delayed struct {
	b   []byte
	to  *net.UDPAddr // for a datagram
	due time.Time
}

// delayClock hands out due times delay (plus up to jitter) from now,
// never earlier than the last: a delay line keeps its order.
type delayClock struct {
	delay, jitter time.Duration
	last          time.Time
}

func (c *delayClock) due() time.Time {
	d := c.delay
	if c.jitter > 0 {
		d += rand.N(c.jitter)
	}
	due := time.Now().Add(d)
	if due.Before(c.last) {
		due = c.last
	}
	c.last = due
	return due
}

// waitUntil returns at t, give or take a few microseconds. A sleep alone
// overshoots by up to a timer tick, which on Windows can be many
// milliseconds: it sleeps to a couple of milliseconds short, then spins.
func waitUntil(t time.Time) {
	if d := time.Until(t) - 2*time.Millisecond; d > 0 {
		time.Sleep(d)
	}
	for time.Now().Before(t) {
		runtime.Gosched()
	}
}

// delayRelays is the stress test's userspace stand-in for a long path
// (--web-stress-relay), which works on any OS, unlike netem. As an
// http.Handler, it takes a page's remote ICE candidate (see
// relayCandidate in ramptrace_js.go) and answers it rewritten to a UDP
// relay of its own, which forwards whatever it receives to the
// candidate's address, after delay, and what that address sends back to
// whoever last sent it something. Every datagram between the pages thus
// passes one relay, one way. A non-UDP candidate is answered with
// nothing: the page drops it.
type delayRelays struct {
	t             *testing.T
	delay, jitter time.Duration
	// burstAt and burstN, if set, make the first relay to carry data
	// drop the burstN data-sized datagrams (over 1000 bytes) it reads
	// burstAt after its first, or those it reads in the following
	// burstMax if fewer: one burst loss in the test, at a moment it
	// chooses, which a sender that slows down doesn't prolong.
	burstAt   time.Duration
	burstN    int
	burstDone atomic.Bool

	mu     sync.Mutex
	relays map[string]string // target address → the relay's
}

func (rs *delayRelays) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// candidate:<foundation> <component> <protocol> <priority> <address> <port> typ <type> ...
	f := strings.Fields(string(b))
	if len(f) < 8 || !strings.EqualFold(f[2], "udp") {
		return
	}
	target := net.JoinHostPort(f[4], f[5])
	rs.mu.Lock()
	defer rs.mu.Unlock()
	addr, ok := rs.relays[target]
	if !ok {
		addr, err = rs.start(f[4], target)
		if err != nil {
			rs.t.Logf("relay for %s: %v", target, err)
			return
		}
		if rs.relays == nil {
			rs.relays = map[string]string{}
		}
		rs.relays[target] = addr
		rs.t.Logf("relay %s → %s, %v each way", addr, target, rs.delay)
	}
	host, port, _ := net.SplitHostPort(addr)
	f[4], f[5] = host, port
	io.WriteString(w, strings.Join(f, " "))
}

// start starts a relay to target, on host (the target's own, so the
// datagrams stay on its interface), and returns its address.
func (rs *delayRelays) start(host, target string) (string, error) {
	to, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return "", err
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return "", err
	}
	c.SetReadBuffer(16 << 20)
	c.SetWriteBuffer(16 << 20)
	line := make(chan delayed, 1<<17)
	var got, sent, failed, lateN int // lateN: sent over 5 ms late
	var late time.Duration
	done := make(chan struct{})
	rs.t.Cleanup(func() {
		c.Close()
		<-done
		rs.t.Logf("relay %v: %d datagrams read, %d sent, %d failed, %d over 5 ms late, at most %v", c.LocalAddr(), got, sent, failed, lateN, late)
	})
	go func() {
		defer close(done)
		for d := range line {
			waitUntil(d.due)
			l := time.Since(d.due)
			late = max(late, l)
			if l > 5*time.Millisecond {
				lateN++
			}
			if _, err := c.WriteToUDP(d.b, d.to); err != nil {
				failed++
			} else {
				sent++
			}
		}
	}()
	go func() {
		defer close(line)
		clock := delayClock{delay: rs.delay, jitter: rs.jitter}
		var other *net.UDPAddr
		var first, burstStart time.Time
		burst := 0
		const burstMax = 100 * time.Millisecond
		buf := make([]byte, 64<<10)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got++
			if first.IsZero() {
				first = time.Now()
			}
			if burst == 0 && n > 1000 && rs.burstN > 0 && time.Since(first) >= rs.burstAt && rs.burstDone.CompareAndSwap(false, true) {
				burst, burstStart = rs.burstN, time.Now()
				rs.t.Logf("relay %v: dropping a burst of %d data datagrams from %v", c.LocalAddr(), burst, time.Since(first).Round(time.Millisecond))
			}
			if burst > 0 && time.Since(burstStart) > burstMax {
				rs.t.Logf("relay %v: burst ended after %v with %d left", c.LocalAddr(), burstMax, burst)
				burst = -1
			}
			if burst > 0 && n > 1000 {
				burst--
				if burst == 0 {
					rs.t.Logf("relay %v: burst dropped by %v", c.LocalAddr(), time.Since(first).Round(time.Millisecond))
				}
				continue
			}
			dst := to
			if from.IP.Equal(to.IP) && from.Port == to.Port {
				if dst = other; dst == nil {
					continue
				}
			} else {
				other = from
			}
			line <- delayed{b: append([]byte(nil), buf[:n]...), to: dst, due: clock.due()}
		}
	}()
	return c.LocalAddr().String(), nil
}

// delayDERP returns a copy of dm whose DERP server the pages reach
// through a TCP proxy that holds what passes each way for delay (plus
// up to jitter), for the rest of the test. A packet relayed by DERP
// passes it twice, from one page and to the other.
func delayDERP(t *testing.T, dm *tailcfg.DERPMap, delay, jitter time.Duration) *tailcfg.DERPMap {
	t.Helper()
	j, _ := json.Marshal(dm)
	cp := new(tailcfg.DERPMap)
	if err := json.Unmarshal(j, cp); err != nil {
		t.Fatal(err)
	}
	n := cp.Regions[1].Nodes[0]
	upstream := net.JoinHostPort("127.0.0.1", strconv.Itoa(n.DERPPort))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pipe := func(dst, src net.Conn) {
		line := make(chan delayed, 4096)
		go func() {
			for d := range line {
				waitUntil(d.due)
				if _, err := dst.Write(d.b); err != nil {
					break
				}
			}
			dst.Close()
		}()
		clock := delayClock{delay: delay, jitter: jitter}
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				line <- delayed{b: append([]byte(nil), buf[:n]...), due: clock.due()}
			}
			if err != nil {
				close(line)
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	n.DERPPort = ln.Addr().(*net.TCPAddr).Port
	t.Logf("DERP through a proxy at %v, %v each way", ln.Addr(), delay)
	return cp
}

// rampSide is what a page records of a transfer for its ramp trace.
type rampSide struct {
	Ramp       []rampmetric.Point `json:"ramp"`
	PathEvents []struct {
		T    int64  `json:"t"`
		Path string `json:"path"`
	} `json:"pathEvents"`
	SendStart int64 `json:"sendStart"`
	// tailcat's samples (ramp-trace builds only).
	TCP json.RawMessage `json:"tcp"`
	RTC json.RawMessage `json:"rtc"`
}

// writeRampTrace reads each page's ramp trace, logs the transfer's ramp,
// and writes everything as JSON to path.
func writeRampTrace(t *testing.T, p *tabPair, path string) {
	t.Helper()
	// tailcat publishes its samples once a second.
	time.Sleep(1500 * time.Millisecond)
	read := func(tab context.Context) rampSide {
		var s string
		ctx, cancel := context.WithTimeout(tab, 20*time.Second)
		defer cancel()
		if err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify({
			ramp: window.tcTest.ramp || [], pathEvents: window.tcTest.pathEvents, sendStart: window.tcTest.sendStart || 0,
			tcp: JSON.parse((window.tailcatTestHooks || {}).rampTCP || "null"),
			rtc: JSON.parse((window.tailcatTestHooks || {}).rampRTC || "null")})`, &s)); err != nil {
			t.Errorf("reading the ramp trace: %v", err)
		}
		var side rampSide
		if err := json.Unmarshal([]byte(s), &side); err != nil {
			t.Errorf("reading the ramp trace: %v", err)
		}
		return side
	}
	listen, send := read(p.listen), read(p.send)
	m := rampmetric.Compute(listen.Ramp, send.SendStart)
	for _, e := range send.PathEvents {
		if e.Path == "webrtc" {
			m.Switch = float64(e.T-send.SendStart) / 1e3
			break
		}
	}
	t.Logf("ramp: steady %.1f MB/s, 50%% at %.2f s, 90%% at %.2f s, overall %.1f MB/s, WebRTC from %.2f s, %d stalls (%.1f s) from %.2f s",
		m.Steady, m.T50, m.T90, m.Total, m.Switch, m.Stalls, m.StalledSecs, m.StallAt)
	trace := map[string]any{
		"path":     *stressPath,
		"netemMs":  float64(*stressNetem) / float64(time.Millisecond),
		"relayMs":  float64(*stressRelay) / float64(time.Millisecond),
		"jitterMs": float64(*stressJitter) / float64(time.Millisecond),
		"cc":       *stressCC,
		"tags":     os.Getenv("TAILCAT_WASM_TAGS"),
		"variant":  os.Getenv("TAILCAT_RAMP_VARIANT"),
		"metrics":  m,
		"listen":   listen,
		"send":     send,
	}
	b, err := json.Marshal(trace)
	if err == nil {
		err = os.WriteFile(path, b, 0o644)
	}
	if err != nil {
		t.Errorf("writing %s: %v", path, err)
	}
	if math.IsNaN(m.Steady) {
		t.Errorf("ramp: no steady rate")
	}
}
