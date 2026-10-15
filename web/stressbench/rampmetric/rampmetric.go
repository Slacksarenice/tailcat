// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package rampmetric measures how a browser stress test's transfer
// ramped up (TestBrowserWebRTCStress --web-stress-trace), from the
// receiving page's progress every 250 ms. The test and rampsum.go share
// it, so a trace's metrics can be recomputed as they change.
package rampmetric

import "slices"

// Point is a page's transfer progress at T (Unix ms).
type Point struct {
	T    int64 `json:"t"`
	Sent int64 `json:"sent"`
	Recv int64 `json:"recv"`
}

// Metrics is how a transfer ramped up, in seconds from its start.
type Metrics struct {
	Steady float64 `json:"steadyMBps"` // the median 250 ms rate over the last third
	T50    float64 `json:"t50"`        // when the rate first held 50% of Steady for a second
	T90    float64 `json:"t90"`        // and 90%
	Switch float64 `json:"switch"`     // when the sender's traffic moved to WebRTC; -1 if never
	Total  float64 `json:"totalMBps"`  // bytes over the transfer's time
	// Stalls counts the times nothing arrived for 2 s or more, after
	// something had; the first began at StallAt (-1 if none). Steady,
	// T50 and T90 are measured before it.
	Stalls      int     `json:"stalls"`
	StallAt     float64 `json:"stallAt"`
	StalledSecs float64 `json:"stalledSecs"`
	// T10 and T20 are when the rate first held 10 and 20 MB/s for a
	// second, -1 if it never did: unlike T50 and T90, they don't depend
	// on what the run settled at.
	T10 float64 `json:"t10"`
	T20 float64 `json:"t20"`
}

type bucket struct {
	t    float64 // the bucket's start, seconds from t0
	rate float64 // MB/s
}

// heldFrom returns the first bucket's start from which the mean rate
// over the next second is at least rate, or -1.
func heldFrom(bs []bucket, rate float64) float64 {
	for i := range bs {
		var sum float64
		n := 0
		for j := i; j < len(bs) && bs[j].t < bs[i].t+1; j++ {
			sum += bs[j].rate
			n++
		}
		if sum/float64(n) >= rate {
			return bs[i].t
		}
	}
	return -1
}

// Compute measures a transfer's ramp from the receiving page's
// progress, from t0, when the sender started. Switch is left -1.
func Compute(recv []Point, t0 int64) Metrics {
	m := Metrics{T50: -1, T90: -1, Switch: -1, StallAt: -1, T10: -1, T20: -1}
	var bs []bucket
	end := -1
	for i, p := range recv {
		if i > 0 && p.Recv > recv[i-1].Recv {
			end = i
		}
	}
	for i := 1; i <= end; i++ {
		a, b := recv[i-1], recv[i]
		if a.T < t0 || b.T <= a.T {
			continue
		}
		bs = append(bs, bucket{float64(a.T-t0) / 1e3, float64(b.Recv-a.Recv) / float64(b.T-a.T) / 1e3})
	}
	if len(bs) < 8 {
		return m
	}
	m.Total = float64(recv[end].Recv) / (float64(recv[end].T-t0) / 1e3) / 1e6
	m.T10, m.T20 = heldFrom(bs, 10), heldFrom(bs, 20)
	// A stall: stallBuckets or more in a row with nothing received, once
	// something was. The ramp is measured before the first one: a stalled
	// path's last third says nothing of the rate it ramped to.
	const stallBuckets = 8 // 2 s
	moving, zeros, cut := false, 0, len(bs)
	for i, b := range bs {
		if b.rate > 0 {
			moving = true
			if zeros >= stallBuckets {
				m.Stalls++
				m.StalledSecs += float64(zeros) / 4
			}
			zeros = 0
			continue
		}
		if !moving {
			continue
		}
		if zeros++; zeros == stallBuckets && m.StallAt < 0 {
			m.StallAt = bs[i-stallBuckets+1].t
			cut = i - stallBuckets + 1
		}
	}
	if zeros >= stallBuckets {
		m.Stalls++
		m.StalledSecs += float64(zeros) / 4
	}
	if cut < 8 {
		return m
	}
	bs = bs[:cut]
	last := bs[len(bs)-1].t
	var tail []float64
	for _, b := range bs[:len(bs)-4] { // not the last second, as the sender stops
		if b.t >= last*2/3 {
			tail = append(tail, b.rate)
		}
	}
	if len(tail) == 0 {
		return m
	}
	slices.Sort(tail)
	m.Steady = tail[len(tail)/2]
	m.T50, m.T90 = heldFrom(bs, 0.5*m.Steady), heldFrom(bs, 0.9*m.Steady)
	return m
}
