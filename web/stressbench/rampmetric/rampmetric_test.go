// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rampmetric

import "testing"

func TestCompute(t *testing.T) {
	// 1 MB per 250 ms (4 MB/s) after a second at a quarter of that: the
	// second from 0.5 s averages 2.5 MB/s, half the steady rate.
	var recv []Point
	var n int64
	for i := range 41 {
		recv = append(recv, Point{T: 1000 + int64(i)*250, Recv: n})
		if i < 4 {
			n += 250e3
		} else {
			n += 1e6
		}
	}
	m := Compute(recv, 1000)
	if m.Steady != 4 || m.T50 != 0.5 || m.T90 != 1 || m.Stalls != 0 || m.StallAt != -1 || m.T10 != -1 {
		t.Errorf("Compute = %+v; want steady 4, t50 0.5, t90 1, no stalls", m)
	}
}

func TestComputeStall(t *testing.T) {
	// 4 MB/s for 6 s, nothing for 3 s, then 1 MB/s for 4 s: the ramp is
	// the first 6 s's, and the stall is counted.
	var recv []Point
	var n int64
	for i := range 53 {
		recv = append(recv, Point{T: int64(i) * 250, Recv: n})
		switch {
		case i < 24:
			n += 1e6
		case i < 36:
		default:
			n += 250e3
		}
	}
	m := Compute(recv, 0)
	if m.Steady != 4 || m.T90 != 0 || m.Stalls != 1 || m.StallAt != 6 || m.StalledSecs != 3 {
		t.Errorf("Compute = %+v; want steady 4, t90 0, one 3 s stall at 6 s", m)
	}
}
