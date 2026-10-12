// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rtcpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func newLiveness() *Liveness {
	return &Liveness{
		SuspectAfter: 4 * time.Second,
		RestartAfter: 6 * time.Second,
		DeadAfter:    15 * time.Second,
		MaxTickGap:   6 * time.Second,
	}
}

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func at(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }

// TestLivenessOutage walks a path through an outage, ticking every 2 s:
// Suspect at 4 s without an answer, Restart (once) at 6, Dead at 15.
func TestLivenessOutage(t *testing.T) {
	l := newLiveness()
	want := []struct {
		at    float64
		state State
	}{
		{0, Healthy}, // the first ping starts the wait
		{2, Healthy},
		{4, Suspect},
		{6, Restart},
		{8, Suspect}, // Restart is reported once per outage
		{10, Suspect},
		{12, Suspect},
		{14, Suspect},
		{16, Dead},
	}
	for _, w := range want {
		if got, _ := l.Tick(at(w.at)); got != w.state {
			t.Fatalf("at %vs: %v; want %v", w.at, got, w.state)
		}
	}
}

// TestLivenessAnswered: answers keep a path Healthy, and an answer to
// any ping sent since the wait began ends it, while one to an older
// ping doesn't.
func TestLivenessAnswered(t *testing.T) {
	l := newLiveness()
	_, first := l.Tick(at(0))
	_, second := l.Tick(at(2))
	if l.Pong(second) {
		t.Errorf("Pong ended a suspicion on a Healthy path")
	}
	if st, _ := l.Tick(at(4)); st != Healthy {
		t.Fatalf("after an answer: %v; want Healthy", st)
	}
	// The wait now runs from the ping at 4 s: an answer to the one at
	// 0 s, arriving late, doesn't end it.
	l.Pong(first)
	l.Tick(at(6))
	if st, _ := l.Tick(at(8)); st != Suspect {
		t.Fatalf("a late answer to an older ping ended the wait: %v; want Suspect", st)
	}
}

// TestLivenessRecovers: an answer during an outage makes the path
// Healthy again, and the next outage gets a Restart of its own.
func TestLivenessRecovers(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0))
	l.Tick(at(2))
	l.Tick(at(4))
	st, seq := l.Tick(at(6))
	if st != Restart {
		t.Fatalf("at 6s: %v; want Restart", st)
	}
	if !l.Pong(seq) {
		t.Errorf("Pong during an outage didn't report recovery")
	}
	if l.Suspect() {
		t.Errorf("still Suspect after an answer")
	}
	if st, _ := l.Tick(at(8)); st != Healthy {
		t.Errorf("after recovering: %v; want Healthy", st)
	}
	for _, s := range []float64{10, 12} {
		l.Tick(at(s))
	}
	if st, _ := l.Tick(at(14)); st != Restart {
		t.Errorf("second outage: %v; want its own Restart", st)
	}
}

// TestLivenessAsleep: a long gap between ticks (this side's timers held
// back) neither kills the path nor counts against it, but holds
// traffic off it until a fresh ping is answered.
func TestLivenessAsleep(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0))
	st, seq := l.Tick(at(60))
	if st != Suspect {
		t.Fatalf("after a 60s gap: %v; want Suspect", st)
	}
	if st, _ := l.Tick(at(62)); st != Suspect {
		t.Fatalf("2s later: %v; want Suspect, not Dead", st)
	}
	if !l.Pong(seq) {
		t.Errorf("an answer to the fresh ping didn't end the suspicion")
	}
	if st, _ := l.Tick(at(64)); st != Healthy {
		t.Errorf("after the answer: %v; want Healthy", st)
	}
}

// TestLivenessMarkSuspect: ICE reporting the path disconnected makes it
// Suspect at once, and starts the clock toward Restart and Dead.
func TestLivenessMarkSuspect(t *testing.T) {
	l := newLiveness()
	_, seq := l.Tick(at(0))
	l.Pong(seq)
	l.MarkSuspect(at(1))
	if !l.Suspect() {
		t.Fatalf("not Suspect after MarkSuspect")
	}
	// The ping sent before the disconnect, answered late, doesn't prove
	// the path back.
	if l.Pong(seq) {
		t.Errorf("an answer to a ping from before the disconnect ended the suspicion")
	}
	if st, _ := l.Tick(at(2)); st != Suspect {
		t.Errorf("at 2s: %v; want Suspect", st)
	}
	if st, _ := l.Tick(at(7)); st != Restart {
		t.Errorf("at 7s: %v; want Restart", st)
	}
}

// TestLivenessNextSeq: after MarkSuspect, the answer to a ping sent at
// once, between ticks, ends the suspicion; one to an earlier ping
// doesn't.
func TestLivenessNextSeq(t *testing.T) {
	l := newLiveness()
	_, old := l.Tick(at(0))
	l.Pong(old)
	l.MarkSuspect(at(1))
	seq := l.NextSeq()
	if l.Pong(old) {
		t.Errorf("an answer to a ping from before MarkSuspect ended the suspicion")
	}
	if !l.Pong(seq) {
		t.Errorf("the answer to the ping sent at once didn't end the suspicion")
	}
	if st, _ := l.Tick(at(2)); st != Healthy {
		t.Errorf("after the answer: %v; want Healthy", st)
	}
}

// TestLivenessTakeRestart: a failure report allows one restart per
// outage, sharing it with Tick's Restart.
func TestLivenessTakeRestart(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0))
	if !l.TakeRestart(at(1)) {
		t.Fatalf("first TakeRestart refused")
	}
	if l.TakeRestart(at(2)) {
		t.Errorf("second TakeRestart in one outage allowed")
	}
	l.Tick(at(2))
	l.Tick(at(4))
	if st, _ := l.Tick(at(6)); st != Suspect {
		t.Errorf("at 6s after TakeRestart: %v; want Suspect, the restart already taken", st)
	}
}

func TestBackoff(t *testing.T) {
	b := &Backoff{Min: 2 * time.Second, Max: 60 * time.Second, MaxAfterUp: 15 * time.Second, HealthyFor: 30 * time.Second}
	var got []time.Duration
	for range 7 {
		got = append(got, b.Next(false, time.Second))
	}
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	for i := range want {
		want[i] *= time.Second
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("never up: %v; want %v", got, want)
	}

	// A path that carried traffic briefly keeps backing off, but no
	// further than MaxAfterUp from then on.
	if d := b.Next(true, 5*time.Second); d != 15*time.Second {
		t.Errorf("after a short-lived path: %v; want 15s", d)
	}
	// One that lasted starts over.
	if d := b.Next(true, time.Minute); d != 2*time.Second {
		t.Errorf("after a lasting path: %v; want 2s", d)
	}
	for range 5 {
		b.Next(false, time.Second)
	}
	if d := b.Next(false, time.Second); d != 15*time.Second {
		t.Errorf("failures after a path once worked: %v; want capped at 15s", d)
	}
	b.Reset()
	if d := b.Next(false, time.Second); d != 2*time.Second {
		t.Errorf("after Reset: %v; want 2s", d)
	}
}

// timeoutErr is an i/o timeout as the tunnel's TCP stack reports one.
type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestClassify(t *testing.T) {
	refused := &net.OpError{Op: "connect", Net: "tcp", Err: errors.New("connection was refused")}
	tests := []struct {
		name string
		got  SignalFailure
		want SignalFailure
	}{
		{"dial refused", ClassifyDial(refused), Refused},
		{"dial refused, wrapped", ClassifyDial(fmt.Errorf("dialing: %w", refused)), Refused},
		{"dial timed out", ClassifyDial(context.DeadlineExceeded), Unreachable},
		{"dial unreachable", ClassifyDial(&net.OpError{Op: "connect", Net: "tcp", Err: errors.New("no route to host")}), Unreachable},
		{"dial other", ClassifyDial(errors.New("not connected")), Unreachable},
		{"preamble timed out", ClassifyPreamble(&net.OpError{Op: "read", Net: "tcp", Err: timeoutErr{}}), Silent},
		{"preamble EOF", ClassifyPreamble(io.EOF), Dropped},
		{"preamble reset", ClassifyPreamble(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), Dropped},
		{"preamble closed", ClassifyPreamble(net.ErrClosed), Dropped},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: %v; want %v", tt.name, tt.got, tt.want)
		}
	}
}
