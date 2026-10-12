// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rtcpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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
	if l.Pong(second, t0) {
		t.Errorf("Pong ended a suspicion on a Healthy path")
	}
	if st, _ := l.Tick(at(4)); st != Healthy {
		t.Fatalf("after an answer: %v; want Healthy", st)
	}
	// The wait now runs from the ping at 4 s: an answer to the one at
	// 0 s, arriving late, doesn't end it.
	l.Pong(first, t0)
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
	if !l.Pong(seq, t0) {
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
	if !l.Pong(seq, t0) {
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
	l.Pong(seq, t0)
	l.MarkSuspect(at(1))
	if !l.Suspect() {
		t.Fatalf("not Suspect after MarkSuspect")
	}
	// The ping sent before the disconnect, answered late, doesn't prove
	// the path back.
	if l.Pong(seq, t0) {
		t.Errorf("an answer to a ping from before the disconnect ended the suspicion")
	}
	if st, _ := l.Tick(at(2)); st != Suspect {
		t.Errorf("at 2s: %v; want Suspect", st)
	}
	if st, _ := l.Tick(at(7)); st != Restart {
		t.Errorf("at 7s: %v; want Restart", st)
	}
}

// TestLivenessMarkSuspectOutstanding: a ping still unanswered when the
// path is marked Suspect can't end the suspicion, however late its
// answer comes, but the wait it started keeps its deadlines.
func TestLivenessMarkSuspectOutstanding(t *testing.T) {
	l := newLiveness()
	_, old := l.Tick(at(0)) // unanswered: the wait starts at 0s
	l.MarkSuspect(at(1))
	if l.Pong(old, t0) {
		t.Errorf("an answer to a ping sent before MarkSuspect ended the suspicion")
	}
	l.Tick(at(2))
	l.Tick(at(4))
	if st, _ := l.Tick(at(6)); st != Restart {
		t.Errorf("at 6s: %v; want Restart, 6s after the wait began at 0s", st)
	}
	l.MarkSuspect(at(7))
	seq := l.NextSeq()
	if !l.Pong(seq, t0) {
		t.Errorf("the answer to a ping sent after MarkSuspect didn't end the suspicion")
	}
}

// TestLivenessNextSeq: after MarkSuspect, the answer to a ping sent at
// once, between ticks, ends the suspicion; one to an earlier ping
// doesn't.
func TestLivenessNextSeq(t *testing.T) {
	l := newLiveness()
	_, old := l.Tick(at(0))
	l.Pong(old, t0)
	l.MarkSuspect(at(1))
	seq := l.NextSeq()
	if l.Pong(old, t0) {
		t.Errorf("an answer to a ping from before MarkSuspect ended the suspicion")
	}
	if !l.Pong(seq, t0) {
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

// TestLivenessRestarted: a restart begun for a reason of its own uses up
// the outage's restart, until an answer ends the outage.
func TestLivenessRestarted(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0))
	l.Restarted(at(1))
	if !l.Suspect() {
		t.Fatalf("not Suspect after Restarted")
	}
	if l.TakeRestart(at(2)) {
		t.Errorf("TakeRestart allowed a second restart in the outage")
	}
	l.Tick(at(2))
	l.Tick(at(4))
	if st, _ := l.Tick(at(6)); st != Suspect {
		t.Errorf("at 6s: %v; want Suspect, the restart already used", st)
	}
	_, seq := l.Tick(at(8))
	if !l.Pong(seq, t0) {
		t.Fatalf("the answer didn't end the outage")
	}
	if !l.TakeRestart(at(9)) {
		t.Errorf("the next outage didn't get a restart of its own")
	}
}

// TestLivenessAdaptive: once a round trip is measured, the wait before
// Suspect is six of them plus a second, within its bounds.
func TestLivenessAdaptive(t *testing.T) {
	l := newLiveness()
	l.MinSuspectAfter, l.MaxSuspectAfter = 3*time.Second, 8*time.Second
	_, seq := l.Tick(at(0))
	l.Pong(seq, at(0.05)) // a 50ms round trip: 1.3s, held at the 3s floor
	if got := l.RTT(); got != 50*time.Millisecond {
		t.Fatalf("RTT %v; want 50ms", got)
	}
	l.Tick(at(1))
	if st, _ := l.Tick(at(4.1)); st != Suspect {
		t.Errorf("3.1s into a wait held at the 3s floor: %v; want Suspect", st)
	}

	slow := newLiveness()
	slow.MinSuspectAfter, slow.MaxSuspectAfter = 3*time.Second, 8*time.Second
	_, seq = slow.Tick(at(0))
	slow.Pong(seq, at(1)) // a 1s round trip: 7s
	slow.Tick(at(2))
	if st, _ := slow.Tick(at(8)); st != Healthy {
		t.Errorf("6s into a wait on a 1s-RTT path: %v; want Healthy (7s allowed)", st)
	}
	if st, _ := slow.Tick(at(9.1)); st != Suspect {
		t.Errorf("7.1s into the wait: %v; want Suspect", st)
	}
}

// TestLivenessHeard: traffic arriving over the path postpones
// suspicion while the answers are late, but can't end a suspicion.
func TestLivenessHeard(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0))
	l.Heard(at(3))
	if st, _ := l.Tick(at(4)); st != Healthy {
		t.Fatalf("at 4s with traffic heard at 3s: %v; want Healthy", st)
	}
	if st, _ := l.Tick(at(7)); st != Suspect {
		t.Fatalf("at 7s, nothing heard for 4s: %v; want Suspect", st)
	}
	l.Heard(at(7.5))
	if st, _ := l.Tick(at(8)); st == Healthy {
		t.Errorf("traffic heard ended a suspicion")
	}
}

// TestLivenessHeardDeadlines: once traffic stops postponing a long-late
// answer, the path still goes Suspect, then Restart, then Dead, each
// timed from the last traffic, not from the unanswered ping.
func TestLivenessHeardDeadlines(t *testing.T) {
	l := newLiveness()
	l.Tick(at(0)) // never answered
	for s := 2.0; s <= 20; s += 2 {
		l.Heard(at(s - 0.5))
		if st, _ := l.Tick(at(s)); st != Healthy {
			t.Fatalf("at %vs, traffic heard at %vs: %v; want Healthy", s, s-0.5, st)
		}
	}
	// Last heard at 19.5s: Suspect after 4s, Restart after 6s, Dead after 15s.
	want := map[float64]State{22: Healthy, 24: Suspect, 26: Restart, 28: Suspect, 34: Suspect, 36: Dead}
	for s := 22.0; s <= 36; s += 2 {
		st, _ := l.Tick(at(s))
		if w, ok := want[s]; ok && st != w {
			t.Errorf("at %vs: %v; want %v", s, st, w)
		}
	}
}

// TestLivenessHold: a path that relapses soon after recovering must
// keep answering for a hold, doubling with each relapse, before traffic
// returns; one that stays healthy long enough loses the hold.
func TestLivenessHold(t *testing.T) {
	l := newLiveness()
	l.MinHold, l.MaxHold, l.StableFor = 5*time.Second, 30*time.Second, 60*time.Second
	l.Tick(at(0))
	l.MarkSuspect(at(1)) // first outage: no hold
	if !l.Pong(l.NextSeq(), at(1.1)) {
		t.Fatalf("first recovery held")
	}
	for s := 2.0; s <= 8; s += 2 { // ticking on time: not asleep
		_, seq := l.Tick(at(s))
		l.Pong(seq, at(s+0.1))
	}
	l.MarkSuspect(at(10)) // relapse 9s later: a 5s hold
	if l.Pong(l.NextSeq(), at(10.1)) {
		t.Fatalf("a relapse recovered at once")
	}
	if st, _ := l.Tick(at(12)); st != Suspect {
		t.Fatalf("during the hold: %v; want Suspect", st)
	}
	_, seq := l.Tick(at(14))
	l.Pong(seq, at(14.1))
	if st, _ := l.Tick(at(16)); st != Healthy {
		t.Fatalf("after the hold, still answering: %v; want Healthy", st)
	}
	l.MarkSuspect(at(20)) // another relapse: 10s
	l.Pong(l.NextSeq(), at(20.1))
	if st, _ := l.Tick(at(26)); st != Suspect {
		t.Fatalf("6s into a 10s hold: %v; want Suspect", st)
	}
	// A relapse during the hold cancels the recovery under way; the
	// hold, still 10s (the path never recovered), runs from the next
	// answer.
	l.MarkSuspect(at(27))
	l.Tick(at(28))
	l.Tick(at(30))
	_, seq = l.Tick(at(32))
	l.Pong(seq, at(32.1))
	for s := 34.0; s <= 42; s += 2 {
		st, seq := l.Tick(at(s))
		if st == Healthy {
			t.Fatalf("at %vs, inside the hold that ends at 42.1s: Healthy", s)
		}
		l.Pong(seq, at(s+0.1))
	}
	if st, _ := l.Tick(at(44)); st != Healthy {
		t.Fatalf("after the hold: %v; want Healthy", st)
	}
	// Healthy for a minute: the next outage starts without a hold.
	for s := 46.0; s <= 110; s += 2 {
		_, seq = l.Tick(at(s))
		l.Pong(seq, at(s+0.1))
	}
	l.MarkSuspect(at(111))
	if !l.Pong(l.NextSeq(), at(111.1)) {
		t.Errorf("an outage after a stable minute was held")
	}
}

// relapsed returns a Liveness whose path went Suspect again 9 s after
// recovering, at 10 s, and was answered at 10.1 s: its recovery waits
// out a 5 s hold, to 15.1 s.
func relapsed(t *testing.T) *Liveness {
	t.Helper()
	l := newLiveness()
	l.MinHold, l.MaxHold, l.StableFor = 5*time.Second, 30*time.Second, 60*time.Second
	l.Tick(at(0))
	l.MarkSuspect(at(1))
	if !l.Pong(l.NextSeq(), at(1.1)) {
		t.Fatalf("first recovery held")
	}
	for s := 2.0; s <= 8; s += 2 {
		_, seq := l.Tick(at(s))
		l.Pong(seq, at(s+0.1))
	}
	l.MarkSuspect(at(10))
	if l.Pong(l.NextSeq(), at(10.1)) {
		t.Fatalf("a relapse recovered at once")
	}
	return l
}

// TestLivenessHoldFails: a path that stops answering while its recovery
// waits out the hold never recovered, so the hold doesn't double: the
// next answer starts the same hold over.
func TestLivenessHoldFails(t *testing.T) {
	l := relapsed(t)
	l.Tick(at(12)) // unanswered from here
	l.Tick(at(14))
	st, seq := l.Tick(at(16)) // the hold ended at 15.1s, but the 12s ping is 4s late
	if st != Suspect {
		t.Fatalf("at 16s, pings unanswered since 12s: %v; want Suspect", st)
	}
	l.Pong(seq, at(16.1)) // the same 5s hold, to 21.1s
	for s := 18.0; s <= 20; s += 2 {
		st, seq := l.Tick(at(s))
		if st != Suspect {
			t.Fatalf("at %vs, inside the hold: %v; want Suspect", s, st)
		}
		l.Pong(seq, at(s+0.1))
	}
	if st, _ := l.Tick(at(22)); st != Healthy {
		t.Fatalf("at 22s, after a 5s hold: %v; want Healthy (the failed recovery doubled the hold)", st)
	}
}

// TestLivenessHoldExpires: a path that stayed healthy for StableFor after
// its last relapse drops the hold even when its next suspicion is this
// side's own (a timer gap), so an answer brings it straight back.
func TestLivenessHoldExpires(t *testing.T) {
	l := relapsed(t)
	for s := 12.0; s <= 80; s += 2 { // recovers at 16s, then a stable minute
		_, seq := l.Tick(at(s))
		l.Pong(seq, at(s+0.1))
	}
	st, seq := l.Tick(at(100)) // a hidden tab's 20s timer gap
	if st != Suspect {
		t.Fatalf("after a 20s gap: %v; want Suspect", st)
	}
	if !l.Pong(seq, at(100.1)) {
		t.Errorf("a path stable for a minute was held after a timer gap")
	}
}

// TestLivenessHoldThrottled: this side's timer gaps (a hidden tab's
// throttled timers) neither cancel a recovery waiting out its hold nor
// impose one: with ticks ten seconds apart and each fresh ping answered
// at once, a held path returns once its hold has passed, and a path that
// went Suspect only for a gap returns on the first answer.
func TestLivenessHoldThrottled(t *testing.T) {
	l := relapsed(t) // holding until 15.1s
	st, seq := l.Tick(at(20))
	if st != Suspect {
		t.Fatalf("after a 12s gap: %v; want Suspect", st)
	}
	if !l.Pong(seq, at(20.1)) {
		t.Fatalf("an answer after the hold had passed, across a timer gap, didn't recover the path")
	}
	_, seq = l.Tick(at(30)) // another gap, 10s after recovering: no relapse
	if !l.Pong(seq, at(30.1)) {
		t.Errorf("a path Suspect only for a timer gap was held")
	}
}

// TestLivenessHoldGapNeedsAnswer: a timer gap keeps a held recovery's
// deadline, but only an answer to a ping sent since the gap completes
// it: the path may have stopped answering meanwhile.
func TestLivenessHoldGapNeedsAnswer(t *testing.T) {
	l := relapsed(t) // holding until 15.1s
	l.Tick(at(20))   // a gap; its fresh ping goes unanswered
	st, seq := l.Tick(at(22))
	if st != Suspect {
		t.Fatalf("2s after a gap, the hold passed but nothing answered since: %v; want Suspect", st)
	}
	if !l.Pong(seq, at(22.1)) {
		t.Errorf("an answer after the gap, the hold passed, didn't recover the path")
	}
}

// TestLivenessSlowRTT: a round trip longer than the ping interval is
// measured, each answer timed against its own ping, and a path that
// answers every ping that slowly stays Healthy.
func TestLivenessSlowRTT(t *testing.T) {
	l := newLiveness()
	l.SuspectAfter = 6 * time.Second
	l.MinSuspectAfter, l.MaxSuspectAfter = 3*time.Second, 8*time.Second
	const rtt = 4.1
	type ping struct {
		seq uint32
		at  float64
	}
	var out []ping // in the order sent, so in the order answered
	for s := 0.0; s <= 40; s += 2 {
		for len(out) > 0 && out[0].at+rtt <= s {
			l.Pong(out[0].seq, at(out[0].at+rtt))
			out = out[1:]
		}
		st, seq := l.Tick(at(s))
		if st != Healthy {
			t.Fatalf("at %vs, every ping answered in %vs: %v; want Healthy", s, rtt, st)
		}
		out = append(out, ping{seq, s})
	}
	if got := l.RTT(); got < 4*time.Second || got > 4200*time.Millisecond {
		t.Errorf("RTT %v; want about 4.1s", got)
	}
}

func TestCheckDataOnly(t *testing.T) {
	const head = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n"
	data := "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n"
	if err := CheckDataOnly(head + data); err != nil {
		t.Errorf("data-only description refused: %v", err)
	}
	for name, sdp := range map[string]string{
		"audio": head + "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" + data,
		"video": head + data + "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
		"two":   head + data + data,
		"none":  head,
		"empty": "",
		"lf":    strings.ReplaceAll(head+"m=video 9 UDP/TLS/RTP/SAVPF 96\r\n", "\r", ""),
	} {
		if err := CheckDataOnly(sdp); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
