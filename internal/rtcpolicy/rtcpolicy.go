// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package rtcpolicy decides, for the browser build's WebRTC packet path
// (web/webrtc_js.go), when a path stops being trusted, when to restart
// its ICE or give up on it, what a failed signaling attempt says about
// the server, and how long to wait before negotiating again. It is
// plain Go, apart from the js/wasm code that uses it, so that it can be
// tested natively.
package rtcpolicy

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// State is what a Liveness makes of its path.
type State int

const (
	// Healthy: the path answers; send over it.
	Healthy State = iota
	// Suspect: the path hasn't answered for a while. Send over the
	// relay instead, and keep pinging: an answer makes it Healthy again.
	Suspect
	// Restart is Suspect, reported once per outage when it has lasted
	// long enough that the offering side should restart ICE.
	Restart
	// Dead: the path has been silent too long. End the session.
	Dead
)

func (s State) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Suspect:
		return "suspect"
	case Restart:
		return "restart"
	case Dead:
		return "dead"
	}
	return "unknown"
}

// Liveness tracks whether a path answers the pings sent over it. Its
// zero value is not usable; set the durations. It is not safe for
// concurrent use.
type Liveness struct {
	// SuspectAfter is how long the oldest unanswered ping may wait
	// before the path is Suspect, RestartAfter before it is reported as
	// Restart, and DeadAfter before it is Dead.
	//
	// If MaxSuspectAfter is set, SuspectAfter is only the wait used
	// until a round trip has been measured: from then on it is six
	// smoothed round trips plus a second, held between MinSuspectAfter
	// and MaxSuspectAfter, so a slow path isn't judged by a fast one's
	// clock, nor a fast one left unwatched. RestartAfter is then at
	// least two seconds past it.
	SuspectAfter, RestartAfter, DeadAfter time.Duration
	MinSuspectAfter, MaxSuspectAfter      time.Duration
	// MaxTickGap is the longest expected gap between Tick calls. A
	// longer one means this side's timers were held back (a hidden
	// tab's are throttled), so the time in between isn't held against
	// the peer: the wait starts over, from a fresh ping, with the path
	// Suspect until that is answered.
	MaxTickGap time.Duration
	// MinHold and MaxHold bound how long a path that went Suspect again
	// within StableFor of recovering must keep answering before traffic
	// returns to it: the hold starts at MinHold and doubles with each
	// such relapse, and a path that stays healthy for StableFor drops
	// it. A path that flaps (a congested uplink, a link that comes and
	// goes) then settles on the relay instead of dragging the tunnel's
	// traffic back and forth. Zero MaxHold disables the hold. Only a
	// relapse is held: a path Suspect because this side's timers were
	// held back returns on the first answer to a fresh ping.
	MinHold, MaxHold, StableFor time.Duration

	seq       uint32
	waitSeq   uint32    // the ping that started the current wait
	waitStart time.Time // when it was sent; zero if no ping is unanswered
	lastTick  time.Time
	suspect   bool
	restarted bool // Restart was reported in the current outage

	// The pings Tick asked for lately, by sequence number modulo
	// rttSlots, so that a round trip longer than the ping interval is
	// still measured: each answer is timed against its own ping.
	sent      [rttSlots]sentPing
	srtt      time.Duration
	lastHeard time.Time // when traffic last arrived over the path

	hold          time.Duration // the hold a relapse's recovery waits out
	held          bool          // the current outage is a relapse: its recovery waits out the hold
	recoverAt     time.Time     // a recovery waiting out its hold, if non-zero
	gapped        bool          // a timer gap since the last answer: recovery waits for a fresh one
	lastRecovered time.Time
}

// rttSlots is how many of the latest pings are kept for timing their
// answers: at a ping every two seconds, round trips up to sixteen.
const rttSlots = 8

type sentPing struct {
	seq uint32
	at  time.Time // zero once answered
}

// suspectAfter is how long the oldest unanswered ping may wait before
// the path is Suspect.
func (l *Liveness) suspectAfter() time.Duration {
	if l.MaxSuspectAfter == 0 || l.srtt == 0 {
		return l.SuspectAfter
	}
	return min(max(6*l.srtt+time.Second, l.MinSuspectAfter), l.MaxSuspectAfter)
}

func (l *Liveness) restartAfter() time.Duration {
	return max(l.RestartAfter, l.suspectAfter()+2*time.Second)
}

// RTT returns the smoothed round trip of the path's pings, or zero if
// none has been measured.
func (l *Liveness) RTT() time.Duration { return l.srtt }

// Tick is called at each ping interval. It returns the path's state and
// the sequence number of the ping to send now. It returns Healthy for a
// Suspect path whose recovery has waited out its hold; the caller sees
// the change from Suspect.
func (l *Liveness) Tick(now time.Time) (State, uint32) {
	l.seq++
	seq := l.seq
	l.sent[seq%rttSlots] = sentPing{seq, now}
	asleep := !l.lastTick.IsZero() && now.Sub(l.lastTick) > l.MaxTickGap
	l.lastTick = now
	if asleep {
		l.waitStart, l.waitSeq = now, seq
		l.gapped = true
		l.becomeSuspect(now, false)
		return Suspect, seq
	}
	if l.waitStart.IsZero() {
		l.waitStart, l.waitSeq = now, seq
	}
	if !l.suspect && l.lastHeard.After(l.waitStart) {
		// Traffic arriving over the path shows it still works while
		// the pings' answers are late (queued behind that traffic, say).
		// It postpones suspicion, but can't end it: only an answer
		// proves the way there works too. The wait is timed from the
		// traffic on, so that once suspicion begins, Restart and Dead
		// still follow it in turn.
		l.waitStart = l.lastHeard
	}
	waited := now.Sub(l.waitStart)
	if l.suspect && !l.recoverAt.IsZero() {
		switch {
		case waited >= l.suspectAfter():
			// The path stopped answering again while its recovery waited
			// out the hold: that recovery never happened, so it is
			// neither recorded nor counted as a relapse. The next answer
			// starts the same hold over.
			l.recoverAt = time.Time{}
		case !l.gapped && !now.Before(l.recoverAt):
			// The hold has passed, and nothing since the last answer says
			// the path stopped: a timer gap since then leaves it to the
			// answer to the gap's fresh ping (see Pong).
			l.recover(now)
		}
	}
	switch {
	case waited >= l.DeadAfter:
		return Dead, seq
	case waited >= l.restartAfter() && !l.restarted:
		l.restarted = true
		l.becomeSuspect(now, true)
		return Restart, seq
	case waited >= l.suspectAfter():
		l.becomeSuspect(now, true)
	}
	if l.suspect {
		return Suspect, seq
	}
	return Healthy, seq
}

// becomeSuspect marks the path Suspect. relapse is false when the cause
// is this side's own (throttled timers): that isn't held against the
// path, so it neither cancels a recovery waiting out its hold (the time
// in between counts toward it) nor starts a hold of its own, though a
// path that has stayed healthy for StableFor still drops its old hold.
// A relapse cancels a recovery under way, and one soon after the last
// recovery makes this outage's recovery wait out a doubled hold.
func (l *Liveness) becomeSuspect(now time.Time, relapse bool) {
	if relapse {
		l.recoverAt = time.Time{}
	}
	if l.suspect {
		return
	}
	l.suspect, l.held = true, false
	if l.MaxHold == 0 {
		return
	}
	switch {
	case l.lastRecovered.IsZero() || now.Sub(l.lastRecovered) >= l.StableFor:
		l.hold = 0
	case relapse:
		l.hold = min(max(2*l.hold, l.MinHold), l.MaxHold)
		l.held = true
	}
}

func (l *Liveness) recover(now time.Time) {
	l.suspect, l.restarted = false, false
	l.recoverAt = time.Time{}
	l.lastRecovered = now
}

// Heard records traffic arriving over the path now (see Tick).
func (l *Liveness) Heard(now time.Time) { l.lastHeard = now }

// Pong records the answer to ping seq, received now. An answer to any
// ping sent since the current wait began ends it: later pings may still
// be queued behind data on a slow uplink. It reports whether the path
// was Suspect and traffic may return to it now; a path that relapsed
// soon after its last recovery returns only once it has kept answering
// for its hold (Tick finds it so, or an answer comes after the hold).
func (l *Liveness) Pong(seq uint32, now time.Time) (recovered bool) {
	if p := &l.sent[seq%rttSlots]; p.seq == seq && !p.at.IsZero() {
		if rtt := now.Sub(p.at); rtt >= 0 {
			if l.srtt == 0 {
				l.srtt = rtt
			} else {
				l.srtt = (7*l.srtt + rtt) / 8
			}
		}
		p.at = time.Time{}
	}
	if l.waitStart.IsZero() || int32(seq-l.waitSeq) < 0 {
		return false
	}
	l.waitStart = time.Time{}
	l.gapped = false
	if !l.suspect {
		return false
	}
	if l.held {
		if l.recoverAt.IsZero() {
			l.recoverAt = now.Add(l.hold)
		}
		if now.Before(l.recoverAt) {
			return false
		}
	}
	l.recover(now)
	return true
}

// MarkSuspect makes the path Suspect at once, as when ICE reports it
// disconnected, and starts the wait for an answer if none is under way.
// Only a ping sent from now on can end the suspicion: the answer to an
// earlier one may have left the peer before the path broke. A wait
// already under way keeps its start, and so its deadlines.
func (l *Liveness) MarkSuspect(now time.Time) {
	l.becomeSuspect(now, true)
	l.waitSeq = l.seq + 1 // the next ping's
	if l.waitStart.IsZero() {
		l.waitStart = now
	}
}

// NextSeq returns the sequence number for a ping sent between ticks, as
// one sent at once to check a path that may just have broken. Sent after
// MarkSuspect, its answer ends the suspicion.
func (l *Liveness) NextSeq() uint32 {
	l.seq++
	return l.seq
}

// TakeRestart reports whether a restart may be tried now, as when ICE
// reports the path failed: true unless one was already tried in the
// current outage. It marks the path Suspect.
func (l *Liveness) TakeRestart(now time.Time) bool {
	l.MarkSuspect(now)
	if l.restarted {
		return false
	}
	l.restarted = true
	return true
}

// Restarted records a restart begun now for a reason of its own, as a
// network change: it marks the path Suspect and uses up the current
// outage's restart, so neither Tick nor TakeRestart starts another on
// top of it.
func (l *Liveness) Restarted(now time.Time) {
	l.MarkSuspect(now)
	l.restarted = true
}

// Suspect reports whether traffic should stay off the path.
func (l *Liveness) Suspect() bool { return l.suspect }

// Backoff paces a client's attempts to negotiate a path. Its zero value
// is not usable; set the durations.
type Backoff struct {
	// Min is the first wait, which doubles after each attempt up to
	// Max, or up to MaxAfterUp once any session has carried traffic (the
	// two networks can reach each other, so a lost path is worth
	// winning back sooner).
	Min, Max, MaxAfterUp time.Duration
	// HealthyFor is how long a path that carried traffic must have
	// lasted, from when it came up, for the next wait to start over from
	// Min. A path that keeps failing soon after it comes up keeps backing
	// off, however long its negotiation took.
	HealthyFor time.Duration

	next   time.Duration
	everUp bool
}

// Next returns how long to wait before the next attempt, given how the
// last one went: up reports whether its path carried traffic, and
// lasted how long, from when it came up to when its session ended.
func (b *Backoff) Next(up bool, lasted time.Duration) time.Duration {
	ceiling := b.Max
	if up {
		b.everUp = true
		if lasted >= b.HealthyFor {
			b.next = 0
		}
	}
	if b.everUp {
		ceiling = b.MaxAfterUp
	}
	if b.next == 0 {
		b.next = b.Min
	} else {
		b.next = min(2*b.next, ceiling)
	}
	return b.next
}

// Reset makes the next wait the shortest, as after a network change,
// when an attempt that failed before may now succeed.
func (b *Backoff) Reset() { b.next = 0 }

// Shedder decides which datagrams a path drops while its send buffer is
// full. Inner TCP learns of congestion only from loss, so the path must
// drop something, but how much matters: a full window lost at once (every
// datagram while the buffer is above a line, as a full UDP socket does)
// leaves gVisor's TCP in a retransmission timeout that resends a segment
// or two per timeout, for minutes, while the connection looks healthy. One
// drop at a time is a signal TCP answers with fast recovery, halving its
// window, so the buffer drains back below the line.
//
// The line is a time, not a size: the bytes the path drains in Target, at
// the rate the Shedder measures it draining. A byte count suits one
// path's speed only: what a fast path drains in a few milliseconds is
// seconds of queue on a slow uplink, and the tunnel's round trips, and
// everything waiting behind the queue, grow by that much. Its zero value
// is not usable; set the fields. It is not safe for concurrent use.
type Shedder struct {
	// Target is how long, at the path's measured rate, the buffered
	// bytes may take to drain before the Shedder sheds.
	Target time.Duration
	// The line is never below MinLimit bytes, so that a slow path still
	// holds a few datagrams, nor above HardLimit; it is InitialLimit
	// until the rate is measured. Above HardLimit every datagram is
	// dropped. HardLimit belongs above what one TCP connection can have
	// in flight, so that a hidden tab's late view of its buffer, or a
	// burst, doesn't reach it.
	MinLimit, InitialLimit, HardLimit int
	// Once the buffer has stayed above the line for Every, one datagram
	// is dropped every Every while it does. A burst, as a TCP window
	// sent at once after a long round trip, crosses the line and drains
	// within milliseconds: only a queue that stands is shed, as CoDel
	// does, or every burst would cost TCP half its window.
	Every time.Duration
	// WarmSamples is how many intervals the rate must have been measured
	// over before the line may fall below InitialLimit. A path's first
	// measurements come while the tunnel's TCP and the path itself (a
	// DataChannel's SCTP) are both still ramping up, and say little of
	// what it can carry; shedding by them cuts TCP's window long before
	// the path is full. 0 trusts the first.
	WarmSamples int

	aboveSince time.Time // when the buffer last went above the line; zero while below
	measured   int       // intervals measured, up to WarmSamples
	last       time.Time // of the last drop above the line

	samples  [rateSamples]float64 // the latest drain rates measured, bytes per second
	next     int                  // index in samples of the next one
	sampleAt time.Time            // when buffered was last sampled for the rate
	sampled  int                  // buffered bytes then
	added    int                  // bytes sent since then
}

const (
	// rateSampleEvery is the shortest interval over which a Shedder
	// measures its path's drain rate. A page's view of a buffer moves
	// only between its tasks, so shorter intervals measure the page,
	// not the path.
	rateSampleEvery = 50 * time.Millisecond
	// rateSamples is how many of its latest measurements a Shedder
	// takes the path's rate from: the fastest of them, since a buffer
	// that empties partway through an interval drains less than the
	// path could carry, and no interval measures more than it can.
	// When a path slows, its line follows once the faster measurements
	// have aged out, after rateSamples backlogged intervals: meanwhile
	// its queue may hold up to that long (half a second) at the slower
	// rate, still within HardLimit.
	rateSamples = 10
)

// Drop reports whether to drop a datagram of size bytes sent at now, with
// buffered bytes waiting in the path ahead of it. The datagram's size
// counts toward the drain rate unless it is dropped.
func (s *Shedder) Drop(buffered, size int, now time.Time) bool {
	s.measure(buffered, now)
	drop := false
	switch {
	case buffered > s.HardLimit:
		drop = true
	case buffered <= s.Limit():
		s.aboveSince = time.Time{}
	case s.aboveSince.IsZero():
		s.aboveSince = now
	case now.Sub(s.aboveSince) < s.Every:
	case !s.last.IsZero() && now.Sub(s.last) < s.Every:
	default:
		s.last = now
		drop = true
	}
	if !drop {
		s.added += size
	}
	return drop
}

// measure takes a drain rate from buffered, the path's buffer at now.
// Only an interval that began and ended with bytes waiting counts: an
// empty buffer drains no faster than it is filled, which says nothing of
// what the path could carry.
func (s *Shedder) measure(buffered int, now time.Time) {
	if s.sampleAt.IsZero() {
		s.sampleAt, s.sampled = now, buffered
		return
	}
	dt := now.Sub(s.sampleAt)
	if dt < rateSampleEvery {
		return
	}
	if drained := s.sampled + s.added - buffered; s.sampled > 0 && buffered > 0 && drained > 0 {
		s.samples[s.next] = float64(drained) / dt.Seconds()
		s.next = (s.next + 1) % rateSamples
		s.measured = min(s.measured+1, s.WarmSamples)
	}
	s.sampleAt, s.sampled, s.added = now, buffered, 0
}

// Limit returns the buffered bytes above which the Shedder sheds: what
// the path drains in Target at its measured rate, within MinLimit and
// HardLimit, and no lower than InitialLimit until the rate has been
// measured WarmSamples times.
func (s *Shedder) Limit() int {
	r := s.Rate()
	if r == 0 {
		return s.InitialLimit
	}
	l := max(int(r*s.Target.Seconds()), s.MinLimit)
	if s.measured < s.WarmSamples {
		l = max(l, s.InitialLimit)
	}
	return min(l, s.HardLimit)
}

// Tune sets the Shedder's parameters from spec, comma-separated
// key=value pairs: target and every (durations), min, init and hard
// (bytes), and warm (WarmSamples). It is for experiments, such as the
// browser stress test's A/B runs.
func (s *Shedder) Tune(spec string) error {
	for kv := range strings.SplitSeq(spec, ",") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		var err error
		var n int
		switch k {
		case "target":
			s.Target, err = time.ParseDuration(v)
		case "every":
			s.Every, err = time.ParseDuration(v)
		case "min", "init", "hard", "warm":
			n, err = strconv.Atoi(v)
			switch k {
			case "min":
				s.MinLimit = n
			case "init":
				s.InitialLimit = n
			case "hard":
				s.HardLimit = n
			case "warm":
				s.WarmSamples = n
			}
		default:
			err = errors.New("unknown parameter")
		}
		if err != nil {
			return fmt.Errorf("shedder tuning %q: %v", kv, err)
		}
	}
	return nil
}

// Rate returns the drain rate the Shedder has measured, in bytes per
// second; 0 until it has.
func (s *Shedder) Rate() float64 { return slices.Max(s.samples[:]) }

// CheckDataOnly reports an error unless sdp describes a data channel
// session and nothing else: exactly one media section, and that an
// "application" one. The tunnel carries only datagrams, so a
// description that asks for audio or video (or anything a browser might
// add later) is refused rather than negotiated.
func CheckDataOnly(sdp string) error {
	n := 0
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "m=") {
			continue
		}
		n++
		if !strings.HasPrefix(line, "m=application ") {
			return errors.New("description has a non-data media section: " + strings.Fields(line)[0])
		}
	}
	if n != 1 {
		return errors.New("description has " + strconv.Itoa(n) + " media sections; want one data section")
	}
	return nil
}

// SignalFailure is what a failed attempt to open a signaling stream says
// about the server.
type SignalFailure int

const (
	// Unreachable: the attempt couldn't reach the server (the tunnel is
	// down for now). It says nothing about the server; try again.
	Unreachable SignalFailure = iota
	// Refused: the server refused the signaling port, as one with
	// WebRTC off does. Don't try again.
	Refused
	// Silent: the server accepted the stream but never answered the
	// preamble, as a server that isn't the web app (a native tailcat
	// server, writing what it receives to its output) does. Don't try
	// again: each attempt would write the preamble to it once more.
	Silent
	// Dropped: the server accepted the stream and then closed or reset
	// it unanswered, as a web server does when it can't place the
	// stream or is pacing its sessions. Try again, a few times.
	Dropped
)

func (f SignalFailure) String() string {
	switch f {
	case Unreachable:
		return "unreachable"
	case Refused:
		return "refused"
	case Silent:
		return "silent"
	case Dropped:
		return "dropped"
	}
	return "unknown"
}

// ClassifyDial classifies the error from dialing the signaling port.
// The tunnel's TCP stack reports a reset answering the dial as a
// connect error reading "connection was refused"; anything else, a
// timeout above all, means the server wasn't reached.
func ClassifyDial(err error) SignalFailure {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "connect" && oe.Err != nil &&
		strings.Contains(oe.Err.Error(), "refused") {
		return Refused
	}
	return Unreachable
}

// ClassifyPreamble classifies the error from the preamble exchange on a
// signaling stream that the server accepted: a timeout (the deadline
// passed with no answer) means a server that doesn't speak it, and
// anything else (end of stream, a reset) one that dropped the stream.
func ClassifyPreamble(err error) SignalFailure {
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return Silent
	}
	return Dropped
}
