// tailcat's Worker: runs the tailcat WebAssembly module (main_js.go) off
// the page's thread. tailcat.js starts it and is the page's side of
// everything here: the API calls it forwards, and the peer connections
// it holds for the Worker. Plain JavaScript, no build step; a classic
// worker script.
//
// Messages from the page:
//
//	{t: "start", module, hooks, connType}  run module (a WebAssembly.Module)
//	{t: "probe", dc}                       a DataChannel tailcat.js handed over to see if it can
//	{t: "call", id, fn, sub, obj, opts, args}  an API call (see call below)
//	{t: "pcReply", id, ok, value, error, state}  a peer connection's answer to a call
//	{t: "pcEvent", pc, type, ev, state}    a peer connection's event
//	{t: "net", event, type}                the page's online event, or navigator.connection's change
//	{t: "hook", k, v}                      the page set tailcatTestHooks[k] = v
//	{t: "credit", conn, n}                 the page read n bytes of what a conn read ahead
//
// and to it:
//
//	{t: "ready"}, {t: "exit", error}       the module started, or stopped (or failed to start)
//	{t: "result", id, ok, value, error}    an API call's result
//	{t: "event", sub, kind, conn, payload} a listener's connection, or a path's change or stats
//	{t: "data", conn, data | eof | error}  what a conn read ahead (see pump), its end, or its error
//	{t: "pc", pc, id, op, args}            a call on a peer connection; id if it wants a reply
//	{t: "log", level, args}                console output, the Go program's included
//	{t: "hook", k, v}                      the Go side set tailcatTestHooks[k] = v
"use strict";

importScripts("wasm_exec.js");

const post = (msg, transfer) => self.postMessage(msg, transfer || []);

// Console output goes to the page, whose console is where its developers
// and tests look; the Go program's log lines arrive there as before.
for (const level of ["log", "info", "warn", "error", "debug"]) {
  self.console[level] = (...args) => post({ t: "log", level, args: args.map(String) });
}

const errorMessage = (err) => String((err && err.message) || err);

// --- Peer connections ---

// TailcatPeerConnection stands in for RTCPeerConnection, which Workers
// don't have; webrtc_js.go uses it in its place (peerConnectionCtor).
// The page holds the real connection: this forwards calls to it and its
// events back, keeping the copy of its state that the page sends with
// every reply and event, so a property the Go side reads after a call or
// in an event handler is as the call or event left it. The DataChannels
// are the browser's own: the page hands each to this Worker as it is
// created, so the tunnel's datagrams never cross the page's thread.
const pcs = new Map(); // id → TailcatPeerConnection
const pcCalls = new Map(); // call id → {pc, resolve, reject}
let nextPC = 1;
let nextPCCall = 1;

class TailcatPeerConnection {
  constructor(config) {
    this.id = nextPC++;
    this.signalingState = "stable";
    this.connectionState = "new";
    this.iceConnectionState = "new";
    this.iceGatheringState = "new";
    this.localDescription = null;
    this.remoteDescription = null;
    pcs.set(this.id, this);
    post({ t: "pc", pc: this.id, op: "new", args: [config] });
  }

  call(op, args) {
    return new Promise((resolve, reject) => {
      const id = nextPCCall++;
      pcCalls.set(id, { pc: this, resolve, reject });
      post({ t: "pc", pc: this.id, id, op, args });
    });
  }

  // createDataChannel resolves to the channel, which the page creates and
  // hands over; RTCPeerConnection's returns it at once.
  createDataChannel(label, opts) {
    return this.call("createDataChannel", [label, opts]);
  }

  setLocalDescription(desc) {
    return this.call("setLocalDescription", desc === undefined ? [] : [desc]);
  }

  setRemoteDescription(desc) {
    return this.call("setRemoteDescription", [desc]);
  }

  addIceCandidate(cand) {
    return this.call("addIceCandidate", [cand]);
  }

  // getStats resolves to a Map of the stats by id, which reads like an
  // RTCStatsReport.
  async getStats() {
    const list = await this.call("getStats", []);
    return new Map(list.map((s) => [s.id, s]));
  }

  restartIce() {
    post({ t: "pc", pc: this.id, op: "restartIce", args: [] });
  }

  close() {
    if (pcs.delete(this.id)) {
      post({ t: "pc", pc: this.id, op: "close", args: [] });
    }
    this.signalingState = "closed";
    this.connectionState = "closed";
  }

  update(state) {
    if (state) {
      Object.assign(this, state);
    }
  }

  dispatch(type, ev) {
    const f = this["on" + type];
    if (typeof f === "function") {
      f.call(this, ev);
    }
  }
}

self.tailcatPeerConnection = TailcatPeerConnection;

function onPCReply(m) {
  const c = pcCalls.get(m.id);
  if (!c) {
    return;
  }
  pcCalls.delete(m.id);
  c.pc.update(m.state);
  if (m.ok) {
    c.resolve(m.value);
  } else {
    c.reject(new Error(m.error));
  }
}

function onPCEvent(m) {
  const pc = pcs.get(m.pc);
  if (!pc) {
    // Closed here while the event was on its way.
    if (m.ev && m.ev.channel) {
      m.ev.channel.close();
    }
    return;
  }
  pc.update(m.state);
  pc.dispatch(m.type, m.ev);
}

// --- Network changes ---

// tailcatNetwork is where webrtc_js.go hears that the network may have
// changed: the page's online events, and its navigator.connection's
// changes, which tailcat.js forwards. The Worker's own would repeat them.
function setupNetwork(connType) {
  const net = new EventTarget();
  if (connType !== null) {
    net.connection = Object.assign(new EventTarget(), { type: connType });
  }
  self.tailcatNetwork = net;
}

function onNet(m) {
  const net = self.tailcatNetwork;
  if (!net) {
    return;
  }
  if (m.event === "online") {
    net.dispatchEvent(new Event("online"));
  } else if (m.event === "change" && net.connection) {
    net.connection.type = m.type;
    net.connection.dispatchEvent(new Event("change"));
  }
}

// --- Test hooks ---

// hooks is the target of tailcatTestHooks, when the page has one: the Go
// side reads and writes it here, each write going to the page's, where
// the tests read it, and the page's writes come here.
let hooks = null;

function setupHooks(init) {
  hooks = { ...init };
  self.tailcatTestHooks = new Proxy(hooks, {
    set(target, k, v) {
      target[k] = v;
      post({ t: "hook", k, v });
      return true;
    },
  });
}

// --- The API ---

const objs = new Map(); // id → a listener or conn object of main_js.go
let nextObj = 1;

function keep(o) {
  const id = nextObj++;
  objs.set(id, o);
  return id;
}

// Each conn reads here as data arrives, ahead of the page, which grants
// the credit for how far (tailcat.js's readAhead) and returns it as it
// reads. A read that waited on its own round trip to this Worker, busy
// with the tunnel, left the tunnel's TCP receive buffer full between
// reads: the sender's TCP stopped, and waited on its timer, seconds, to
// try again. The tunnel's TCP still stops a sender the page doesn't keep
// up with, once the credit runs out.

// credits holds each conn's read credit, and how to wake its pump.
const credits = new Map(); // conn id → {n, wake}

function connInfo(conn) {
  const id = keep(conn);
  const credit = { n: 0, wake: null };
  credits.set(id, credit);
  pump(id, conn, credit);
  return { conn: id, port: conn.port, peerKey: conn.peerKey };
}

// pump reads conn until it ends, or is closed, sending the page what it
// reads. It starts once the page grants it credit.
async function pump(id, conn, credit) {
  try {
    for (;;) {
      while (credit.n <= 0) {
        if (!objs.has(id)) {
          return; // closed before the page read it
        }
        await new Promise((resolve) => {
          credit.wake = resolve;
        });
      }
      // Each read's bytes are a Uint8Array of their own (makeJSConn), so
      // they move to the page rather than being copied.
      const b = await conn.read();
      if (b === null) {
        post({ t: "data", conn: id, eof: true });
        return;
      }
      credit.n -= b.byteLength;
      post({ t: "data", conn: id, data: b }, [b.buffer]);
    }
  } catch (err) {
    post({ t: "data", conn: id, error: errorMessage(err) });
  } finally {
    credits.delete(id);
  }
}

function onCredit(m) {
  const credit = credits.get(m.conn);
  if (credit) {
    credit.n += m.n;
    if (credit.n > 0 && credit.wake) {
      credit.wake();
      credit.wake = null;
    }
  }
}

// callbackOpts returns the options for tailcatListen or tailcatDial: the
// page's, with a function for each callback it asked for (marked true)
// that sends what it is called with to the page.
function callbackOpts(opts, sub) {
  const o = { ...opts };
  for (const [name, kind] of [["onPathChange", "pathChange"], ["onPathStats", "pathStats"]]) {
    if (opts[name]) {
      o[name] = (payload) => post({ t: "event", sub, kind, payload });
    } else {
      delete o[name];
    }
  }
  return o;
}

async function call(m) {
  switch (m.fn) {
    case "listen": {
      const opts = callbackOpts(m.opts, m.sub);
      opts.onConnection = (conn) => post({ t: "event", sub: m.sub, kind: "connection", conn: connInfo(conn) });
      const ln = await self.tailcatListen(opts);
      return { value: { listener: keep(ln), addr: ln.addr, privateKeyJSON: ln.privateKeyJSON } };
    }
    case "dial":
      return { value: connInfo(await self.tailcatDial(callbackOpts(m.opts, m.sub))) };
  }
  const o = objs.get(m.obj);
  if (!o) {
    throw new Error("already closed");
  }
  switch (m.fn) {
    case "write":
      await o.write(m.args[0]);
      return {};
    case "closeWrite":
      await o.closeWrite();
      return {};
    case "close":
      try {
        await o.close();
      } finally {
        objs.delete(m.obj);
        const credit = credits.get(m.obj);
        if (credit && credit.wake) {
          credit.wake(); // to see it is closed
        }
      }
      return {};
    case "disconnect":
      return { value: await o.disconnect(...m.args) };
  }
  throw new Error(`unknown call ${m.fn}`);
}

// --- Starting ---

async function start(m) {
  if (m.hooks) {
    setupHooks(m.hooks);
  }
  setupNetwork(m.connType);
  const go = new Go();
  const ready = new Promise((resolve) => {
    self.onTailcatReady = resolve;
  });
  let exited;
  try {
    const instance = await WebAssembly.instantiate(m.module, go.importObject);
    // run settles only when the Go program exits, which it never does
    // unless it crashes.
    exited = go.run(instance).then(
      () => post({ t: "exit", error: "tailcat stopped unexpectedly" }),
      (err) => post({ t: "exit", error: `tailcat stopped: ${errorMessage(err)}` }),
    );
  } catch (err) {
    post({ t: "exit", error: `tailcat failed to start: ${errorMessage(err)}` });
    return;
  }
  const started = await Promise.race([ready.then(() => true), exited.then(() => false)]);
  delete self.onTailcatReady;
  if (started) {
    post({ t: "ready" });
  }
}

self.onmessage = (e) => {
  const m = e.data;
  switch (m.t) {
    case "start":
      start(m);
      break;
    case "probe":
      m.dc.close();
      break;
    case "call":
      call(m).then(
        (r) => post({ t: "result", id: m.id, ok: true, value: r.value }, r.transfer),
        (err) => post({ t: "result", id: m.id, ok: false, error: errorMessage(err) }),
      );
      break;
    case "pcReply":
      onPCReply(m);
      break;
    case "pcEvent":
      onPCEvent(m);
      break;
    case "net":
      onNet(m);
      break;
    case "hook":
      if (hooks) {
        hooks[m.k] = m.v;
      }
      break;
    case "credit":
      onCredit(m);
      break;
  }
};
