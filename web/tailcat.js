// tailcat.js starts tailcat, the WebAssembly build of the tailcat tunnel
// (main_js.go), and hands the page its API. Plain JavaScript, no build
// step; a classic script that defines one global, tailcatStart.
//
// Where the browser allows, tailcat runs in a dedicated Worker
// (worker.js), off the page's thread: the page's own work, its UI and
// reading and saving files, and the tunnel's, WireGuard, TCP and their
// timers, then run side by side, and the timers of a page in a hidden
// tab, which the browser slows to a few a second, no longer slow the
// tunnel. Workers have no RTCPeerConnection, so the page holds each peer
// connection for the Worker, which drives it through a stand-in
// (worker.js), and hands the Worker each DataChannel as it is created:
// the tunnel's datagrams go between the channel and the Worker without
// crossing the page's thread. Where the browser can't hand a Worker a
// DataChannel, tailcat runs on the page, as it did before.
//
//	const tc = await tailcatStart({wasm: fetch("main.wasm")});
//	const ln = await tc.listen({...}); // as tailcatListen in main_js.go
//	const conn = await tc.dial({...}); // as tailcatDial
//
// tailcatStart's options:
//
//	wasm: the module: a Response (served as application/wasm), its bytes,
//	  or a WebAssembly.Module, or a Promise of one. Required.
//	base: the URL of the directory holding worker.js and wasm_exec.js;
//	  this script's own if absent.
//	worker: "auto" (the default), or false to run on the page.
//
// It resolves to {listen, dial, mode, exited}. listen and dial take and
// return what tailcatListen and tailcatDial do, whichever the mode; mode
// is "worker" or "page"; and exited rejects if the module stops, which it
// does only if it crashes. Every call after that rejects. In a Worker,
// a listener's disconnect takes effect once the call reaches the Worker,
// before its promise settles, rather than before it returns.
(() => {
  "use strict";

  const scriptBase = document.currentScript
    ? new URL(".", document.currentScript.src).href
    : new URL(".", location.href).href;

  async function compile(wasm) {
    wasm = await wasm;
    if (wasm instanceof WebAssembly.Module) {
      return wasm;
    }
    if (typeof Response !== "undefined" && wasm instanceof Response) {
      if (!wasm.ok) {
        throw new Error(`fetching the tailcat module: HTTP ${wasm.status}`);
      }
      return WebAssembly.compileStreaming(wasm);
    }
    return WebAssembly.compile(wasm);
  }

  async function tailcatStart(opts) {
    const base = new URL(opts.base || scriptBase, location.href).href;
    const module = await compile(opts.wasm);
    if (opts.worker !== false && typeof Worker === "function") {
      try {
        const tc = await startInWorker(module, base);
        if (tc) {
          return tc;
        }
      } catch (err) {
        // A Worker the page may not start (its Content-Security-Policy),
        // or whose script didn't load: the page still has tailcat.
        console.warn("tailcat: couldn't start in a Worker, so it runs on the page:", err);
      }
    }
    return startOnPage(module, base);
  }

  // --- On the page ---

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`couldn't load ${src}`));
      document.head.appendChild(script);
    });
  }

  // pageStarts orders starts on the page: each instance there tells of its
  // start through the one global onTailcatReady, and defines the same
  // globals, so each must be ready, and have taken its API, before the next
  // begins.
  let pageStarts = Promise.resolve();

  function startOnPage(module, base) {
    const start = pageStarts.then(() => startOnPageNow(module, base));
    pageStarts = start.catch(() => {});
    return start;
  }

  async function startOnPageNow(module, base) {
    if (typeof Go === "undefined") {
      await loadScript(base + "wasm_exec.js");
    }
    const go = new Go();
    const ready = new Promise((resolve) => {
      globalThis.onTailcatReady = resolve;
    });
    const instance = await WebAssembly.instantiate(module, go.importObject);
    // run settles only when the Go program exits, which it never does
    // unless it crashes.
    const exited = go.run(instance).then(() => {
      throw new Error("tailcat stopped unexpectedly");
    });
    exited.catch(() => {});
    await Promise.race([ready, exited]);
    delete globalThis.onTailcatReady;
    const { tailcatListen, tailcatDial } = globalThis;
    if (!tailcatListen || !tailcatDial) {
      throw new Error("tailcat did not start");
    }
    exited.catch(() => {
      // A later instance sets its own; these belong to this one.
      if (globalThis.tailcatListen === tailcatListen) delete globalThis.tailcatListen;
      if (globalThis.tailcatDial === tailcatDial) delete globalThis.tailcatDial;
    });
    return {
      mode: "page",
      listen: (o) => tailcatListen(o),
      dial: (o) => tailcatDial(o),
      exited,
    };
  }

  // --- In a Worker ---

  // handOverChannel reports whether this browser can hand a Worker a
  // DataChannel, which recent Chrome, Firefox and Safari can, by handing
  // worker one. A browser without WebRTC loses nothing in a Worker.
  function handOverChannel(worker) {
    if (typeof RTCPeerConnection !== "function") {
      return true;
    }
    let pc;
    try {
      pc = new RTCPeerConnection();
    } catch {
      return true;
    }
    try {
      const dc = pc.createDataChannel("probe");
      worker.postMessage({ t: "probe", dc }, [dc]);
      return true;
    } catch {
      return false;
    } finally {
      pc.close();
    }
  }

  async function startInWorker(module, base) {
    const worker = new Worker(base + "worker.js");
    if (!handOverChannel(worker)) {
      worker.terminate();
      return null;
    }
    const w = new WorkerClient(worker);
    worker.postMessage({ t: "start", module, hooks: w.setupHooks(), connType: w.watchNetwork() });
    await w.ready;
    return {
      mode: "worker",
      listen: (o) => w.listen(o),
      dial: (o) => w.dial(o),
      exited: w.exited,
    };
  }

  // readAhead is how many bytes the Worker reads a conn ahead of the page
  // (worker.js's pump), and creditBatch how many the page's reads return
  // at a time. creditBatch must stay well under readAhead: a pump out of
  // credit then always has bytes the page has yet to read, whose reads
  // return more.
  const readAhead = 1 << 20;
  const creditBatch = 256 << 10;

  const describe = (d) => d && { type: d.type, sdp: d.sdp };

  // snapshot is the state of pc that a Worker's stand-in keeps a copy of.
  function snapshot(pc) {
    return {
      signalingState: pc.signalingState,
      connectionState: pc.connectionState,
      iceConnectionState: pc.iceConnectionState,
      iceGatheringState: pc.iceGatheringState,
      localDescription: describe(pc.localDescription),
      remoteDescription: describe(pc.remoteDescription),
    };
  }

  // plainOpts returns opts as a Worker can receive them: each callback (an
  // "on..." option) that is a function replaced by true, which the Worker
  // answers with events, and one that isn't left out, as tailcatListen and
  // tailcatDial would ignore or refuse it.
  function plainOpts(opts) {
    const o = {};
    for (const [k, v] of Object.entries(opts || {})) {
      if (k.startsWith("on")) {
        if (typeof v === "function") o[k] = true;
        continue;
      }
      o[k] = v;
    }
    return o;
  }

  class WorkerClient {
    constructor(worker) {
      this.worker = worker;
      this.calls = new Map(); // id → {resolve, reject}
      this.nextCall = 1;
      this.subs = new Map(); // id → a listen or dial call's callbacks
      this.nextSub = 1;
      this.conns = new Map(); // conn id → its read-ahead state (see conn)
      this.pcs = new Map(); // id → RTCPeerConnection
      this.hooks = null;
      this.unwatch = () => {};
      this.dead = null;
      this.exited = new Promise((_, reject) => {
        this.exit = reject;
      });
      this.exited.catch(() => {});
      this.ready = new Promise((resolve, reject) => {
        this.started = resolve;
        this.exited.catch(reject);
      });
      worker.onmessage = (e) => this.onMessage(e.data);
      worker.onerror = (e) => {
        e.preventDefault();
        this.die(new Error(`tailcat's worker failed: ${e.message || "error"}`));
      };
      worker.onmessageerror = () => this.die(new Error("tailcat's worker sent a message the page couldn't read"));
    }

    // die ends this instance: its calls reject, its peer connections
    // close, its Worker stops, and exited rejects with err.
    die(err) {
      if (this.dead) {
        return;
      }
      this.dead = err;
      for (const c of this.calls.values()) {
        c.reject(err);
      }
      this.calls.clear();
      for (const st of this.conns.values()) {
        st.error = st.error || err;
        st.feed();
      }
      this.conns.clear();
      for (const pc of this.pcs.values()) {
        pc.close();
      }
      this.pcs.clear();
      this.unwatch();
      this.worker.terminate();
      this.exit(err);
    }

    send(msg, transfer) {
      if (!this.dead) {
        this.worker.postMessage(msg, transfer || []);
      }
    }

    call(msg, transfer) {
      if (this.dead) {
        return Promise.reject(this.dead);
      }
      return new Promise((resolve, reject) => {
        const id = this.nextCall++;
        this.calls.set(id, { resolve, reject });
        this.worker.postMessage({ ...msg, t: "call", id }, transfer || []);
      });
    }

    subscribe(callbacks) {
      const id = this.nextSub++;
      this.subs.set(id, callbacks);
      return id;
    }

    async listen(opts) {
      const sub = this.subscribe({
        connection: opts.onConnection,
        pathChange: opts.onPathChange,
        pathStats: opts.onPathStats,
      });
      try {
        const v = await this.call({ fn: "listen", sub, opts: plainOpts(opts) });
        const obj = v.listener;
        return {
          addr: v.addr,
          privateKeyJSON: v.privateKeyJSON,
          // As on the page (main_js.go), close and disconnect never reject: a
          // listener the Worker has closed already, or a Worker that has
          // stopped, has nothing left to close or drop.
          disconnect: (peerKey, o) =>
            this.call({ fn: "disconnect", obj, args: o ? [peerKey, { block: !!o.block }] : [peerKey] }).catch(
              () => false,
            ),
          close: () =>
            this.call({ fn: "close", obj })
              .finally(() => this.subs.delete(sub))
              .catch(() => undefined),
        };
      } catch (err) {
        this.subs.delete(sub);
        throw err;
      }
    }

    async dial(opts) {
      const sub = this.subscribe({ pathChange: opts.onPathChange, pathStats: opts.onPathStats });
      try {
        return this.conn(await this.call({ fn: "dial", sub, opts: plainOpts(opts) }), sub);
      } catch (err) {
        this.subs.delete(sub);
        throw err;
      }
    }

    // conn is the page's side of a conn object in the Worker (makeJSConn).
    // The Worker reads it ahead of the page (worker.js's pump), so a read
    // takes what has arrived, or waits for the next to: the page returns
    // the credit for what it has read, a batch at a time.
    conn(v, sub) {
      const obj = v.conn;
      const st = {
        chunks: [], // read ahead, not yet read
        eof: false,
        error: null,
        closed: false,
        owed: 0, // credit for bytes read, not yet returned
        waiter: null, // a read waiting for the next to arrive
      };
      this.conns.set(obj, st);
      this.send({ t: "credit", conn: obj, n: readAhead });
      const take = () => {
        const b = st.chunks.shift();
        st.owed += b.byteLength;
        if (st.owed >= creditBatch) {
          this.send({ t: "credit", conn: obj, n: st.owed });
          st.owed = 0;
        }
        return b;
      };
      st.feed = () => {
        const w = st.waiter;
        if (!w) {
          return;
        }
        if (st.chunks.length > 0) {
          st.waiter = null;
          w.resolve(take());
        } else if (st.error) {
          st.waiter = null;
          w.reject(st.error);
        } else if (st.eof) {
          st.waiter = null;
          w.resolve(null);
        }
      };
      return {
        port: v.port,
        peerKey: v.peerKey,
        read: () => {
          if (st.chunks.length > 0) {
            return Promise.resolve(take());
          }
          if (st.error || st.closed || this.dead) {
            return Promise.reject(st.error || (st.closed && new Error("read on a closed conn")) || this.dead);
          }
          if (st.eof) {
            return Promise.resolve(null);
          }
          return new Promise((resolve, reject) => {
            st.waiter = { resolve, reject };
          });
        },
        write: (data) => {
          // A copy of just these bytes moves to the Worker: posting the
          // view itself would copy all of its buffer, and leave the
          // caller's, which it may reuse, alone only at that cost.
          const copy = data.slice();
          return this.call({ fn: "write", obj, args: [copy] }, [copy.buffer]);
        },
        closeWrite: () => this.call({ fn: "closeWrite", obj }),
        // Never rejects, as on the page: see the listener's close.
        close: () => {
          // What was read ahead and not read is dropped, and so is what
          // arrives from here on (onData).
          st.closed = true;
          st.chunks = [];
          return this.call({ fn: "close", obj })
            .finally(() => {
              this.conns.delete(obj);
              if (sub) {
                this.subs.delete(sub);
              }
              // A read still waiting fails, as it would on the closed conn.
              st.error = st.error || new Error("read on a closed conn");
              st.feed();
            })
            .catch(() => undefined);
        },
      };
    }

    // onData takes what a conn's pump in the Worker read: bytes, its end,
    // or the error that ended it.
    onData(m) {
      const st = this.conns.get(m.conn);
      if (!st || st.closed) {
        return; // closed here
      }
      if (m.data) {
        st.chunks.push(m.data);
      } else if (m.eof) {
        st.eof = true;
      } else {
        st.error = new Error(m.error);
      }
      st.feed();
    }

    onMessage(m) {
      switch (m.t) {
        case "ready":
          this.started();
          break;
        case "exit":
          this.die(new Error(m.error || "tailcat stopped unexpectedly"));
          break;
        case "result": {
          const c = this.calls.get(m.id);
          if (c) {
            this.calls.delete(m.id);
            if (m.ok) {
              c.resolve(m.value);
            } else {
              c.reject(new Error(m.error));
            }
          }
          break;
        }
        case "event":
          this.onEvent(m);
          break;
        case "data":
          this.onData(m);
          break;
        case "log":
          (console[m.level] || console.log)(...m.args);
          break;
        case "hook":
          if (this.hooks) {
            this.hooks[m.k] = m.v;
          }
          break;
        case "pc":
          this.onPC(m);
          break;
      }
    }

    onEvent(m) {
      const s = this.subs.get(m.sub);
      const f = s && s[m.kind];
      if (typeof f !== "function") {
        // A connection no one takes (its listener is closing) is closed,
        // or the Worker would keep it, waiting for its reads.
        if (m.kind === "connection") {
          this.call({ fn: "close", obj: m.conn.conn }).catch(() => {});
        }
        return;
      }
      try {
        f(m.kind === "connection" ? this.conn(m.conn) : m.payload);
      } catch (err) {
        // As main_js.go's invokeSafely: a callback that throws is logged.
        console.error(`tailcat: on${m.kind[0].toUpperCase()}${m.kind.slice(1)} threw:`, err);
      }
    }

    // --- Peer connections, held for the Worker ---

    async onPC(m) {
      const { pc: id, op, args } = m;
      if (op === "new") {
        this.newPC(id, args[0]);
        return;
      }
      const pc = this.pcs.get(id);
      if (op === "close") {
        if (pc) {
          this.pcs.delete(id);
          pc.close();
        }
        return;
      }
      if (op === "restartIce") {
        if (pc) {
          pc.restartIce();
        }
        return;
      }
      try {
        if (!pc) {
          throw new Error("the peer connection is closed");
        }
        let value;
        switch (op) {
          case "createDataChannel": {
            // A DataChannel can be handed over only as it is created.
            const dc = pc.createDataChannel(...args);
            this.send({ t: "pcReply", id: m.id, ok: true, value: dc, state: snapshot(pc) }, [dc]);
            return;
          }
          case "setLocalDescription":
            await pc.setLocalDescription(...args);
            break;
          case "setRemoteDescription":
            await pc.setRemoteDescription(args[0]);
            break;
          case "addIceCandidate":
            await pc.addIceCandidate(args[0]);
            break;
          case "getStats":
            value = [...(await pc.getStats()).values()];
            break;
          default:
            throw new Error(`unknown peer connection call ${op}`);
        }
        this.send({ t: "pcReply", id: m.id, ok: true, value, state: snapshot(pc) });
      } catch (err) {
        this.send({
          t: "pcReply",
          id: m.id,
          ok: false,
          error: String((err && err.message) || err),
          state: pc ? snapshot(pc) : null,
        });
      }
    }

    newPC(id, config) {
      let pc;
      try {
        pc = new RTCPeerConnection(config);
      } catch (err) {
        console.error("tailcat: RTCPeerConnection:", err);
        // The stand-in's session ends on a failed connection.
        this.send({ t: "pcEvent", pc: id, type: "connectionstatechange", ev: {}, state: { connectionState: "failed" } });
        return;
      }
      this.pcs.set(id, pc);
      const forward = (type, ev, transfer) =>
        this.send({ t: "pcEvent", pc: id, type, ev, state: snapshot(pc) }, transfer);
      pc.onicecandidate = (e) => forward("icecandidate", { candidate: e.candidate ? e.candidate.toJSON() : null });
      pc.onconnectionstatechange = () => forward("connectionstatechange", {});
      pc.oniceconnectionstatechange = () => forward("iceconnectionstatechange", {});
      pc.onsignalingstatechange = () => forward("signalingstatechange", {});
      pc.ontrack = () => forward("track", {});
      // A DataChannel can be handed over only as it is announced.
      pc.ondatachannel = (e) => forward("datachannel", { channel: e.channel }, [e.channel]);
    }

    // --- The page's events the Worker needs ---

    // watchNetwork forwards the page's online events and its
    // navigator.connection's changes to the Worker (see webrtc_js.go's
    // netWatch). It returns the connection's type now, or null if the
    // browser has no navigator.connection.
    watchNetwork() {
      const online = () => this.send({ t: "net", event: "online" });
      addEventListener("online", online);
      const conn = navigator.connection;
      if (!conn || typeof conn.addEventListener !== "function") {
        this.unwatch = () => removeEventListener("online", online);
        return null;
      }
      const change = () => this.send({ t: "net", event: "change", type: conn.type });
      conn.addEventListener("change", change);
      this.unwatch = () => {
        removeEventListener("online", online);
        conn.removeEventListener("change", change);
      };
      return conn.type === undefined ? "" : conn.type;
    }

    // setupHooks shares the page's tailcatTestHooks, if it has one, with
    // the Worker, where the Go side reads and writes it: the page's writes
    // go to the Worker's copy, and the Worker's come back. It returns the
    // hooks as they stand.
    setupHooks() {
      const hooks = globalThis.tailcatTestHooks;
      if (!hooks || typeof hooks !== "object") {
        return null;
      }
      this.hooks = hooks;
      globalThis.tailcatTestHooks = new Proxy(hooks, {
        set: (target, k, v) => {
          target[k] = v;
          this.send({ t: "hook", k, v });
          return true;
        },
      });
      return { ...hooks };
    }
  }

  globalThis.tailcatStart = tailcatStart;
})();
