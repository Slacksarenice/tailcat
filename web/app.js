// tailcat web app. Plain JavaScript, no build step. tailcat.js starts
// the Go side (main_js.go), in a Worker where the browser allows, and
// the page calls it through the globals tailcatListen and tailcatDial.

const CHUNK = 64 * 1024;
const KEY_STORAGE = "tailcat-web-key";

const params = new URLSearchParams(location.search);
const verbose = params.has("verbose");

// tcTest is the state surface polled by the headless-browser
// integration test (web/wasm_test.go). It is set up before the
// module's first await, so it exists as soon as the page has loaded.
window.tcTest = {
  ready: false,
  listenAddr: null,
  recvBytes: 0,
  recvSha256: null,
  recvDone: false,
  sentBytes: 0,
  sentSha256: null,
  sendDone: false,
  path: null, // "webrtc" or "derp" once reported
  paths: [],  // every path reported, in order
  pathsAtDone: null, // paths as they stood when this side's transfer completed
  stats: null, // the last onPathStats report
  go: false,  // with ?gate, the sender waits for the test to set this
  mode: null, // where tailcat runs: "worker", or "page" (with ?worker=0)
  errors: [],
};
window.addEventListener("error", (e) => window.tcTest.errors.push(String(e.message)));
window.addEventListener("unhandledrejection", (e) => window.tcTest.errors.push(String(e.reason)));

// With ?hooks, the Go side reports its WebRTC path's state into
// tailcatTestHooks, and the test can steer it from there (see
// webrtc_js.go): dropRTC discards what the DataChannel receives, family
// ("4" or "6", from ?family) makes the page's WebRTC act as on a host
// with only that address family, and delayMs (from ?delay) holds each
// datagram received that long, for a longer round trip.
if (params.has("hooks")) {
  window.tailcatTestHooks = { dropRTC: false, family: params.get("family") || "", delayMs: Number(params.get("delay")) || 0 };
}

if (params.has("webrtc")) {
  document.getElementById("use-webrtc").checked = true;
}

// webrtcOption returns the "webrtc" option for tailcatListen and
// tailcatDial: off unless the checkbox (or ?webrtc) enables it, and
// with ?webrtc=host, host candidates only (no STUN), as the tests use.
function webrtcOption() {
  if (!document.getElementById("use-webrtc").checked) {
    return false;
  }
  return params.get("webrtc") === "host" ? { iceServers: [] } : true;
}

// onPathChange shows whether traffic flows over a direct WebRTC path
// or through DERP.
function onPathChange({ peerKey, path }) {
  window.tcTest.path = path;
  window.tcTest.paths.push(path);
  document.getElementById("path").textContent =
    path === "webrtc" ? "· direct (WebRTC)" : "· relayed (DERP)";
  if (verbose) {
    console.log(`path to ${peerKey}: ${path}`);
  }
}

// onPathStats shows the direct path's round trip and candidate types
// while it carries the traffic: the network's round trip as ICE times
// it, and beside it the tunnel's pings', which add the time each page
// took to answer.
function onPathStats(stats) {
  window.tcTest.stats = stats;
  if (stats.path !== "webrtc") {
    return;
  }
  const ms = (v) => (v < 1 ? "<1" : String(Math.round(v)));
  const family = stats.family ? ` ${stats.family}` : "";
  const route = stats.local && stats.remote ? ` ${stats.local} ↔ ${stats.remote}${family}` : "";
  const rtt = stats.iceRttMs === undefined ? `${ms(stats.rttMs)} ms` : `${ms(stats.iceRttMs)} ms, tunnel ${ms(stats.rttMs)} ms`;
  document.getElementById("path").textContent = `· direct (WebRTC${route}, ${rtt})`;
}

// canonicalDERPMapURL is the public tailcat DERP map, which allows
// cross-origin fetches with CORS headers.
const canonicalDERPMapURL = "https://tailcat.dev/derpmap.json";

// pickDERPMapURL returns the DERP map URL to hand to
// tailcatListen/tailcatDial: the ?derpmap= query parameter if given,
// and the canonical public map when hosted on GitHub Pages, which
// serves no map of its own. Anywhere else (cmd/tailcat-web, the
// integration tests, or this page copied onto some other site), it
// prefers a same-origin derpmap.json if the host serves one and
// otherwise falls back to the canonical map.
async function pickDERPMapURL() {
  if (params.get("derpmap")) {
    return new URL(params.get("derpmap"), location.href).toString();
  }
  if (location.hostname.endsWith(".github.io")) {
    return canonicalDERPMapURL;
  }
  const sameOrigin = new URL("derpmap.json", location.href).toString();
  try {
    const resp = await fetch(sameOrigin, { method: "HEAD" });
    if (resp.ok) {
      return sameOrigin;
    }
  } catch (e) {}
  return canonicalDERPMapURL;
}
const derpMapURL = await pickDERPMapURL();

const $ = (id) => document.getElementById(id);
const setStatus = (msg) => { $("status").textContent = msg; };

async function hex(digest) {
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

// countProgress wraps a stream, updating the page's progress bar and
// status line as bytes pass through: loaded/total drives the bar,
// wireBytes is the transfer size shown to the user.
function countProgress(stream, total, wireBytes) {
  const ofMB = wireBytes > 0 ? ` of ${(wireBytes / (1 << 20)).toFixed(1)} MB` : "";
  const bar = $("load-progress");
  let loaded = 0;
  return stream.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      loaded += chunk.byteLength;
      if (total > 0) {
        bar.value = loaded / total;
        const pct = Math.min(100, Math.floor(100 * loaded / total));
        setStatus(`Loading WebAssembly… ${pct}%${ofMB}`);
      } else {
        setStatus(`Loading WebAssembly…`);
      }
      controller.enqueue(chunk);
    },
  }));
}

// fetchWasm fetches the wasm with load progress. Static hosts like
// GitHub Pages can't do Content-Encoding negotiation (and don't
// compress wasm), so they serve only the pre-gzipped main.wasm.gz,
// fetched raw here and decompressed in the page. Servers that
// negotiate (the webdemo package) don't serve that name; on 404 the
// plain main.wasm fetch below gets the negotiated encoding, which the
// browser decompresses itself.
async function fetchWasm() {
  const gz = await fetch("main.wasm.gz");
  if (gz.ok) {
    // The counted stream sees compressed bytes, so progress runs
    // against the compressed size on the wire.
    const size = Number(gz.headers.get("Content-Length")) || 0;
    const wasm = countProgress(gz.body, size, size)
      .pipeThrough(new DecompressionStream("gzip"));
    return new Response(wasm, { headers: { "Content-Type": "application/wasm" } });
  }

  const resp = await fetch("main.wasm");
  if (!resp.ok) {
    throw new Error(`fetching main.wasm: ${resp.status}`);
  }
  // The body stream yields decompressed bytes, so progress is
  // tracked against the uncompressed size, but the size shown to the
  // user is what actually crosses the wire.
  const total = Number(resp.headers.get("X-Uncompressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const wireBytes = Number(resp.headers.get("X-Compressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const counted = countProgress(resp.body, total, wireBytes);
  return new Response(counted, { headers: { "Content-Type": "application/wasm" } });
}

// Boot the wasm module: in a Worker where the browser allows, or on the
// page with ?worker=0. tailcatListen and tailcatDial are the started
// instance's, wherever it runs.
const tc = await tailcatStart({
  wasm: fetchWasm(),
  worker: params.get("worker") === "0" ? false : "auto",
});
globalThis.tailcatListen = tc.listen;
globalThis.tailcatDial = tc.dial;
tc.exited.catch((err) => window.tcTest.errors.push(String(err)));
window.tcTest.mode = tc.mode;
window.tcTest.ready = true;
$("load-progress").remove();
setStatus("Ready.");
$("listen-btn").disabled = false;
$("send-btn").disabled = false;
$("send-text-btn").disabled = false;

// --- Receive side ---

async function startListener() {
  $("listen-btn").disabled = true;
  setStatus("Starting listener…");
  const persist = $("persist-key").checked;
  const privateKey = persist ? (localStorage.getItem(KEY_STORAGE) || "") : "";
  try {
    const ln = await tailcatListen({
      derpMapURL, privateKey, verbose, onConnection,
      webrtc: webrtcOption(), onPathChange, onPathStats,
    });
    if (persist) {
      localStorage.setItem(KEY_STORAGE, ln.privateKeyJSON);
    }
    $("listen-addr").textContent = ln.addr;
    $("listen-info").classList.remove("hidden");
    setStatus("Listening. Share the address with the sender.");
    window.tcTest.listenAddr = ln.addr;
  } catch (err) {
    setStatus("Listen failed: " + err.message);
    window.tcTest.errors.push(String(err));
    $("listen-btn").disabled = false;
  }
}

function onConnection(conn) {
  if (params.get("sink") === "hash") {
    hashSink(conn);
    return;
  }
  if (params.get("sink") === "count") {
    countSink(conn);
    return;
  }
  const li = document.createElement("li");
  const btn = document.createElement("button");
  btn.textContent = "Save incoming file…";
  const textBtn = document.createElement("button");
  textBtn.textContent = "Show as text";
  const progress = document.createElement("span");
  li.append(btn, " ", textBtn, " ", progress);
  $("incoming").append(li);
  const chose = () => {
    btn.disabled = true;
    textBtn.disabled = true;
  };
  textBtn.onclick = () => {
    chose();
    receiveText(conn, li, progress);
  };
  btn.onclick = async () => {
    chose();
    try {
      // Stream to disk. The pull-based conn.read means the sender
      // stalls on TCP backpressure while the user picks a file, and
      // while the disk keeps up; nothing is buffered in memory.
      const handle = await showSaveFilePicker({ suggestedName: "tailcat-download" });
      const w = await handle.createWritable();
      let n = 0;
      for (let chunk; (chunk = await conn.read()) !== null; ) {
        await w.write(chunk);
        n += chunk.length;
        progress.textContent = `${n} bytes`;
      }
      await w.close();
      conn.close();
      progress.textContent = `done, ${n} bytes`;
    } catch (err) {
      conn.close();
      progress.textContent = "failed: " + err.message;
      window.tcTest.errors.push(String(err));
    }
  };
}

// receiveText reads the whole incoming stream into memory and shows
// it as copyable text under the connection's list item.
async function receiveText(conn, li, progress) {
  try {
    const chunks = [];
    let n = 0;
    for (let chunk; (chunk = await conn.read()) !== null; ) {
      chunks.push(chunk);
      n += chunk.length;
      progress.textContent = `${n} bytes`;
    }
    conn.close();
    const all = new Uint8Array(n);
    let off = 0;
    for (const c of chunks) {
      all.set(c, off);
      off += c.length;
    }
    const text = new TextDecoder().decode(all);
    const box = document.createElement("code");
    box.className = "recv-text";
    box.textContent = text;
    const copyBtn = document.createElement("button");
    copyBtn.textContent = "Copy";
    copyBtn.onclick = () => navigator.clipboard.writeText(text);
    li.append(box, copyBtn);
    progress.textContent = `done, ${n} bytes`;
  } catch (err) {
    conn.close();
    progress.textContent = "failed: " + err.message;
    window.tcTest.errors.push(String(err));
  }
}

// hashSink is the test-mode receiver: instead of the file picker
// (which needs a user gesture that headless Chrome can't provide), it
// counts and hashes the received bytes into tcTest.
async function hashSink(conn) {
  const chunks = [];
  let n = 0;
  for (let chunk; (chunk = await conn.read()) !== null; ) {
    chunks.push(chunk);
    n += chunk.length;
    window.tcTest.recvBytes = n;
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  window.tcTest.recvSha256 = await sha256Hex(all);
  window.tcTest.recvDone = true;
  conn.close();
}

// countSink is the stress tests' receiver: it keeps nothing, so a
// transfer of any size fits, and checks each byte against the sender's
// pattern (see patternChunk) as it arrives.
async function countSink(conn) {
  let n = 0;
  let bad = 0;
  for (let chunk; (chunk = await conn.read()) !== null; ) {
    for (let i = 0; i < chunk.length; i += 4093) {
      if (chunk[i] !== patternByte(n + i)) {
        bad++;
      }
    }
    n += chunk.length;
    window.tcTest.recvBytes = n;
  }
  window.tcTest.recvBad = bad;
  window.tcTest.pathsAtDone = window.tcTest.paths.slice();
  window.tcTest.recvDone = true;
  conn.close();
}

// patternByte is the byte at offset off of a ?pattern transfer.
function patternByte(off) {
  return (off * 2654435761 >>> 24) & 0xff;
}

// patternChunk returns n bytes of the pattern starting at off.
function patternChunk(off, n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = patternByte(off + i);
  }
  return b;
}

// With ?timeline, the page records once a second how far the transfer
// has got, where the traffic goes, and how late its own timers fire:
// a late timer means the page's thread was busy.
if (params.has("timeline")) {
  window.tcTest.timeline = [];
  window.tcTest.maxLagMs = 0;
  const t0 = performance.now();
  let last = t0;
  let lag = 0;
  setInterval(() => {
    const now = performance.now();
    lag = Math.max(lag, now - last - 100);
    last = now;
  }, 100);
  setInterval(() => {
    const s = window.tcTest.stats || {};
    window.tcTest.maxLagMs = Math.max(window.tcTest.maxLagMs, lag);
    window.tcTest.timeline.push({
      t: Math.round((performance.now() - t0) / 100) / 10,
      sent: window.tcTest.sentBytes,
      recv: window.tcTest.recvBytes,
      path: window.tcTest.path,
      rtt: Math.round(s.rttMs || 0),
      iceRtt: s.iceRttMs,
      dropped: s.dropped || 0,
      recvDropped: s.recvDropped || 0,
      lagMs: Math.round(lag),
      heapMB: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1e6) : 0,
    });
    lag = 0;
  }, 1000);
}

$("listen-btn").onclick = startListener;
$("copy-addr").onclick = () => navigator.clipboard.writeText($("listen-addr").textContent);

// --- Send side ---

// until resolves once cond() is true, checking every 100ms.
async function until(cond) {
  while (!cond()) {
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function sendStream(addr, size, readChunk, progressEl) {
  const conn = await tailcatDial({
    addr, derpMapURL, verbose,
    webrtc: webrtcOption(), onPathChange, onPathStats,
  });
  // Test hooks: ?waitpath=webrtc holds the data until the direct path
  // is up, and ?gate until the test sets tcTest.go (after stopping the
  // DERP server, to prove the data doesn't need it).
  if (params.get("waitpath")) {
    await until(() => window.tcTest.path === params.get("waitpath"));
  }
  if (params.has("gate")) {
    await until(() => window.tcTest.go);
  }
  let off = 0;
  while (off < size) {
    const chunk = await readChunk(off, Math.min(CHUNK, size - off));
    await conn.write(chunk);
    off += chunk.length;
    window.tcTest.sentBytes = off;
    progressEl.textContent = `${off} / ${size} bytes`;
  }
  await conn.closeWrite();
  // Wait for the receiver's close: like the CLI, the peer's EOF is
  // the confirmation that everything we sent was delivered.
  while ((await conn.read()) !== null) {}
  window.tcTest.pathsAtDone = window.tcTest.paths.slice();
  conn.close();
  window.tcTest.sentBytes = off;
  window.tcTest.sendDone = true;
  progressEl.textContent = `sent ${off} bytes`;
}

$("send-btn").onclick = async () => {
  const addr = $("send-addr").value.trim();
  const file = $("send-file").files[0];
  if (!addr || !file) {
    setStatus("Enter an address and pick a file first.");
    return;
  }
  $("send-btn").disabled = true;
  setStatus("Connecting…");
  try {
    await sendStream(addr, file.size,
      async (off, n) => new Uint8Array(await file.slice(off, off + n).arrayBuffer()),
      $("send-progress"));
    setStatus("Done.");
  } catch (err) {
    setStatus("Send failed: " + err.message);
    window.tcTest.errors.push(String(err));
  }
  $("send-btn").disabled = false;
};

$("send-text-btn").onclick = async () => {
  const addr = $("send-addr").value.trim();
  const text = $("send-text").value;
  if (!addr || !text) {
    setStatus("Enter an address and type some text first.");
    return;
  }
  $("send-text-btn").disabled = true;
  setStatus("Connecting…");
  try {
    const data = new TextEncoder().encode(text);
    await sendStream(addr, data.length,
      async (off, n) => data.subarray(off, off + n),
      $("send-progress"));
    setStatus("Done.");
  } catch (err) {
    setStatus("Send failed: " + err.message);
    window.tcTest.errors.push(String(err));
  }
  $("send-text-btn").disabled = false;
};

// --- Test automation via query parameters ---

if (params.get("mode") === "listen") {
  startListener();
} else if (params.get("mode") === "send") {
  const addr = params.get("addr");
  const size = parseInt(params.get("bytes"), 10);
  let readChunk;
  if (params.has("pattern")) {
    // A stress test's transfer, too large to hold: generated as it
    // goes, and checked by countSink.
    readChunk = async (off, n) => patternChunk(off, n);
  } else {
    const data = new Uint8Array(size);
    // crypto.getRandomValues caps each call at 64 KiB.
    for (let off = 0; off < size; off += CHUNK) {
      crypto.getRandomValues(data.subarray(off, Math.min(off + CHUNK, size)));
    }
    window.tcTest.sentSha256 = await sha256Hex(data);
    readChunk = async (off, n) => data.subarray(off, off + n);
  }
  try {
    await sendStream(addr, size, readChunk, $("send-progress"));
  } catch (err) {
    window.tcTest.errors.push(String(err));
  }
}
