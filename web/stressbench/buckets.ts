// Buckets a Chrome .cpuprofile's self time (idle excluded) by category,
// and by Go package for wasm frames named via the name section (build
// with TAILCAT_WASM_NAMES=1).
//
//   node web/stressbench/buckets.ts <dir>/listen.cpuprofile [topN]
import { readFileSync } from "node:fs";

interface Node { id: number; callFrame: { functionName: string; url: string } }
interface Profile { nodes: Node[]; samples: number[]; timeDeltas: number[] }

const categories: [string, RegExp][] = [
  ["AEAD: chacha20poly1305 (x/crypto)", /golang\.org_x_crypto_(chacha20|internal_poly1305|chacha20poly1305)/],
  ["handshake crypto: blake2s/curve25519/noise", /blake2s|curve25519|x25519|filippo|edwards25519|noise/i],
  ["gVisor netstack (tcpip)", /^gvisor\.dev_/],
  ["wireguard-go (incl. tun checksum)", /wireguard_go/],
  ["tailscale.com (magicsock, derp, netstack glue)", /^tailscale\.com_/],
  ["tailcat (webrtc/derpws glue, main)", /tailcat|^main\./],
  ["Go runtime: GC + alloc", /^runtime\.(gc|mallocgc|scan|markroot|greyobject|findObject|sweep|bgsweep|bgscavenge|wbBuf|bulkBarrier|typePointers|heapBits|nextFreeFast|mspan|mcache|mcentral|mheap|(.*)Alloc|memclrNoHeapPointers|deductAssist|mProf)|gcDrain|gcWork|shade|scanobject|scanblock/],
  ["Go runtime: memmove/memequal", /runtime\.(memmove|memequal|memeqbody)/],
  ["Go runtime: scheduler/other", /^runtime\.|^internal\/runtime|^sync\b|^sync\./],
  ["Go std (other)", /^(crypto|encoding|bytes|strings|time|math|io|net|errors|fmt|strconv|unicode|slices|maps|sort|hash|container|context|bufio|log|reflect|internal)\b/],
  ["syscall/js + wasm_exec glue", /syscall\/js|wasm_exec|loadSlice|storeValue|loadValue|loadString|copyBytes|finalizeRef|_resume|wasm-to-js|js-to-wasm/],
  ["Go runtime host calls (nanotime/walltime/timers)", /runtime\.(nanotime1|walltime|scheduleTimeoutEvent|clearTimeoutEvent|getRandomData)|^now$/],
  ["(program)/(garbage collector) [V8]", /^\((program|garbage collector)\)$/],
];

function categorize(name: string, url: string): string {
  for (const [label, re] of categories) if (re.test(name)) return label;
  if (/wasm-function/.test(name)) return "wasm (unnamed)";
  if (url) return "JS: " + (url.split("/").pop() || url).replace(/\?.*$/, "");
  return "other: " + name;
}

function main(path: string, topN: number): void {
  const p = JSON.parse(readFileSync(path, "utf8")) as Profile;
  const byId = new Map(p.nodes.map((n) => [n.id, n]));
  const fn = new Map<string, number>();
  const cat = new Map<string, number>();
  let busy = 0, idle = 0;
  for (let i = 0; i < p.samples.length; i++) {
    const n = byId.get(p.samples[i])!;
    const us = p.timeDeltas[i] ?? 0;
    const name = n.callFrame.functionName || "(anonymous)";
    if (name === "(idle)") { idle += us; continue; }
    busy += us;
    fn.set(name, (fn.get(name) ?? 0) + us);
    const c = categorize(name, n.callFrame.url);
    cat.set(c, (cat.get(c) ?? 0) + us);
  }
  const pct = (us: number): string => (100 * us / busy).toFixed(1).padStart(5) + "%";
  console.log(`${path}\n  busy ${(busy / 1e6).toFixed(2)} s, idle ${(idle / 1e6).toFixed(2)} s (${(100 * busy / (busy + idle)).toFixed(0)}% busy)`);
  for (const [c, us] of [...cat].sort((a, b) => b[1] - a[1])) console.log(`  ${pct(us)}  ${c}`);
  console.log("  top functions:");
  for (const [k, us] of [...fn].sort((a, b) => b[1] - a[1]).slice(0, topN)) console.log(`    ${pct(us)}  ${k}`);
}

main(process.argv[2], Number(process.argv[3] ?? 30));
