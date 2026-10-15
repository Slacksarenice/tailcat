// For self time in functions matching a regexp, attributes it to the
// nearest ancestor frame that is not runtime, syscall/js or JS glue: the
// Go code paying for it.
//
//   node web/stressbench/callers.ts <profile> '^runtime\.(addspecial|SetFinalizer)$'
import { readFileSync } from "node:fs";
interface Node { id: number; callFrame: { functionName: string }; children?: number[] }
const p = JSON.parse(readFileSync(process.argv[2], "utf8")) as { nodes: Node[]; samples: number[]; timeDeltas: number[] };
const byId = new Map<number, any>(p.nodes.map((n: any) => [n.id, n]));
const parent = new Map<number, number>();
for (const n of p.nodes) for (const c of n.children ?? []) parent.set(c, n.id);
const re = new RegExp(process.argv[3]);
const skip = /^(runtime\.|syscall_js|syscall\/js|internal_|sync\.|wasm|js-to-wasm|wasm-to-js|loadString|storeValue|loadValue|loadSlice|decode|encode|now|_resume|\(anon|time\.|mallocgc|wasm_pc)/;
const agg = new Map<string, number>(); let busy = 0, matched = 0;
for (let i = 0; i < p.samples.length; i++) {
  const n = byId.get(p.samples[i]); const name = n.callFrame.functionName || "(anon)";
  if (name === "(idle)") continue; const us = p.timeDeltas[i] ?? 0; busy += us;
  if (!re.test(name)) continue; matched += us;
  let id: number | undefined = n.id; let caller = "?";
  while (id !== undefined) { const f = byId.get(id).callFrame.functionName; if (f && !skip.test(f) && !re.test(f)) { caller = f; break; } id = parent.get(id); }
  agg.set(caller, (agg.get(caller) ?? 0) + us);
}
console.log(`${process.argv[3]}: ${(100 * matched / busy).toFixed(1)}% of busy`);
for (const [k, us] of [...agg].sort((a, b) => b[1] - a[1]).slice(0, 12)) console.log((100 * us / busy).toFixed(2).padStart(6) + "%  " + k);
