// 打页:esbuild 把 page.mjs(连 typage 公开入口)打成 page.js;page.html 只外链 page.js、page.css(CSP 不许内联)。
// 用法:node build.mjs [--vault https://vault.dadamia.ai] [--out <page.js 写到哪>] [--abl L1,L3](--abl、--out 只给判据用,正式发版不带)
import { build } from "esbuild";
import { readFileSync } from "node:fs";
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const here = new URL(".", import.meta.url).pathname;
const vault = arg("--vault", "https://vault.dadamia.ai"), abl = arg("--abl", ""), out = arg("--out", here + "page.js");
const csp = readFileSync(here + "_headers", "utf8");
if (!vault.startsWith("http://127.0.0.1:") && !csp.includes(`connect-src ${vault};`))
  throw new Error(`_headers 的 connect-src 不是 ${vault}`);              // 页连的地方跟 CSP 放行的必须是同一个
const r = await build({ entryPoints: [here + "page.mjs"], bundle: true, format: "iife", target: "safari16", minify: true,
  outfile: out, metafile: true, logLevel: "error",
  define: { __VAULT__: JSON.stringify(vault), __ABL__: JSON.stringify(abl) } });
const imports = r.metafile.inputs[here.replace(process.cwd() + "/", "") + "page.mjs"]?.imports
  ?? Object.entries(r.metafile.inputs).find(([k]) => k.endsWith("page.mjs"))[1].imports;
console.log(JSON.stringify({ vault, abl, bytes: r.metafile.outputs[Object.keys(r.metafile.outputs)[0]].bytes, imports }));
