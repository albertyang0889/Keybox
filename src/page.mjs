// ALB-5194 安全盒开盒页(稿 whole-page-plan-v8 §2.3、§2.13 锁 1–5、§9 B1/B2/M3/M4;v9 砍法第 2、6 条;块「换上」PLAN)。
//
// 一套说清:户私钥只在这页里出现,服务器只拿公钥和密文。地址 # 后面那一格定这页做哪一件:
//   #u=<请求号>  开盒(块 1/2):列出这次交哪几样 → 他点 → 刷脸(通行密钥 PRF)→ 解开他的人钥匙口令文件 → 解开这几户的户钥匙包
//               (锁 L6:口令文件里钉过这一户的户公钥,解出来的那把算出的公钥要一样;没钉一律不开)→ 每样整份解开、里层名字四格逐样比(锁 1)、
//               类 → 哪一把(锁 2)、核章(锁 ST,v9 第 6 条:章只有解得开户钥匙的页算得出)→ 全对上才整份封给这一单的一次性公钥交回。
//               服务器说「待盖章」的那几样(刚存、重封过),这一刷顺手盖好章、封回户公钥交上(盖章 = HKDF 从户私钥派生章钥 → HMAC)。
//   #e=<号>      成员登记(块「换上」):建通行密钥(带 PRF)→ 页生成人钥匙、PRF 当口令封成口令文件 → 只交公钥(登记这一下不念码)。
//               他生成好以后同一条链接「收钥匙」:刷一次 → 服务器递她那几户的户公钥 → 一人一串码(她这一刷的人公钥 + 她收的全部户公钥)
//               电话里跟他屏上她那行对 → 钉。
//   #c=<号>      他那一屏:列每人包给哪几把 → 刷一次:生成这户两把户钥匙、只包给他自己(口令文件里那把,锁 C2)和恢复码、
//               头一回生成恢复码给他抄 → 户公钥和这屏的名单钉进他的口令文件 → 只交公钥和这两份包 → 列每人一串码(他 16:08 点确认一人一串)。
//               家里人念码,跟哪一行一样他就点那一行「对上了」(再点取消),每一行都点完页才包给名单上的人、写换好(先核后包,原 C1;
//               他 18:06 点确认;不按名字认人,点了哪几行只在这页里)。重开这张:刷一下再看每人的码、照样逐行点;有一行一直没人来 →
//               「作废重来」把还没重封的户全作废(只有这一颗,一串码看不出是哪户;还没包出去,删了就完)。
//   #s=<号>      补章那一屏(换上那天第二刷):重封好的每一样逐样解开、盖章、封回。
//   #v=<一串>    看证件(网页证件块那条路):刷脸后安全盒认出是谁才给料,页解开、比、核章,图只回给这个浏览器。
// 加解密只用 typage(age 官方 TS 库,钉 0.3.1)的公开接口 + 浏览器自带 WebAuthn / WebCrypto(HKDF、HMAC);不手拼 age 头和 STREAM。
// 安全盒递来的字一律 textContent(锁 3,另有 _headers 里的 CSP / Trusted Types 兜着)。
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption";

/* global __VAULT__, __ABL__ */
const VAULT = __VAULT__;                         // 安全盒那几个口的来源(跟 _headers 的 connect-src 是同一个)
const ABL = __ABL__.split(",").filter(Boolean);  // 只给判据消融用;正式打包是空串
const on = (lock) => !ABL.includes(lock);
const SCRYPT_LOGN = "10";                        // 口令文件只认 10 档(设计审 v8 M4:解前读头,不是 10 就拒)
const FIELDS = ["户", "谁的", "叫什么", "类"];
const MARK = "|box1|";
const CLASS_KEY = { "证件": "证件", "卡": "卡和私密", "私密格": "卡和私密", "私密文件": "卡和私密", "系统密码": "卡和私密" };  // 锁 2
const enc = (s) => new TextEncoder().encode(s);
const SALT = crypto.subtle.digest("SHA-256", enc("ALB-5194 person-key PRF salt v1")).then((h) => new Uint8Array(h));  // PRF 盐写死在页里
const STAMP_HEAD = "ALB5194-STAMP ";            // 章在明文第 2 行
const STAMP_INFO = "ALB-5194 item stamp key v1"; // 章钥:HKDF 的 info 写死
const RECOVERY = "_recovery";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const T = {
  zh: { title: "安全盒", list: "这次交:", count: (n) => `共 ${n} 样`, btn: "🔓 刷脸交出这几样", working: "正在交…",
        done: "交好了，回 Telegram 就行", refused: (n, why) => `没交：第 ${n} 样${why}，一样都没交出去。回 Telegram 跟助理说一声。`,
        changed: (n, what) => `没交：第 ${n} 样「${what}」被改过，一样都没交出去。回 Telegram 跟助理说一声，请他重存这一样。`,
        why: { 0: "解不开", 1: "里面装的跟列给你看的不是同一样", 2: "封它的那把钥匙不对" },
        paySub: "刷脸就是确认付款，卡号不会被保存", payBtn: "💳 刷脸确认付款", cancelPay: "不付了，取消",
        payCancelled: "取消了，这笔不会付。回 Telegram 就行。", paid: "确认好了，回 Telegram 就行，助手这就去付",
        payDown: "这会儿没连上，稍等一下再点一次。",
        btnToPin: "🔑 他说钥匙生成好了，点这里收钥匙", pinAlready: "这几把钥匙你都收好了，不用再对。回 Telegram 就行。", btnCodes: "🔓 刷脸再看一遍每人的码", btnPin: "🔐 刷脸收钥匙", pinSave: "🔒 都对上了，收下",
        pinNotYet: "他那边钥匙还没生成好。等他说好了，再点一次上面那颗键。",
        pinHint: "电话里把下面这串码念给他听，跟他屏上你那一行一样，就点「对上了」。等多久都行，这页开着就好。",
        pinRow: (c) => `你的码 · ${c}`, pinAgain: "你已经收过钥匙了。只有他刚跟你说了「作废重来」，才跟他对这串码；不然就是有人在动手脚，别点。", pinDone: "收好了。以后每次开，这台手机都会先核这把钥匙，被换过会直接拦下。回 Telegram 就行。",
        houseCodes: "钥匙生成好了，每人跟你对上、你全点完才包给他们。等你要换的几户都生成好，再电话请每人点「收钥匙」，她念的码跟下面哪一行一样，就点那一行的「对上了」（点错了再点一下取消）；有一行一直没人打来，就点「作废重来」：", left: (n) => `还有 ${n} 行没点「对上了」，点完才算换好。`, btnVoid: "有人对不上，作废重来", voidHint: "作废还没封好的这几户，你再点各户链接重新换一次，家里人再收一次钥匙。", voided: (n) => `作废了 ${n} 户。回 Telegram 重新点各户的链接再换一次。`, voidNone: "这几户都已经封好了，不能作废。回 Telegram 跟助理说一声。", houseRow: (who, c) => `${who} · ${c}`, houseRowBad: (who) => `${who} · 这个人的钥匙前后不一样，点「作废重来」`,
        stale: "没交：你在另一张屏上已经先做完了一户，这张是那之前打开的。请回 Telegram 重新点开这一户的链接再做一次（刚才这张显示的恢复码不用记）。",
        badHouseKey: "没交：安全盒递来的这一户的钥匙跟你手机上记的那把对不上，一样都没交出去。回 Telegram 跟助理说一声。",
        toSafari: "正在打开 Safari…", toSafariSlow: "没跳过去？点右上角 ⋯，选「在 Safari 中打开」。",
        gone: "这件已经不在等了，要的话跟助理再说一声。", down: "安全盒这会儿没接上，稍等一下再点一次。",
        failed: "没成，回 Telegram 重新点一下。", noPrf: "这把通行密钥给不出开盒子要的那一样，回 Telegram 跟助理说一声。",
        doc: { passport: "护照", licence: "驾照", medicare: "Medicare 卡", concession: "优惠卡", visa: "签证", other: "证件" },
        of: (who, what) => `${who} 的${what}`, card: (net, l4) => `${net} 尾号 ${l4} 那张卡`, form: (n) => `私密格 ${n}`,
        scan: (n) => `文件 ${n}`, site: (d) => `${d} 的系统密码`,
        cls: { "证件": "证件", "私密格": "私密格", "私密文件": "私密文件" },
        win: (who, cls, n) => `另外 ${who} 的${cls} ${n} 样，15 分钟内助手不用再叫你刷`,
        store: "这次存：", del: "这次删：", btnConfirm: "🔓 刷脸确认", doneConfirm: "确认好了，回 Telegram 就行",
        enrollTitle: "安全盒 · 登记这台手机", btnEnroll: "🔐 刷脸建这台手机的钥匙", enrolled: "建好了。等他说钥匙生成好了，再点下面那颗键收钥匙。",
        already: "这台手机已经登记过了。", notSynced: "这把通行密钥不会同步备份，换手机就开不了。请在设置里打开 iCloud 钥匙串（密码），再点一次。",
        cutTitle: "安全盒 · 换上", cutHint: "这一户会包给这几个人，每人打电话跟你对上码、你全点完才包：", cutSolo: "这一户只有你自己，不用跟谁对码。",
        row: (who, keys) => `${who} · 包给他：${keys}`, keyName: { "证件": "证件", "卡和私密": "卡和私密" }, sep: "、",
        matched: "对上了", btnCut: "🔓 刷脸换上这一户", recovery: "这是恢复码，抄在纸上收好（手机全丢了靠它找回）：", copied: "抄好了",
        doneCut: "换好了，回 Telegram 就行", doneFail: "都点了，但没交上去。关掉页再点一次链接、重新点一遍。", notEnrolled: (w) => `还有人没登记：${w}。等他们登记好再点。`,
        stampTitle: "安全盒 · 补章", stampWhat: "这次补章：", btnStamp: "🔓 刷脸补章", doneStamp: (n) => `补好了 ${n} 样，回 Telegram 就行`,
        nothingToStamp: "没有要补章的了。", viewWhat: "这次看：", btnView: "🔓 刷脸看", doneView: "看完回 Telegram 就行",
        noPerm: "你没有看这一样的权限。", notStored: "安全盒里还没有这一样。",
        stampAlso: "这一刷顺手盖章（看一眼是不是你们存的）：", stampLine: (when, what) => `${when} 存的 ${what}`,
        when: (d, today) => today ? `${p2(d.getHours())}:${p2(d.getMinutes())}` : `${d.getMonth() + 1}月${d.getDate()}日 ${p2(d.getHours())}:${p2(d.getMinutes())}` },
  en: { title: "Safe Box", list: "Handing over:", count: (n) => `${n} in total`, btn: "🔓 Hand these over with Face ID",
        working: "Handing over…", done: "Done. Go back to Telegram.",
        refused: (n, why) => `Not handed over: item ${n} ${why}. Nothing was sent. Go back to Telegram and tell your assistant.`,
        changed: (n, what) => `Not handed over: item ${n} "${what}" has been changed. Nothing was sent. Go back to Telegram and ask your assistant to save it again.`,
        why: { 0: "couldn't be opened", 1: "isn't what was listed", 2: "was locked with the wrong key" },
        paySub: "Face ID confirms the payment. Your card number won't be saved.", payBtn: "💳 Confirm payment with Face ID",
        cancelPay: "Don't pay, cancel", payCancelled: "Cancelled. This won't be paid. Go back to Telegram.",
        paid: "Confirmed. Go back to Telegram, your assistant will pay now", payDown: "Can't connect right now. Wait a moment and tap again.",
        btnToPin: "🔑 Tap here once they say the keys are ready", pinAlready: "You already have all these keys. Nothing to check. Go back to Telegram.",
        btnCodes: "🔓 Show everyone's code again with Face ID", btnPin: "🔐 Get the keys with Face ID", pinSave: "🔒 All match, keep them",
        pinNotYet: "The keys aren't ready yet. Tap the button above again once they say they are.",
        pinHint: "Read this code out on the phone. If it matches your line on their screen, tap \"Matches\". Take as long as you need; just keep this page open.",
        pinRow: (c) => `Your code · ${c}`, pinAgain: "You already have these keys. Only check this code if they've just told you to start over; otherwise someone is tampering, so don't tap.", pinDone: "Saved. From now on this phone checks this key every time and blocks it if it's been swapped. Go back to Telegram.",
        houseCodes: "The keys are ready. Each person only gets them once their code matches yours and you've tapped every line. Once every household you're switching is ready, call each person and ask them to tap \"Get the keys\". When the code they read out is the same as a line below, tap \"Matches\" on that line (tap it again to undo); if a line's person never calls, tap \"start over\":",
        left: (n) => `${n} line${n === 1 ? "" : "s"} not tapped yet. It's only switched over once every line is tapped.`,
        btnVoid: "Someone's code doesn't match, start over", voidHint: "This cancels the households not sealed yet. Open each household's link again to redo it, and everyone gets the keys again.",
        voided: (n) => `Cancelled ${n} household${n === 1 ? "" : "s"}. Go back to Telegram and open each household's link again.`, voidNone: "These households are already sealed and can't be cancelled. Go back to Telegram and tell your assistant.",
        houseRow: (who, c) => `${who} · ${c}`, houseRowBad: (who) => `${who} · this person's key isn't the same everywhere, tap "start over"`,
        stale: "Not saved: you finished another household on a different screen after this one was opened. Go back to Telegram and open this household's link again (ignore the recovery code shown here).",
        badHouseKey: "Not handed over: the household key Safe Box sent doesn't match the one your phone remembers. Nothing was sent. Go back to Telegram and tell your assistant.",
        toSafari: "Opening Safari…", toSafariSlow: "Didn't switch? Tap ⋯ at the top right and choose \"Open in Safari\".",
        gone: "This isn't waiting any more. If you still need it, just tell your assistant.",
        down: "Safe Box isn't reachable right now. Wait a moment and tap again.",
        failed: "That didn't work. Go back to Telegram and tap again.",
        noPrf: "This passkey can't open the box. Go back to Telegram and tell your assistant.",
        doc: { passport: "passport", licence: "licence", medicare: "Medicare card", concession: "concession card", visa: "visa", other: "ID" },
        of: (who, what) => `${who}'s ${what}`, card: (net, l4) => `${net} card ending ${l4}`, form: (n) => `saved ${n}`,
        scan: (n) => `saved file ${n}`, site: (d) => `system password for ${d}`,
        cls: { "证件": "IDs", "私密格": "saved private details", "私密文件": "saved files" },
        win: (who, cls, n) => `Also ${who}'s other ${cls} (${n}), so your assistant won't ask you again for 15 minutes`,
        store: "Saving:", del: "Deleting:", btnConfirm: "🔓 Confirm with Face ID", doneConfirm: "Confirmed. Go back to Telegram.",
        enrollTitle: "Safe Box · Set up this phone", btnEnroll: "🔐 Make this phone's key with Face ID",
        enrolled: "Done. Once they say the keys are ready, tap the button below to get the keys.",
        already: "This phone is already set up.",
        notSynced: "This passkey won't be backed up, so a new phone couldn't open the box. Turn on iCloud Keychain (Passwords) in Settings, then tap again.",
        cutTitle: "Safe Box · Switch over", cutHint: "The household key will go to these people only after each one calls you, the codes match, and you've tapped every line:", cutSolo: "You're the only one in this household, so there are no codes to check.",
        row: (who, keys) => `${who} · gets: ${keys}`, keyName: { "证件": "IDs", "卡和私密": "cards & private" }, sep: ", ",
        matched: "Matches", btnCut: "🔓 Switch this household over with Face ID",
        recovery: "This is the recovery code. Write it on paper and keep it safe (it's how you get back in if every phone is lost):",
        copied: "I've written it down", doneCut: "Switched over. Go back to Telegram.", doneFail: "All tapped, but it didn't go through. Close this page, open the link again and tap them again.", notEnrolled: (w) => `Not set up yet: ${w}. Tap again once they have.`,
        stampTitle: "Safe Box · Seal", stampWhat: "Sealing:", btnStamp: "🔓 Seal these with Face ID", doneStamp: (n) => `Sealed ${n}. Go back to Telegram.`,
        nothingToStamp: "Nothing left to seal.", viewWhat: "Viewing:", btnView: "🔓 View with Face ID", doneView: "Go back to Telegram when you're done.",
        noPerm: "You don't have permission to see this one.", notStored: "This one isn't in the Safe Box yet.",
        stampAlso: "Also sealing these (check they're things your family saved):", stampLine: (when, what) => `${what}, saved ${when}`,
        when: (d, today) => (today ? "" : `${d.getDate()} ${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getMonth()]} `)
          + `${p2(d.getHours())}:${p2(d.getMinutes())}` },
};

const $ = (id) => document.getElementById(id);
const p2 = (n) => String(n).padStart(2, "0");
const put = (el, t) => { if (on("L3")) el.textContent = t; else el.innerHTML = t; };   // 锁 3
const u2b = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const b2u = (buf) => { const a = new Uint8Array(buf); let s = ""; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (u) => { u = new Uint8Array(u); let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const cat = (...xs) => { const u = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let o = 0; for (const x of xs) { u.set(x, o); o += x.length; } return u; };
const M = {}; const mark = (k) => { M[k] = Math.round(performance.now()); };
window.__box = { M, getCalls: 0, getAllow: null };   // 判据读数(调了几次 get、带没带 allowCredentials);不碰值
class Refuse extends Error { constructor(n, lock, what) { super(`refused ${n}/${lock}`); this.n = n; this.lock = lock; this.what = what; } }
const fail = (why) => Object.assign(new Error(why), { why });

const RAW = location.hash.slice(1);
const h = new URLSearchParams(RAW);
const MODE = ["u", "e", "c", "s", "v"].find((k) => h.has(k)) || "";
const code = h.get("e") || h.get("c") || h.get("s") || "";
let rid = h.get("u") || (MODE === "s" ? "s:" + code : "");
let L = T[h.get("l") === "en" ? "en" : "zh"];
try { history.replaceState(null, "", location.pathname); } catch (e) { /* 不留在历史里 */ }

async function api(path, body) {
  try {
    const r = await fetch(`${VAULT}/box/${path}?r=${encodeURIComponent(rid)}`, { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ unlock_request_id: rid, ...(code ? { code } : {}), ...body }) });
    return await r.json();
  } catch (e) { return { ok: false, why: "vault_down" }; }
}
const said = (o) => (o.why === "vault_down" ? L.down : o.why === "no_such_request" || o.why === "no_such_link" ? L.gone : L.failed);

// 这一行的人话:只照这一行四格拼(拼的就是要比的那几格,他看见的 = 页比的)
function label(x) {
  const [pre, a, b] = x.叫什么.split(":");
  if (pre === "id") return L.of(a, L.doc[b] || b);
  const what = pre === "card" ? L.card(a, b) : pre === "form" ? L.form(a) : pre === "scan" ? L.scan(a) : pre === "site" ? L.site(a) : x.叫什么;
  return L.of(x.户, what);
}
const slotOf = (row) => `${row.户}|${row.把}`;

function innerOf(plain) {                        // 明文第一行(绑定行)末尾的里层名字;没有就 null
  const nl = plain.indexOf(10);
  const line = new TextDecoder().decode(plain.subarray(0, nl < 0 ? 0 : nl));
  const i = line.indexOf(MARK);
  if (i < 0) return null;
  try { const x = JSON.parse(line.slice(i + MARK.length)); return line.startsWith(`${x.户}|user|`) ? x : null; } catch (e) { return null; }
}

// ── 暗记(v9 第 6 条):明文 = 第 1 行绑定行 + 第 2 行章(有的话)+ 正文;章 = HMAC(章钥, 第 1 行整行 + 换行 + 正文) ──
function splitStamp(plain) {
  const nl = plain.indexOf(10);
  const line1 = plain.subarray(0, nl < 0 ? 0 : nl), rest = plain.subarray(nl + 1);
  const head = enc(STAMP_HEAD);
  if (rest.length > head.length && head.every((c, i) => rest[i] === c)) {
    const nl2 = rest.indexOf(10);
    let stamp = null;
    try { stamp = unb64(new TextDecoder().decode(rest.subarray(head.length, nl2 < 0 ? rest.length : nl2))); } catch (e) { /* 坏章 = 没章 */ }
    return { line1, stamp, body: nl2 < 0 ? new Uint8Array(0) : rest.subarray(nl2 + 1) };
  }
  return { line1, stamp: null, body: rest };
}
const stampKeys = new Map();
function stampKey(houseSk) {                     // 章钥:HKDF-SHA256(户 age 私钥串的字节)→ HMAC-SHA256;服务器只有户公钥,算不出
  if (!stampKeys.has(houseSk)) stampKeys.set(houseSk, crypto.subtle.importKey("raw", enc(houseSk), "HKDF", false, ["deriveKey"]).then((ikm) =>
    crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc(STAMP_INFO) }, ikm,
      { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"])));
  return stampKeys.get(houseSk);
}
const stampInput = (p) => cat(p.line1, new Uint8Array([10]), p.body);
async function withStamp(houseSk, p) {
  const st = new Uint8Array(await crypto.subtle.sign("HMAC", await stampKey(houseSk), stampInput(p)));
  return cat(p.line1, new Uint8Array([10]), enc(STAMP_HEAD + b64(st) + "\n"), p.body);
}
async function stampOk(houseSk, p) {
  return !!p.stamp && crypto.subtle.verify("HMAC", await stampKey(houseSk), p.stamp, stampInput(p));
}
const sealTo = async (pub, plain) => { const e = new Encrypter(); e.addRecipient(pub); return e.encrypt(plain); };

// 一串人能对的码:SHA-256(公钥串)前 60 位,12 个 base32 字,四个一组
async function codeOf(pub) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc(pub)));
  let bits = "", s = "";
  for (const x of d.subarray(0, 8)) bits += x.toString(2).padStart(8, "0");
  for (let i = 0; i < 60; i += 5) s += B32[parseInt(bits.slice(i, i + 5), 2)];
  return s.match(/.{4}/g).join("-");
}
// 一人一串(他 16:08 点确认):codeOf(「户钥匙码」‖ 她的人钥匙公钥 ‖ 她收的全部「户|把=户公钥」排好序)。
// 服务器换了她的人公钥、或递她一把假户钥匙、或少给一户,两边算的都对不上 —— 一串盖住。byT = {户: {把: 户公钥}}
const personCode = (agePub, byT) =>
  codeOf(["户钥匙码", agePub, ...Object.keys(byT).flatMap((t) => Object.keys(byT[t]).map((k) => `${t}|${k}=${byT[t][k]}`)).sort()].join("\n"));
// 他屏上每人那一行:只从他口令文件里钉的户公钥(pins)和那一屏封进去的名单(seen)算,不用服务器这一刻递的(修后复核 B2)。
// 不按名字认人(他 18:06 点确认):同名才算同一行,名字长得像的照样各占一行 —— 多塞进来的那行没人打来对,他点不完,就作废重来。
// 同一个人几户递来的人公钥不一样(人公钥只在登记那一下定,正常不会):不出码、那一行点不了,直接写对不上(修后复核 1123-1625 B1)。
async function hisCodes(kf) {
  const per = {};
  for (const [t, rows] of Object.entries(kf.seen || {})) {
    const pin = (kf.pins || {})[t];
    if (!pin) continue;
    for (const r of rows) {
      const e = per[r.id] || (per[r.id] = { id: r.id, pubs: new Set(), byT: {} });
      e.pubs.add(r.age_pub);
      e.byT[t] = Object.fromEntries(r.keys.map((x) => [x, pin[x]]));
    }
  }
  return Promise.all(Object.values(per).sort((a, b) => (a.id < b.id ? -1 : 1)).map(async (e) => (e.pubs.size === 1
    ? { text: L.houseRow(e.id, await personCode([...e.pubs][0], e.byT)), ok: true } : { text: L.houseRowBad(e.id), ok: false })));
}
// 他那屏每人一行 + 「对上了」点按(再点取消);每一行都点了才写换好、标题 DONE-OK,没点完是 DONE-WAIT(点了哪几行只在这页里)。
// tail:重开那屏跟在状态后面的作废说明
// onAll:每一行都点了那一下才包给家里人(wrapAll;先核后包,原 C1)—— 回 true 才写换好,回字串是那句没成的话
function matchRows(rows, tail = "", onAll = null) {
  const done = new Set(), total = rows.length;
  let sent = null;
  const say = async () => {
    const all = done.size === total || !on("C4");
    window.__box.matched = done.size; window.__box.allMatched = all;
    if (!all) { put($("note"), [L.left(total - done.size), tail].filter(Boolean).join("\n\n")); document.title = "DONE-WAIT"; return; }
    if (onAll && sent !== true) sent = await onAll();
    const ok = !onAll || sent === true;
    put($("note"), [ok ? L.doneCut : (L[sent] || L.doneFail), tail].filter(Boolean).join("\n\n")); document.title = ok ? "DONE-OK" : "DONE-ERROR";
  };
  $("list").replaceChildren(...rows.map((r, i) => {
    const li = document.createElement("li"), sp = document.createElement("span");
    put(sp, r.text + " "); li.append(sp);
    if (r.ok) {
      const b = document.createElement("button");
      b.type = "button"; b.className = "ok"; put(b, L.matched);
      b.onclick = () => { if (done.has(i)) done.delete(i); else done.add(i); b.classList.toggle("on", done.has(i)); say(); };
      li.append(b);
    }
    return li;
  }));
  window.__box.houseCodes = rows.map((r) => r.text);
  say();
}
// 他每一行都点了才包(先核后包,原 C1):解开 staged 里他自己那份(mine)、核户公钥跟他口令文件里钉的一样(L6 同一行),
// 包给他口令文件里那一屏名单(seen)上每个人,交 cut_wrap。没点完不调,谁都拿不到户钥匙;多塞的那一行没人来对,永远包不出去。
const wrapAll = (kf, mine) => async () => {
  const packages = {};
  try {
    for (const [t, rows] of Object.entries(kf.seen || {})) {
      const pin = (kf.pins || {})[t], need = [...new Set(rows.flatMap((r) => r.keys))];
      if (!pin || !rows.length || !need.every((k) => mine[`${t}|${k}`])) continue;   // 已拨(包已齐)的户不在 mine 里
      const sk = {};
      for (const k of need) {
        const d = new Decrypter(); d.addIdentity(kf.age);
        sk[k] = (await d.decrypt(unb64(mine[`${t}|${k}`]), "text")).trim();
        if (on("L6") && (await identityToRecipient(sk[k])) !== pin[k]) { window.__box.wrapped = "bad_house_key"; return "badHouseKey"; }
      }
      packages[t] = {};
      for (const r of rows) packages[t][r.id] = Object.fromEntries(await Promise.all(r.keys.map(async (k) => [k, b64(await sealTo(r.age_pub, enc(sk[k] + "\n")))])));
    }
  } catch (e) { window.__box.wrapped = String(e.message || e); return false; }
  if (!Object.keys(packages).length) { window.__box.wrapped = []; return true; }
  const out = await api("cut_wrap", { packages });
  window.__box.wrapped = out.ok ? out.wrapped : out.why;
  return !!out.ok;
};
function recoveryCode() {                        // 恢复码:160 位随机,32 个 base32 字,四个一组
  const r = crypto.getRandomValues(new Uint8Array(20));
  let bits = "", s = "";
  for (const x of r) bits += x.toString(2).padStart(8, "0");
  for (let i = 0; i < 160; i += 5) s += B32[parseInt(bits.slice(i, i + 5), 2)];
  return s;
}

async function passkeyPrf(o) {
  const g = o.get;
  const allow = on("L4") ? (g.allowCredentials || []).map((c) => ({ type: "public-key", id: u2b(c.id) })) : [];
  window.__box.getCalls++; window.__box.getAllow = allow.length;
  const cred = await navigator.credentials.get({ publicKey: { challenge: u2b(g.challenge), rpId: g.rpId, timeout: g.timeout,
    userVerification: "required", allowCredentials: allow, extensions: { prf: { eval: { first: await SALT } } } } });
  const out = cred.getClientExtensionResults().prf?.results?.first;
  const r = cred.response;
  const assertion = { id: cred.id, rawId: b2u(cred.rawId), type: cred.type, clientExtensionResults: {},
    response: { clientDataJSON: b2u(r.clientDataJSON), authenticatorData: b2u(r.authenticatorData), signature: b2u(r.signature),
                ...(r.userHandle ? { userHandle: b2u(r.userHandle) } : {}) } };
  return { prf: out ? new Uint8Array(out) : null, assertion, credId: assertion.rawId };
}

// 口令文件:标准 age 口令文件(PRF 当口令,scrypt 10 档),里面一份 JSON {v, age: 人钥匙[, pins: {户: {把: 户公钥}}][, rec: 恢复码公钥]
//   } —— 没钉的户一律不开(谁的口令文件都一样:挡服务器递回钉之前那份旧口令文件 + 自造户钥匙;整包审 1123-1520 B1)
async function openKeyfile(keyfileB64, prf) {
  const file = unb64(keyfileB64);
  const stanza = new TextDecoder().decode(file.subarray(0, 256)).split("\n")[1] || "";
  const f = stanza.split(" ");
  if (f[0] !== "->" || f[1] !== "scrypt" || f[3] !== SCRYPT_LOGN) throw new Refuse(0, 0);   // M4:只认 10 档,解前读头
  const d = new Decrypter(); d.addPassphrase(b64(prf));
  const k = JSON.parse(await d.decrypt(file, "text").catch(() => { throw new Refuse(0, 0); }));
  if (typeof k.age !== "string") throw new Refuse(0, 0);
  return k;
}
async function sealKeyfile(passphrase, k) {
  const e = new Encrypter(); e.setPassphrase(passphrase); e.setScryptWorkFactor(Number(SCRYPT_LOGN));
  return b64(await e.encrypt(JSON.stringify(k)));
}

// 一刷:认人 → 解口令文件 → 解户钥匙包(L6)→ 该交的整份解、比(锁 1、2)、核章或盖章 → 封给一次性公钥 / 封回户公钥 → 交 → finish
// how.me(assertion, credId) 认出是谁(开盒 / 补章从清单里找;看证件那一单签名交上去由安全盒认,认了才给料)
async function hand(o, how) {
  mark("click");
  const { prf, assertion, credId } = await passkeyPrf(o); mark("get");
  const me = await how.me(assertion, credId);
  if (!me) throw new Refuse(0, 0);
  const give = (row) => !row.stamp_only && (!row.win || ((row.for == null || row.for.includes(me.id)) && !!me.packages[slotOf(row)]));
  const rows = o.list.map((row, i) => [i, row]).filter(([, row]) => give(row) || (row.unstamped && me.packages[slotOf(row)]));
  const sealed = [], stamps = [];
  if (rows.length) {
    if (!prf) throw fail("noPrf");
    const kf = await openKeyfile(me.keyfile, prf); mark("keyfile");
    const houseKey = {};
    for (const [slot, pkg] of Object.entries(me.packages)) {
      const d = new Decrypter(); d.addIdentity(kf.age);
      const sk = (await d.decrypt(unb64(pkg), "text").catch(() => { throw new Refuse(0, 0); })).trim();
      const [t, k] = slot.split("|"), pin = kf.pins && kf.pins[t];
      if (on("L6") && pin && (await identityToRecipient(sk)) !== pin[k]) throw new Refuse(0, 3);   // L6:钉过的户只认钉的那把
      if (on("L6") && on("L6M") && !pin) throw new Refuse(0, 3);   // 没钉这一户 = 递来的是钉之前的旧口令文件(或还没收钥匙),整张拒,谁都一样(整包审 1123-1520 B1)
      houseKey[slot] = sk;
    }
    mark("unwrap");
    for (const [i, row] of rows) {
      const n = i + 1, sk = houseKey[slotOf(row)];
      if (!sk) throw new Refuse(n, 0);
      const r = await fetch(`${VAULT}/box/item?r=${encodeURIComponent(rid)}&n=${i}`);
      if (!r.ok) throw new Refuse(n, 0);
      const d = new Decrypter(); d.addIdentity(sk);
      const plain = await d.decrypt(new Uint8Array(await r.arrayBuffer())).catch(() => { throw new Refuse(n, 0); });
      const inner = innerOf(plain);
      if (on("L1") && (!inner || FIELDS.some((f) => inner[f] !== row[f]))) { plain.fill(0); throw new Refuse(n, 1); }   // 锁 1
      if (on("L2") && CLASS_KEY[inner?.类] !== row.把) { plain.fill(0); throw new Refuse(n, 2); }                       // 锁 2
      const p = splitStamp(plain);
      let out = plain;
      if (row.unstamped) {                                                      // 待盖章:盖好、封回这一户这把的户公钥(从户私钥算,不认服务器递的)
        out = await withStamp(sk, p);
        stamps.push([i, await sealTo(await identityToRecipient(sk), out)]);
      } else if (on("ST") && !(await stampOk(sk, p))) { plain.fill(0); throw new Refuse(n, 4, label(row)); }     // 锁 ST:没章 / 章对不上
      if (give(row)) sealed.push([i, await sealTo(o.eph_pub, out)]);
      plain.fill(0); out.fill(0);
    }
  }
  mark("sealed");
  for (const [path, list] of [["put", sealed], ["stamp", stamps]]) {
    for (const [i, ct] of list) {
      const r = await fetch(`${VAULT}/box/${path}?r=${encodeURIComponent(rid)}&n=${i}`, { method: "POST",
        headers: { "Content-Type": "application/octet-stream" }, body: ct });
      if (!(await r.json()).ok) throw fail("failed");
    }
  }
  mark("put");
  const out = await how.finish(assertion);
  mark("delivered");
  if (!out.ok) throw Object.assign(fail(out.why === "vault_down" ? "down" : "failed"), { out });
  window.__box.sent = sealed.map(([i]) => i); window.__box.stamped = stamps.map(([i]) => i);
  return { n: sealed.length, stamped: stamps.length, out };
}

function clickThen(btn = $("go")) {
  btn.hidden = false;
  return new Promise((res) => { btn.onclick = res; if (!on("L4") && btn === $("go")) res(); }).then(() => { btn.hidden = true; });
}
function lines(texts) {
  $("list").replaceChildren(...texts.map((k) => { const li = document.createElement("li"); put(li, k); return li; }));
}
// 待盖章清单屏(v9 第 6 条:逐样列名字和存的钟点,他看一眼是不是他们存的;钟点是服务器写的,照实留④)
function stampList(rows) {
  const st = rows.filter((x) => x.unstamped);
  if (!st.length) return;
  const now = new Date();
  put($("stampWhat"), L.stampAlso);
  $("stamps").replaceChildren(...st.map((x) => {
    const d = new Date(x.unstamped * 1000), li = document.createElement("li");
    put(li, L.stampLine(L.when(d, d.toDateString() === now.toDateString()), label(x)));
    return li;
  }));
}
function refusedSay(e) { return e.lock === 4 ? L.changed(e.n, e.what || "") : e.lock === 3 ? L.badHouseKey : L.refused(e.n, L.why[e.lock] || L.why[0]); }
async function run(fn, onRefuse) {
  try { await fn(); } catch (e) {
    if (e instanceof Refuse) {                    // 设计审 v8 M3:回一行拒了第几样、哪条锁,不带值
      if (onRefuse) await onRefuse(e);
      put($("note"), refusedSay(e)); window.__box.refused = { n: e.n, lock: e.lock }; document.title = "DONE-REFUSED";
    } else { put($("note"), L[e.why] || L.failed); window.__box.error = String(e.message || e); document.title = "DONE-ERROR"; }
  }
}

// ── #u= 开盒(块 1、2)──
async function openMode() {
  mark("start");
  const o = await api("order", {}); mark("order");
  if (!o.ok) { put($("note"), said(o)); document.title = "DONE-ERROR"; return; }
  const confirm = o.confirm === "store" || o.confirm === "delete";
  if (o.pay) {                                       // 整包审 I4:付安全盒里那张卡,整页照线上 k.js 只说付款(他 11-05 07:27)
    L = { ...L, down: L.payDown };                   // 付款页没接上照 k.js 那句,不提安全盒(修后复核 I4 残)
    const head = String(o.headline || L.payBtn);
    document.title = head; put($("title"), head.replace(" · ", "\n")); $("title").style.whiteSpace = "pre-line";
    put($("what"), L.paySub); stampList(o.list); put($("go"), L.payBtn);
    const cb = $("cancel");                          // 「不付了」(照 k.js v30 A4):只让这一单付不出,不开任何东西;刷脸前才有
    put(cb, L.cancelPay); cb.hidden = false;
    let cancelled = false;
    cb.onclick = async () => {
      cb.disabled = true;
      const r = await api("cancel", {});
      if (!r || !r.ok) { cb.disabled = false; put($("note"), L.payDown); return; }
      cancelled = true; cb.hidden = true; $("go").hidden = true; put($("note"), L.payCancelled); document.title = "DONE-CANCELLED";
    };
    await clickThen();
    cb.hidden = true;
    if (cancelled) return;
    put($("note"), L.working);
    await run(async () => {
      const r = await hand(o, { me: (a, credId) => o.persons.find((p) => p.cred_ids.includes(credId)),
                                finish: (assertion) => api("deliver", { assertion }) });
      put($("note"), L.paid); window.__box.delivered = r.n; document.title = "DONE-OK";
    }, (e) => api("deliver", { refused: { n: e.n, lock: e.lock } }));
    return;
  }
  put($("what"), confirm ? (o.confirm === "store" ? L.store : L.del) : L.list);
  // 本单那几样逐样一行(只照这一行四格拼);整类行按 户 + 类 合成一句,字由页拼、不用安全盒递来的句子(设计审 M1)
  const seen = new Map(), groups = new Map();
  for (const x of confirm ? o.rows : []) { const k = x.叫什么 ? label(x) : String(x.what || ""); if (k) seen.set(k, 1); }
  for (const x of o.list) {
    if (x.stamp_only) continue;
    if (x.win) { const g = `${x.户}|${x.类}`; groups.set(g, (groups.get(g) || new Set()).add(label(x))); }
    else if (!confirm) seen.set(label(x), 1);
  }
  lines([...seen.keys(), ...[...groups.entries()].map(([g, set]) => { const [who, cls] = g.split("|"); return L.win(who, L.cls[cls] || cls, set.size); })]);
  put($("count"), L.count(seen.size + [...groups.values()].reduce((a, v) => a + v.size, 0)));
  stampList(o.list);
  put($("go"), confirm ? L.btnConfirm : L.btn);
  await clickThen();
  put($("note"), L.working);
  await run(async () => {
    const r = await hand(o, { me: (a, credId) => o.persons.find((p) => p.cred_ids.includes(credId)),
                              finish: (assertion) => api("deliver", { assertion }) });
    put($("note"), confirm ? L.doneConfirm : L.done); window.__box.delivered = r.n; document.title = "DONE-OK";
  }, (e) => api("deliver", { refused: { n: e.n, lock: e.lock } }));
}

// ── #s= 补章那一屏(换上那天第二刷)──
async function stampMode() {
  const o = await api("stamp_order", {});
  if (o.lang === "en" && !h.get("l")) L = T.en;
  document.title = L.stampTitle; put($("title"), L.stampTitle);
  if (!o.ok) { put($("note"), o.why === "nothing_to_stamp" ? L.nothingToStamp : said(o)); document.title = o.why === "nothing_to_stamp" ? "DONE-OK" : "DONE-ERROR"; return; }
  rid = o.order_id;
  put($("what"), L.stampWhat);
  const now = new Date();
  lines(o.list.map((x) => { const d = new Date(x.unstamped * 1000); return L.stampLine(L.when(d, d.toDateString() === now.toDateString()), label(x)); }));
  put($("count"), L.count(o.list.length));
  put($("go"), L.btnStamp);
  await clickThen();
  put($("note"), L.working);
  await run(async () => {
    const r = await hand(o, { me: (a, credId) => o.persons.find((p) => p.cred_ids.includes(credId)),
                              finish: (assertion) => api("stamp_finish", { assertion }) });
    put($("note"), L.doneStamp(r.out.stamped)); window.__box.result = r.out; document.title = "DONE-OK";
  });
}

// ── #v= 看证件 ──
async function viewMode() {
  const o = await api("view_order", { items: h.get("v") || "" });
  if (!o.ok) { put($("note"), said(o)); document.title = "DONE-ERROR"; return; }
  rid = o.order_id; if (o.lang === "en" && !h.get("l")) L = T.en;
  document.title = L.title; put($("title"), L.title);
  put($("what"), L.viewWhat);
  const items = (h.get("v") || "").split(",").filter(Boolean);
  lines(items.map((it) => label({ 叫什么: it, 户: "" })));
  put($("go"), L.btnView);
  await clickThen();
  await run(async () => {
    const r = await hand(o, {
      me: async (assertion) => { const a = await api("view_auth", { order_id: rid, assertion }); return a.ok ? a.me : null; },
      finish: () => api("view_finish", { order_id: rid }) }).catch((e) => {
      if (e.out && (e.out.why === "no_permission" || e.out.why === "not_stored")) return { out: e.out, shown: false };
      throw e;
    });
    const out = r.out, docs = out.docs || (out.pages ? [{ pages: out.pages }] : [{ why: out.why }]);
    const nodes = [];
    for (const d of docs) {
      if (d.pages) for (const pg of d.pages) {
        const img = document.createElement("img");
        img.src = URL.createObjectURL(new Blob([unb64(pg.b64)], { type: pg.mime === "image/png" ? "image/png" : "image/jpeg" }));
        img.style.maxWidth = "100%"; nodes.push(img);
      } else { const p = document.createElement("p"); put(p, d.why === "no_permission" ? L.noPerm : L.notStored); nodes.push(p); }
    }
    $("view").replaceChildren(...nodes);
    window.__box.shown = docs.reduce((a, d) => a + (d.pages ? d.pages.length : 0), 0);
    put($("note"), L.doneView); document.title = "DONE-OK";
  });
}

// ── #e= 成员登记 ──
async function enrollMode() {
  const b = await api("enroll_begin", {});
  if (b.lang === "en" && !h.get("l")) L = T.en;
  document.title = L.enrollTitle; put($("title"), L.enrollTitle);
  if (!b.ok) { put($("note"), said(b)); document.title = "DONE-ERROR"; return; }
  if (b.already) { put($("note"), L.already); document.title = "DONE-OK"; return toPin(); }
  put($("go"), L.btnEnroll);
  for (;;) {
    await clickThen();
    try {
      const c = b.create, salt = await SALT;
      const cred = await navigator.credentials.create({ publicKey: { ...c, challenge: u2b(c.challenge),
        user: { ...c.user, id: u2b(c.user.id) }, excludeCredentials: (c.excludeCredentials || []).map((x) => ({ ...x, id: u2b(x.id) })),
        extensions: { prf: { eval: { first: salt } } } } });
      const x = cred.getClientExtensionResults().prf || {};
      let first = x.results && x.results.first;
      if (!first) {                                // 建的那一下没给 PRF(多数手机):再刷一次取(这一刷不交给服务器)
        const a = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: c.rp.id,
          userVerification: "required", allowCredentials: [{ type: "public-key", id: cred.rawId }], extensions: { prf: { eval: { first: salt } } } } });
        first = a.getClientExtensionResults().prf?.results?.first;
      }
      if (!first) throw fail("noPrf");
      const sk = await generateX25519Identity(), pub = await identityToRecipient(sk);
      const keyfile = await sealKeyfile(b64(first), { v: 1, age: sk });
      const credential = { id: cred.id, rawId: b2u(cred.rawId), type: cred.type, clientExtensionResults: {},
        response: { clientDataJSON: b2u(cred.response.clientDataJSON), attestationObject: b2u(cred.response.attestationObject),
                    ...(cred.response.getTransports ? { transports: cred.response.getTransports() } : {}) } };
      const out = await api("enroll_finish", { credential, age_pub: pub, keyfile_b64: keyfile });
      if (out.why === "not_synced") { put($("note"), L.notSynced); window.__box.error = "not_synced"; continue; }
      if (!out.ok) throw fail(out.why === "vault_down" ? "down" : "failed");
      put($("note"), L.enrolled); document.title = "DONE-OK";
      return toPin();
    } catch (e) { put($("note"), L[e.why] || L.failed); window.__box.error = String(e.message || e); document.title = "DONE-ERROR"; return; }
  }
}

// ── 家里人收钥匙(还是登记那条链接;他生成好那一户以后):刷一次 → 拿服务器递的户公钥 + 她的人公钥算一串码电话里对 →
//    她点「对上了」才把户公钥钉进她的口令文件(L6 从此认这把;服务器造不出口令文件,钉过的塞不进假户钥匙)。对码不限时。
async function toPin() {
  for (;;) {
    const b2 = $("go2"); put(b2, L.btnToPin);
    await clickThen(b2);
    const o = await api("pin_order", {});
    if (o.ok) return pinMode(o);
    put($("note"), o.why === "nothing_to_pin" ? L.pinNotYet : said(o));
    if (o.why !== "nothing_to_pin") { document.title = "DONE-ERROR"; return; }
  }
}
async function pinMode(o) {
  put($("code"), ""); put($("note"), ""); put($("go"), L.btnPin); $("go").disabled = false;
  await clickThen();
  await run(async () => {
    const { prf, assertion, credId } = await passkeyPrf(o); mark("get");
    if (!o.cred_ids.includes(credId)) throw new Refuse(0, 0);
    if (!prf) throw fail("noPrf");
    const kf = await openKeyfile(o.keyfile, prf), me = await identityToRecipient(kf.age);
    const got = {};                                                // 服务器递来的户公钥(公开的);递假的、少递一户,码就跟他那行对不上
    for (const [slot, pub] of Object.entries(o.pubs || {})) {
      const [t, k] = slot.split("|");
      (got[t] = got[t] || {})[k] = String(pub);
    }
    const old = kf.pins || {};
    const differs = (t) => old[t] && Object.keys(got[t]).some((k) => old[t][k] && old[t][k] !== got[t][k]);
    const ts = Object.keys(got).filter((t) => !old[t] || Object.keys(got[t]).some((k) => old[t][k] !== got[t][k])).sort();
    if (!ts.length) { put($("note"), L.pinAlready); document.title = "DONE-OK"; return; }
    // 钉过、这回递来的不一样:只可能是他作废重来了,或有人在动手脚 —— 不自己判,先写明,再照样对一串(他那屏只用他口令文件里的户公钥算)
    const again = ts.some(differs);
    const code = await personCode(me, got), go = $("go");      // 一人一串:她收的全部户(连已钉的),跟他屏上她那一行比
    put($("what"), L.pinHint); put($("note"), again ? L.pinAgain : "");
    const li = document.createElement("li"), sp = document.createElement("span"), b = document.createElement("button");
    put(sp, L.pinRow(code) + " ");
    b.type = "button"; b.className = "ok"; put(b, L.matched);
    let matched = false;
    b.onclick = () => { matched = true; b.disabled = true; go.disabled = false; };
    li.append(sp, b); $("list").replaceChildren(li);
    window.__box.pinCode = code; window.__box.pinAgain = again;
    put(go, L.pinSave); go.disabled = on("C3");
    await clickThen();
    if (on("C3") && !matched) throw new Refuse(0, 0);
    const pins = { ...old };
    for (const t of ts) pins[t] = { ...got[t] };
    const out = await api("pin_finish", { assertion, tenants: ts, keyfile_b64: await sealKeyfile(b64(prf), { ...kf, pins }) });
    if (!out.ok) throw fail(out.why === "vault_down" ? "down" : "failed");
    put($("note"), L.pinDone); document.title = "DONE-OK";
  });
}

// ── #c= 他那一屏 ──
async function cutMode() {
  const o = await api("cut_order", {});
  if (o.lang === "en" && !h.get("l")) L = T.en;
  document.title = L.cutTitle; put($("title"), L.cutTitle);
  if (!o.ok) { put($("note"), o.why === "not_enrolled" ? L.notEnrolled((o.who || []).join(L.sep)) : said(o)); document.title = "DONE-ERROR"; return; }
  if (o.codes_only) {                                // 交过了、重开这张:刷一下,用他口令文件里钉的户公钥给每人算那行码(I2),不再生成
    put($("go"), L.btnCodes); await clickThen();
    await run(async () => {
      const { prf, assertion, credId } = await passkeyPrf(o);
      if (!o.owner.cred_ids.includes(credId)) throw new Refuse(0, 0);
      if (!prf) throw fail("noPrf");
      const kf = await openKeyfile(o.owner.keyfile, prf);
      if (!(kf.pins || {})[o.tenant] || !(kf.seen || {})[o.tenant]) throw new Refuse(0, 3);   // 只认他口令文件里那一套(B2)
      const codes = await hisCodes(kf);
      if (!codes.length) { matchRows([], "", wrapAll(kf, o.mine || {})); return; }   // 名单上只有他:没码要对、没人要包
      put($("what"), L.houseCodes);
      // 有一行一直没人来 → 作废重来:还没重封的户全作废(一串码看不出是哪户);已重封的不动(那时它的人全钉过了)
      matchRows(codes, L.voidHint, wrapAll(kf, o.mine || {}));
      const b2 = $("go2"); put(b2, L.btnVoid); b2.hidden = false;
      await clickThen(b2);
      const vt = (o.void_tenants || []).filter((t) => (kf.pins || {})[t]);
      if (!vt.length) { put($("note"), L.voidNone); document.title = "DONE-ERROR"; return; }
      const pins = { ...(kf.pins || {}) }, seen = { ...(kf.seen || {}) };
      for (const t of vt) { delete pins[t]; delete seen[t]; }
      const out = await api("cut_void", { assertion, tenants: vt, kf_fp: o.kf_fp,
        owner_keyfile_b64: await sealKeyfile(b64(prf), { ...kf, pins, seen }) });
      if (!out.ok) throw fail(out.why === "vault_down" ? "down" : "failed");
      lines([]); put($("what"), ""); put($("note"), L.voided(vt.length)); window.__box.voided = vt; document.title = "DONE-OK";
    });
    return;
  }
  put($("what"), o.rows.length ? L.cutHint : L.cutSolo);      // 名单上只有他:不写「这几个人」配空名单(联测撞见 1)
  lines(o.rows.map((row) => L.row(row.id, row.keys.map((k) => L.keyName[k] || k).join(L.sep))));
  put($("go"), L.btnCut);
  await clickThen();
  put($("note"), L.working);
  await run(async () => {
    const { prf, assertion, credId } = await passkeyPrf(o); mark("get");
    if (!o.owner.cred_ids.includes(credId)) throw new Refuse(0, 0);
    if (!prf) throw fail("noPrf");
    const kf = await openKeyfile(o.owner.keyfile, prf);
    const keys = {}, pubs = {};
    for (const k of ["证件", "卡和私密"]) { keys[k] = await generateX25519Identity(); pubs[k] = await identityToRecipient(keys[k]); }
    const wrap = async (pub, ks) => Object.fromEntries(await Promise.all(ks.map(async (k) => [k, b64(await sealTo(pub, enc(keys[k] + "\n")))])));
    const packages = {};                                                                     // 首刷只包他自己和恢复码(先核后包):家里人那几份他全点完才包
    packages[o.owner.id] = await wrap(await identityToRecipient(kf.age), o.owner.keys);    // 锁 C2:他自己那份用口令文件里那把
    let recovery = null, recPub = kf.rec;                                                    // 恢复码公钥也只取口令文件里的,没有才生成
    if (!recPub) {
      const rsk = await generateX25519Identity(), rc = recoveryCode();
      recPub = await identityToRecipient(rsk);
      recovery = { pub: recPub, keyfile_b64: await sealKeyfile(rc, { v: 1, age: rsk, pins: { [o.tenant]: pubs } }) };
      put($("note"), L.recovery); put($("code"), rc.match(/.{4}/g).join("-")); window.__box.recovery = true;
      put($("go2"), L.copied);
      await clickThen($("go2"));
      put($("code"), "");
    }
    packages[RECOVERY] = await wrap(recPub, ["证件", "卡和私密"]);
    // 这一屏的名单(人公钥、收哪几把)跟钉一起封进他的口令文件:之后每人那一行码只从这里算,服务器改不了(修后复核 1123-1540 B2)
    const nkf = { ...kf, pins: { ...(kf.pins || {}), [o.tenant]: pubs }, rec: recPub,
                  seen: { ...(kf.seen || {}), [o.tenant]: o.rows.map((r) => ({ id: r.id, age_pub: r.age_pub, keys: r.keys })) } };
    const owner_keyfile_b64 = await sealKeyfile(b64(prf), nkf);
    const out = await api("cut_finish", { assertion, pubs, packages, owner_keyfile_b64, kf_fp: o.kf_fp, ...(recovery ? { recovery } : {}) });
    if (!out.ok) throw fail(out.why === "vault_down" ? "down" : out.why === "stale" ? "stale" : "failed");   // 整包审 I3
    const mine = { ...(o.mine || {}), ...Object.fromEntries(Object.entries(packages[o.owner.id]).map(([k, v]) => [`${o.tenant}|${k}`, v])) };
    const wrapNow = wrapAll(nkf, mine);
    if (!on("W1")) window.__box.wrappedAtCut = await wrapNow();     // 只给判据消融:改回首刷就包
    const codes = await hisCodes(nkf);                 // 一人一串:她收的全部户(到这一户为止他换过的),她那页拿递来的户公钥自己算
    if (!codes.length) { matchRows([], "", wrapNow); return; }
    put($("what"), L.houseCodes); matchRows(codes, "", wrapNow);
  });
}

async function main() {
  document.title = L.title;
  put($("title"), L.title);
  // 锁 5:在 Telegram 自带浏览器里(不是安卓)跳一次 Safari —— 那里建不了 / 用不了通行密钥(真机 NotAllowedError)。
  // 照线上开盒页 k.js:103-120:sessionStorage 记跳过一次,重载不再跳只教一句;切走就把自己关掉。小程序 openLink 出来的不在这里,照他默认浏览器开
  const inTg = !!window.TelegramWebviewProxy, android = /Android/i.test(navigator.userAgent || "");
  if (on("L5") && MODE && inTg && !android) {
    const key = "bj:" + RAW; let again = false;
    try { again = sessionStorage.getItem(key) === "1"; sessionStorage.setItem(key, "1"); } catch (e) { /* 无痕模式 */ }
    put($("note"), L.toSafari);
    document.addEventListener("visibilitychange", () => { if (document.hidden) setTimeout(() => window.close(), 50); });
    const slow = () => put($("note"), L.toSafariSlow);
    document.title = "JUMP";
    if (again) return slow();
    setTimeout(slow, 1500);
    location.href = "x-safari-" + location.origin + location.pathname + "#" + RAW + "&j=1";
    return;
  }
  const modes = { u: openMode, e: enrollMode, c: cutMode, s: stampMode, v: viewMode };
  if (!modes[MODE]) { put($("note"), L.failed); document.title = "DONE-ERROR"; return; }
  await modes[MODE]();
}

main();
