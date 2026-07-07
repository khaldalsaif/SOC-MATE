/* ============================================================
   SOC Mate — popup logic
   Tabs: Extract / Utilities / History / Settings
   Features: site-aware extraction (Splunk DOM), sanitize/defang/redact,
   Splunk OR/AND/IN, Defender KQL, decoders + HTML/HTTP strippers,
   UA parser, subnet calc + membership, live VT/AbuseIPDB/RDAP/Geo enrichment.
   ============================================================ */

const state = {
  raw: {},            // raw extracted (refanged + sanitized minimal)
  rendered: {},       // what we display/copy based on toggles
  encoded: [],        // rich encoded-command data: {blob, decoded, src}
  fieldOverrides: {}, // per-category custom field names
  enrichResults: [],  // [{ value, provider, iocType, level, summary, fields, lines }]
  procs: []           // Defender process records: {name,pid,cmd,pname,ppid,pcmd,gpname,...}
};

let enrichConfirmed = false; // session gate before first live lookup
let hiddenCats = {};         // category visibility (from Settings)
let lastExtractWasFresh = false; // suppress "preserve open sections" on new extract
let includeHeaders = false;  // settings: prepend "=== TITLE ===" in All IOCs pane
let autoExtract = false;     // settings: auto-run extraction when popup opens on a SOC page
let autoExtractUrls = [];    // user-defined domains/URLs that also trigger auto-extract
let lastExtractedUrl = "";   // URL the current results came from (gates auto-extract re-runs)
let lastOwnSaveTs = 0;       // timestamp of our own last saveLastExtraction — skip self-echoes
let iocFieldSettings = {};   // { type: { field, index, sourcetype } } — persisted to storage
let kqlSettings      = {};   // { type: { table, col, op } } — persisted to storage
let splunkControls   = [];   // [{ id, name, index, sourcetype, fields:{type:fieldname} }]
let kqlControls      = [];   // [{ id, name, fields:{type:{col,op}} }]
let savedOpenSections   = null; // Set of IOC types that were open when popup last closed

/* Are we running as the full-page workspace (popup.html?view=tab) rather than
   the toolbar popup? The workspace persists while the analyst works in other
   tabs; the popup vanishes on blur. Same code, two layouts. */
const IS_TAB_VIEW = (() => {
  try { return new URLSearchParams(location.search).get("view") === "tab"; }
  catch (_) { return false; }
})();

/* ---------- element refs ---------- */
const statusEl    = document.getElementById("status");
const sanitizeEl  = document.getElementById("sanitize");
const defangEl    = document.getElementById("defang");
const redactEl    = document.getElementById("redact");
const separatorEl = document.getElementById("separator");
const numberEl    = document.getElementById("numbered");
const quotedEl    = document.getElementById("quoted");
const wildcardPreEl   = document.getElementById("wildcard-pre");
const wildcardSufEl   = document.getElementById("wildcard-suf");
const singleQuotedEl  = document.getElementById("single-quoted");

/* Redaction config — loaded from storage; reapplied on every recompute. */
let redactCfg = { list: [], isRegex: false, replacement: "<redacted>" };
function applyRedaction(s) {
  if (!redactEl || !redactEl.checked || !redactCfg.list.length) return s;
  let out = String(s);
  for (const pat of redactCfg.list) {
    if (!pat) continue;
    try {
      const re = redactCfg.isRegex
        ? new RegExp(pat, "gi")
        : new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      out = out.replace(re, redactCfg.replacement);
    } catch (e) { /* malformed user regex — skip */ }
  }
  return out;
}

/* ---------- maps ---------- */
const TITLES = {
  src_ip: "SRC IP", dest_ip: "DEST IP", ips: "IP",
  domains: "DOMAINS", urls: "URLS", emails: "EMAILS",
  email_subjects: "EMAIL SUBJECTS",
  hostnames: "HOSTNAMES", files: "FILES", paths: "FILE PATHS",
  md5: "MD5", sha1: "SHA1", sha256: "SHA256", cves: "CVEs",
  user_agents: "USER AGENTS",
  encoded: "ENCODED CMD"
};

const FIELD_DEFAULTS = {
  src_ip: "src_ip", dest_ip: "dest_ip", ips: "ip",
  domains: "domain", urls: "url", emails: "email",
  email_subjects: "subject",
  hostnames: "host", files: "file_name", paths: "folder_path",
  md5: "md5", sha1: "sha1", sha256: "sha256", cves: "cve",
  user_agents: "http_user_agent",
  encoded: "process_command_line"
};

const KQL = {
  src_ip:        { table: "DeviceNetworkEvents", col: "RemoteIP",          op: "in~" },
  dest_ip:       { table: "DeviceNetworkEvents", col: "RemoteIP",          op: "in~" },
  ips:           { table: "DeviceNetworkEvents", col: "RemoteIP",          op: "in~" },
  domains:       { table: "DeviceNetworkEvents", col: "RemoteUrl",         op: "has_any" },
  urls:          { table: "DeviceNetworkEvents", col: "RemoteUrl",         op: "has_any" },
  emails:        { table: "EmailEvents",         col: "SenderFromAddress", op: "in~" },
  email_subjects:{ table: "EmailEvents",         col: "Subject",           op: "has_any" },
  hostnames:     { table: "DeviceInfo",          col: "DeviceName",        op: "in~" },
  files:         { table: "DeviceFileEvents",    col: "FileName",          op: "in~" },
  paths:         { table: "DeviceFileEvents",    col: "FolderPath",        op: "in~" },
  md5:           { table: "DeviceFileEvents",    col: "MD5",               op: "in~" },
  sha1:          { table: "DeviceFileEvents",    col: "SHA1",              op: "in~" },
  sha256:        { table: "DeviceFileEvents",    col: "SHA256",            op: "in~" },
  user_agents:   { table: "CloudAppEvents",      col: "UserAgent",         op: "has_any" }
};

/* Pivot URL builders (open a pre-filled tab; nothing is sent until the analyst clicks) */
const PIVOTS = {
  vt_ip:      v => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}`,
  vt_domain:  v => `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}`,
  vt_url:     v => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`,
  vt_file:    v => `https://www.virustotal.com/gui/file/${encodeURIComponent(v)}`,
  abuse:      v => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`,
  shodan:     v => `https://www.shodan.io/host/${encodeURIComponent(v)}`,
  urlscan:    v => `https://urlscan.io/search/#${encodeURIComponent(v)}`,
  google:     v => `https://www.google.com/search?q=${encodeURIComponent('"' + v + '"')}`,
  mxt_ip:     v => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${encodeURIComponent(v)}&run=toolpage`,
  mxt_domain: v => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${encodeURIComponent(v)}&run=toolpage`,
  mxt_email:  v => { const d = v.includes('@') ? v.split('@').pop() : v; return `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${encodeURIComponent(d)}&run=toolpage`; },
};
const PIVOT_LABEL = {
  vt_ip:"VT", vt_domain:"VT", vt_url:"VT", vt_file:"VT",
  abuse:"AbuseIPDB", shodan:"Shodan", urlscan:"URLScan", google:"Google",
  mxt_ip:"MXToolbox", mxt_domain:"MXToolbox", mxt_email:"MXToolbox",
};

/* Short + full labels for live-enrich providers */
const ENRICH_LABEL = { vt:"VT", abuseipdb:"Abuse", multigeo:"Geo", rdap:"WHOIS" };
const ENRICH_NAME  = { vt:"VirusTotal", abuseipdb:"AbuseIPDB", multigeo:"multi-source geo", rdap:"RDAP" };

function pivotsForType(type) {
  if (["src_ip", "dest_ip", "ips"].includes(type)) return ["vt_ip", "abuse", "shodan", "mxt_ip", "google"];
  if (type === "domains") return ["vt_domain", "urlscan", "mxt_domain", "google"];
  if (type === "urls")    return ["vt_url", "urlscan", "google"];
  if (["md5", "sha1", "sha256"].includes(type)) return ["vt_file", "google"];
  if (type === "emails")  return ["mxt_email", "google"];
  return ["google"];
}
function enrichForType(type) {
  const out = [];
  if (["src_ip","dest_ip","ips","domains","urls","md5","sha1","sha256"].includes(type)) out.push("vt");
  if (["src_ip","dest_ip","ips"].includes(type)) out.push("abuseipdb");
  if (["src_ip","dest_ip","ips"].includes(type)) out.push("multigeo");   // multi-source geolocation
  if (["src_ip","dest_ip","ips","domains"].includes(type)) out.push("rdap"); // WHOIS brief
  return out;
}

const FILE_EXTS = [
  "exe","dll","sys","scr","pif","bat","cmd","ps1","psm1","vbs","vbe","js","jse",
  "wsf","wsh","hta","msi","msp","jar","lnk","reg","inf","cpl","ocx",
  "doc","docx","docm","dot","dotm","xls","xlsx","xlsm","xlsb","ppt","pptx","pptm",
  "pdf","rtf","one","txt","md","htm","html","xhtml","css",
  "zip","rar","7z","gz","tar","tgz","bz2","cab","ace","arj","iso","img","vhd",
  "csv","xml","json","ini","conf","log","dat","bin","tmp","dmp","yaml","yml",
  "php","asp","aspx","jsp","jspx","sh","bash","py","pl","rb","go","elf","so",
  "apk","dmg","pkg","deb","rpm","torrent","jpg","jpeg","png","gif","svg","ico"
];
const FILE_RE = new RegExp("\\b[A-Za-z0-9._\\-]+\\.(?:" + FILE_EXTS.join("|") + ")\\b", "gi");
const FILE_EXT_SET = new Set(FILE_EXTS.map(e => e.toLowerCase()));

/* ---------------------------
   File path extraction (spaces allowed)
   Windows:  C:\Program Files\App\evil.exe   \\server\share\my file.dll
             %APPDATA%\Roaming\thing.bat
   Unix:     /usr/local/bin/payload   /home/john doe/x.sh   ~/.config/run.py

   Strategy: match generously (allow spaces inside segments), stopping only at
   a hard boundary (newline, tab, quote, comma, the chars Windows forbids, or a
   second consecutive space). Then trimToPath() walks the tail back to the last
   segment that ends in a KNOWN extension — that's how we let "Program Files"
   through but cut "evil.exe and also..." right after the .exe.
   --------------------------- */
// Windows root + greedy body that allows single spaces. Stops at hard delimiters.
const WIN_PATH_RE = /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9._$ -]+?\\[A-Za-z0-9._$ -]+?\\|%[A-Za-z0-9_()]+%\\)(?:[^\\\/:*?"<>|\t\r\n,]+\\?)*/g;
// Unix root + greedy body allowing single spaces, stopping at hard delimiters.
const NIX_PATH_RE = /(?:^|[\s"'(=`])((?:\/|~\/)(?:[^\/\0\t\r\n,"'`]+\/)+[^\/\0\t\r\n,"'`]+)/g;

const HARD_SEP = /[.,;:)\]}"'>]+$/; // trailing sentence punctuation

/* Walk a raw match back to a real path ending in a known extension.
   - If a segment contains a "<file.ext> <word>" boundary, cut right after .ext.
   - Collapse double-spaces (those usually mean prose started).
   - Trim trailing punctuation. */
function trimToPath(raw, sep) {
  let p = String(raw).replace(HARD_SEP, "");
  // If a double space appears, prose almost certainly started — cut there.
  const dbl = p.indexOf("  ");
  if (dbl !== -1) p = p.slice(0, dbl);

  const lastSep = p.lastIndexOf(sep);
  if (lastSep === -1) return p.trim();
  const dir = p.slice(0, lastSep + 1);
  let last = p.slice(lastSep + 1); // final segment, may be "evil.exe and also"

  // If the final segment has a known extension followed by " word(s)", cut after ext.
  // Find the FIRST token in the last segment that ends in a known extension.
  const tokens = last.split(" ");
  let acc = [];
  for (let i = 0; i < tokens.length; i++) {
    acc.push(tokens[i]);
    const candidate = tokens[i].replace(HARD_SEP, "");
    const ext = candidate.includes(".") ? candidate.split(".").pop().toLowerCase() : "";
    if (FILE_EXT_SET.has(ext)) {
      // path ends here (filename with known ext). Drop trailing punctuation.
      return (dir + acc.join(" ")).replace(HARD_SEP, "").trim();
    }
  }
  // No known extension in the final segment (e.g. a folder path). Keep as-is,
  // but if the last token looks like a lone prose word, keep the whole dir+last.
  return (dir + last).replace(HARD_SEP, "").trim();
}

/* Pull the filename (last segment) out of a path, if it has a known extension. */
function fileNameFromPath(p) {
  const seg = String(p).replace(HARD_SEP, "").split(/[\\/]/).pop() || "";
  const ext = seg.includes(".") ? seg.split(".").pop().toLowerCase() : "";
  return FILE_EXT_SET.has(ext) ? seg : "";
}

function extractPaths(text) {
  const out = new Set();
  let m;
  WIN_PATH_RE.lastIndex = 0;
  while ((m = WIN_PATH_RE.exec(text)) !== null) {
    const p = trimToPath(m[0], "\\");
    if (p.length > 3 && /\\.+/.test(p.replace(/^[A-Za-z]:\\$/, ""))) out.add(p);
  }
  NIX_PATH_RE.lastIndex = 0;
  while ((m = NIX_PATH_RE.exec(text)) !== null) {
    const p = trimToPath(m[1], "/");
    if (p.length > 2) out.add(p);
  }
  return [...out];
}

/* Valid TLD allowlist — a real domain's last label must be one of these.
   This is what separates "report.html" (file) from "evil.com" (domain).
   Not exhaustive (there are 1500+ TLDs) but covers the overwhelming majority
   seen in IOCs: all common gTLDs, the ccTLDs, and the abuse-heavy new gTLDs.
   Add any you need. */
const VALID_TLDS = new Set([
  // classic gTLDs
  "com","net","org","edu","gov","mil","int","info","biz","name","pro","mobi",
  "aero","asia","cat","coop","jobs","museum","tel","travel","xxx","post",
  // common new gTLDs (incl. abuse-heavy ones seen in phishing/malware)
  "io","co","app","dev","cloud","online","site","web","website","space","store",
  "shop","tech","xyz","top","club","live","life","world","today","news","blog",
  "icu","vip","work","link","click","download","stream","host","fun","cyou",
  "monster","quest","sbs","cfd","rest","bond","autos","lol","makeup","skin",
  "ai","me","tv","cc","ws","gg","sh","to","ly","fm","is","as","im",
  // real TLDs that ALSO look like file extensions (2023+ gTLDs, abuse-prone)
  "zip","mov","app","dev","page","foo","day","new","prof","phd","esq","bar",
  // major ccTLDs
  "us","uk","ca","au","de","fr","nl","ru","cn","jp","kr","in","br","it","es",
  "se","no","fi","dk","pl","ch","at","be","cz","pt","gr","ie","il","tr","za",
  "mx","ar","cl","nz","sg","hk","tw","th","my","id","ph","vn","ua","ro","hu",
  "sa","ae","eg","ng","ke","pk","bd","ir","iq","jo","lb","kw","qa","bh","om",
  // common second-level patterns handled separately below (co.uk etc.)
]);

/* Multi-label public suffixes we want to recognize (so "bbc.co.uk" stays a
   domain and the last label "uk" is correctly a TLD). We only need the SET of
   final labels for validation, which VALID_TLDS already covers; this list is
   here as documentation of the known compound suffixes. */

/* Decide whether a domain-regex match is really a domain.
   Returns true if the final label is a valid TLD AND (it's not purely a
   file ext, or it's an ambiguous ext that's also a TLD like .zip/.app). */
function isLikelyDomain(candidate) {
  const labels = candidate.toLowerCase().split(".");
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];

  const isTld = VALID_TLDS.has(tld);
  const isExt = FILE_EXT_SET.has(tld);

  // Clear cases
  if (isTld && !isExt) return true;    // e.g. evil.com
  if (isExt && !isTld) return false;   // e.g. report.html, invoice.docx

  // Ambiguous: extension that is ALSO a real TLD (.zip .mov .app .sh .py ...)
  // Keep as a domain candidate (don't silently drop a possible IOC), but the
  // file regex will also surface it under FILES, so the analyst sees both.
  if (isTld && isExt) return true;

  // Final label is neither a known TLD nor a known ext — unknown TLD.
  // Be permissive: 2+ char alpha final label that isn't an ext -> treat as domain
  // (covers rarer ccTLDs/gTLDs not in our list).
  return /^[a-z]{2,}$/.test(tld) && !isExt;
}

/* Filter a list of raw domain matches down to real domains. */
function filterDomains(matches) {
  return (matches || []).filter(isLikelyDomain);
}

/* ============================================================
   TABS
   ============================================================ */
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tabpanel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") renderHistory();
    saveLiveState();
  });
});

/* Persist which IOC sections are open/closed whenever the analyst expands or
   collapses one. Uses capture because <details> toggle doesn't bubble in all
   contexts, and we only care about ioc-section details inside #output. */
(function wireOutputTogglePersist() {
  const out = document.getElementById("output");
  if (!out) return;
  out.addEventListener("toggle", (e) => {
    if (e.target && e.target.classList && e.target.classList.contains("ioc-section")) {
      saveLiveState();
    }
  }, true /* capture */);
})();

/* Persist append-mode toggle state */
(function wireAppendModePersist() {
  const el = document.getElementById("append-mode");
  if (el) el.addEventListener("change", saveLiveState);
})();

/* ============================================================
   WORKSPACE TAB (popup.html?view=tab)
   "Open in tab" promotes the popup to a persistent full-page tab so collected
   IOCs survive while the analyst works. The extraction state already round-
   trips through chrome.storage.local (lastExtraction), so the workspace picks
   up whatever the popup had on open — no explicit handoff needed.
   ============================================================ */
(function initViewMode() {
  const openBtn = document.getElementById("open-tab");
  if (IS_TAB_VIEW) {
    document.body.classList.add("tab-view");
    document.title = "SOC Mate — workspace";
    if (openBtn) openBtn.remove();          // already in the tab; nothing to open
    return;
  }
  if (!openBtn) return;
  openBtn.addEventListener("click", async () => {
    saveLastExtraction();                    // make sure the tab sees current work
    const wsUrl = chrome.runtime.getURL("popup.html") + "?view=tab";
    try {
      // Reuse an existing workspace tab if one's already open; else create it.
      const all = await chrome.tabs.query({});
      const existing = all.find(t => (t.url || "").startsWith(wsUrl));
      if (existing) {
        await chrome.tabs.update(existing.id, { active: true });
        if (existing.windowId != null) await chrome.windows.update(existing.windowId, { focused: true });
      } else {
        await chrome.tabs.create({ url: wsUrl });
      }
    } catch (e) {
      console.warn("[IOC] open-in-tab failed:", e);
      chrome.tabs.create({ url: wsUrl });
    }
    window.close();                          // collapse the popup; work continues in the tab
  });
})();

/* ============================================================
   EXTRACTION
   ============================================================ */
/* Run the extraction in the target tab on demand — no pre-injected content
   script, no message passing. chrome.scripting.executeScript serializes the
   function, runs it in the tab's isolated world, and returns whatever the
   function returns via structured clone. Always fresh, no race conditions.
   Returns { ok, result?, error? } so the caller can show specifics. */
async function extractFromTab(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: pageExtract
    });
    if (!results || !results.length) return { ok: false, error: "no results" };
    const frame = results[0];
    // Chrome puts a thrown error inside the function under frame.error (Chrome 102+).
    if (frame.error) {
      console.warn("[IOC] pageExtract threw:", frame.error);
      return { ok: false, error: "page script error: " + (frame.error.message || frame.error) };
    }
    if (!frame.result) return { ok: false, error: "page script returned nothing" };
    return { ok: true, result: frame.result };
  } catch (e) {
    console.warn("[IOC] executeScript failed:", e);
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* Which tab should "Extract from page" run against?
   - Popup: the page underneath us — the active tab in the current window.
   - Workspace (?view=tab): WE are the active tab, so that query would target
     the extension page. Use the last real web page the analyst focused
     (tracked by the background worker into chrome.storage.session), and
     re-validate it's still open. Falls back to the most recently accessed
     http(s) tab. Returns a tab object or null. */
async function getTargetTab() {
  if (!IS_TAB_VIEW) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  }
  const { lastContentTab } = await chrome.storage.session.get(["lastContentTab"]);
  if (lastContentTab && lastContentTab.id != null) {
    try {
      const t = await chrome.tabs.get(lastContentTab.id);
      if (t && /^https?:\/\//i.test(t.url || "")) return t;
    } catch (_) { /* tab was closed — fall through */ }
  }
  // Fallback: newest-accessed real web page that isn't this workspace tab.
  let myId = null;
  try { const cur = await chrome.tabs.getCurrent(); myId = cur ? cur.id : null; } catch (_) {}
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  const cands = tabs.filter(t => t.id !== myId);
  cands.sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
  return cands[0] || null;
}


/* pageExtract is defined in extract.js — loaded before this script by popup.html
   and imported by background.js via importScripts. Available as a global here. */


/* Return the first matching auto-extract URL pattern for `url`, or null.
   Pattern rules (one per line in settings):
     - No protocol/path  → domain match: hostname must equal pattern or be a subdomain of it
       e.g. "company.splunk.com" matches "company.splunk.com" and "en.company.splunk.com"
     - Leading "*."      → explicit subdomain wildcard (same as above without the root)
     - Contains "://"    → URL prefix match: current URL must start with the pattern
     - Bare IP address   → exact hostname match                                          */
function matchAutoExtractUrl(url) {
  if (!url || !autoExtractUrls.length) return null;
  try {
    const urlObj  = new URL(url);
    const host    = urlObj.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();
    for (const raw of autoExtractUrls) {
      const p = String(raw).trim();
      if (!p || p.startsWith("#")) continue;           // skip blank + comment lines
      const pl = p.toLowerCase();
      if (pl.includes("://")) {
        // URL prefix match
        if (fullUrl.startsWith(pl)) return p;
      } else {
        // Domain match (strip leading "*." if present)
        const domain = pl.startsWith("*.") ? pl.slice(2) : pl;
        if (host === domain || host.endsWith("." + domain)) return p;
      }
    }
  } catch (_) {}
  return null;
}

/* Core extraction routine, shared by the Extract button and auto-extract.
   opts.auto = true  → silent, non-destructive: bail out (without touching the
   restored results) on any non-SOC / non-scriptable page, so opening the popup
   on a random tab can never wipe what the analyst already captured. */
async function runExtraction(opts = {}) {
  const auto = !!opts.auto;
  if (!chrome.scripting || !chrome.scripting.executeScript) {
    if (auto) return;
    const mf = (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getManifest) ? chrome.runtime.getManifest() : {};
    const perms = (mf.permissions || []).join(",");
    const v = mf.version || "?";
    const has = {
      chrome:    typeof chrome,
      runtime:   typeof chrome.runtime,
      tabs:      typeof chrome.tabs,
      scripting: typeof chrome.scripting,
      storage:   typeof chrome.storage
    };
    console.warn("[IOC] missing scripting api. manifest v", v, "perms:", perms, "apis:", has);
    statusEl.textContent = `chrome.scripting unavailable. Manifest v${v} perms=[${perms}]. See console.`;
    return;
  }
  if (!auto) statusEl.textContent = "Extracting...";
  try {
    const tab = await getTargetTab();
    if (!tab) {
      if (auto) return;
      statusEl.textContent = IS_TAB_VIEW
        ? "No web page yet — open/click your Splunk or Defender tab once, then come back and Extract."
        : "No active tab to extract from.";
      return;
    }
    const url = tab.url || "";
    const host = (() => { try { return new URL(url).hostname; } catch (e) { return ""; } })();
    const blocked = await isExcludedDomain(host);
    if (blocked) {
      if (auto) return;
      statusEl.textContent = `Skipped — ${blocked} is on the non-collectable list.`;
      return;
    }

    // Content scripts can't run on chrome://, edge://, the Web Store, or
    // view-source: pages — Chrome blocks scripting entirely. Tell the user
    // up front instead of silently failing.
    if (/^(chrome|edge|about|view-source|chrome-extension):/i.test(url) ||
        /^https:\/\/chrome\.google\.com\/webstore/i.test(url) ||
        /^https:\/\/chromewebstore\.google\.com/i.test(url)) {
      if (auto) return;
      statusEl.textContent = "Chrome blocks extraction on this page (chrome:// / store / etc).";
      return;
    }

    const r = await extractFromTab(tab.id);
    if (!r.ok) {
      if (auto) return;
      if (/Cannot access|cannot be scripted|chrome:\/\/|web store/i.test(r.error || "")) {
        statusEl.textContent = "Chrome blocks scripting on this page.";
      } else {
        statusEl.textContent = `Failed: ${r.error || "no response"}`;
      }
      return;
    }
    const response = r.result;
    if (typeof response.text !== "string") {
      if (auto) return;
      statusEl.textContent = "Page returned no text. See console.";
      return;
    }
    const typed = response.typed || {};
    const diag = response.diag || {};
    const typedKeys = Object.keys(typed);
    const site       = diag.splunk ? "Splunk" : diag.defender ? "Defender" : null;
    const customSite = !site ? matchAutoExtractUrl(url) : null; // user-defined match
    const procN      = Array.isArray(response.procs) ? response.procs.length : 0;
    // Auto-extract only adopts results on a recognised SOC page or a user-defined
    // auto-extract URL. On anything else leave the existing results untouched.
    if (auto && !site && !customSite) return;

    processIOCs(response.text, url, typed, response.procs || []);
    const siteTag  = site ? ` · ${site}` : customSite ? ` · ${customSite}` : "";
    const procTag  = procN ? ` · ${procN} process${procN === 1 ? "" : "es"}` : "";
    const autoTag  = auto ? "Auto · " : "";
    if (typedKeys.length) {
      statusEl.textContent = `${autoTag}Done${siteTag} · ${typedKeys.length} typed (${typedKeys.join(",")})${procTag}`;
    } else if (procN) {
      // No typed IOCs, but processes were captured — that's the win on alert
      // pages, so report it instead of the misleading "no typed fields".
      statusEl.textContent = `${autoTag}Done${siteTag}${procTag} · no typed IOCs`;
    } else if (site) {
      const extra = diag.splunk
        ? ` (stat=${diag.statTables||0}, evt=${diag.eventTables||0})`
        : ` (cells=${diag.defCells||0})`;
      statusEl.textContent = `${site} page but no typed fields${extra}. See console.`;
    } else {
      statusEl.textContent = `Done${siteTag}`;
    }
  } catch (err) {
    console.error(err);
    if (!auto) statusEl.textContent = "❌ Error";
  }
}

document.getElementById("extract").addEventListener("click", () => runExtraction());

/* Is this hostname on the analyst's non-collectable list? Returns the matched
   pattern (string) if blocked, else "". Matches host or any subdomain. */
function isExcludedDomain(host) {
  return new Promise(resolve => {
    if (!host) return resolve("");
    chrome.storage.local.get(["excludedDomains"], (d) => {
      const list = d.excludedDomains || DEFAULT_EXCLUDED;
      const h = host.toLowerCase();
      const hit = list.find(dom => {
        dom = String(dom).toLowerCase().trim();
        return dom && (h === dom || h.endsWith("." + dom));
      });
      resolve(hit || "");
    });
  });
}
const DEFAULT_EXCLUDED = ["virustotal.com", "abuseipdb.com", "urlscan.io", "shodan.io"];

/* Paste-to-extract: run the full pipeline on arbitrary pasted text.
   Works for Ctrl+A/Ctrl+C of any page, or OCR'd text from Copilot/Snipping Tool. */
document.getElementById("extract-paste").addEventListener("click", () => {
  const txt = document.getElementById("paste-in").value || "";
  if (!txt.trim()) { statusEl.textContent = "Paste text first."; return; }
  processIOCs(txt, "(pasted text)", {});
  statusEl.textContent = "Done";
});

document.getElementById("paste-clear").addEventListener("click", () => {
  document.getElementById("paste-in").value = "";
  statusEl.textContent = "";
  // Also clear displayed + persisted results (full reset)
  state.raw = {}; state.rendered = {}; state.encoded = []; state.enrichResults = []; state.procs = [];
  document.getElementById("output").innerHTML = "";
  renderProcs();
  updateCopyAllEnriched();
  chrome.storage.local.remove("lastExtraction");
});

sanitizeEl.addEventListener("change",  () => { recomputeRendered(); renderIOCs(); saveLiveState(); });
defangEl.addEventListener("change",    () => { recomputeRendered(); renderIOCs(); saveLiveState(); });
if (redactEl) redactEl.addEventListener("change", () => { recomputeRendered(); renderIOCs(); saveLiveState(); });
/* Numbered/Quote/Separator only affect formatted output (the All IOCs pane
   + Copy buttons), not raw per-category textareas. Force-refresh the pane
   so the visible text changes immediately. */
function refreshFormatting() {
  renderIOCs();
  if (allPaneDirty && allPaneBaseValues !== null) {
    // Pane has custom text — reformat it in-place using current toggles
    try {
      const formatted = applyOutputFormat(allPaneBaseValues);
      if (allPaneEl) allPaneEl.value = formatted.join(getSeparator());
    } catch (_) {}
  } else {
    try { allPaneDirty = false; syncAllPane(); } catch (_) {}
  }
  saveLiveState();
}
separatorEl.addEventListener("change", refreshFormatting);
numberEl.addEventListener("change",    refreshFormatting);
// Quotes are mutually exclusive — checking one unchecks the other
quotedEl.addEventListener("change", () => {
  if (singleQuotedEl && quotedEl.checked) singleQuotedEl.checked = false;
  refreshFormatting();
});
singleQuotedEl.addEventListener("change", () => {
  if (quotedEl && singleQuotedEl.checked) quotedEl.checked = false;
  refreshFormatting();
});
wildcardPreEl.addEventListener("change", refreshFormatting);
wildcardSufEl.addEventListener("change", refreshFormatting);

function refangText(text) {
  return text
    .replace(/\s*\[\s*\.\s*\]\s*/g, ".")
    .replace(/\s*\(\s*\.\s*\)\s*/g, ".")
    .replace(/\s*\[\s*@\s*\]\s*/g, "@")
    .replace(/\s*\[\s*:\s*\/\s*\/\s*\]\s*/g, "://")
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\bfxxp\b/gi, "ftp");
}

function sanitizeValue(v) {
  if (!v) return v;
  let s = String(v).trim();
  s = s.replace(/^[<\(\[\{'"`]+/, "");
  s = s.replace(/[>\)\]\}'"`]+$/, "");
  s = s.replace(/[.,;:]+$/g, "");
  s = s.replace(/\)+$/g, "");
  s = s.replace(/\]+$/g, "");
  s = s.replace(/>+$/g, "");
  return s.trim();
}

function defangValue(v) {
  if (!v) return v;
  let s = String(v);
  s = s.replace(/\bhttps\b/gi, "hxxps");
  s = s.replace(/\bhttp\b/gi, "hxxp");
  s = s.replace(/\bftp\b/gi, "fxxp");
  s = s.replace(/:\/\//g, "[://]");
  s = s.replace(/@/g, "[@]");
  s = s.replace(/\./g, "[.]");
  return s;
}

const IP = "(\\d{1,3}(?:\\.\\d{1,3}){3})";
const SRC_RE  = new RegExp("\\b(?:src|source|sender)(?:[\\s_\\-]*(?:ip|addr|address))?\\s*[:=]?\\s*" + IP + "\\b", "gi");
const DEST_RE = new RegExp("\\b(?:dst|dest|destination|target)(?:[\\s_\\-]*(?:ip|addr|address))?\\s*[:=]?\\s*" + IP + "\\b", "gi");
const HOST_RE = /\b(?:hostname|host|computer(?:[\s_\-]?name)?|machine(?:[\s_\-]?name)?|device(?:[\s_\-]?name)?|workstation|dnshostname)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._\-]{1,62})/gi;

/* IPv6 — covers all RFC 5952 forms: full 8-group, compressed (::),
   loopback (::1), and mixed IPv4-tail. Applied to free-text extraction;
   typed DOM values are already funnelled into the `ips` bucket by pageExtract. */
const IPV6_RE = new RegExp(
  "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}" +              // full
  "|(?:[0-9a-fA-F]{1,4}:){1,7}:" +                            // ends ::
  "|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}" +           // 6+1
  "|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}" +  // 5+2
  "|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}" +  // 4+3
  "|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}" +  // 3+4
  "|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}" +  // 2+5
  "|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}" +           // 1+6
  "|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}" +          // ::+groups
  "|::(?:[fF]{4}(?::0{1,4})?:)?" +                             // IPv4-mapped prefix
    "(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])" +
    "(?:\\.(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])){3}" +
  "|(?:[0-9a-fA-F]{1,4}:){1,4}:" +                            // IPv4-mapped middle
    "(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])" +
    "(?:\\.(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])){3}",
  "g"
);

/* ---------------------------
   Encoded-command extraction
   Catches base64 blobs three ways:
   1) PowerShell:  -enc / -e / -EncodedCommand <blob>   (blob is UTF-16LE base64)
   2) Linux:       base64 -d / --decode  ... "<blob>"   or  echo <blob> | base64 -d
   3) Standalone:  any long base64 blob ending in '==' (or '=')
   A blob must be reasonably long (>= 20 b64 chars) to avoid false hits.
   --------------------------- */
const B64 = "([A-Za-z0-9+/=]{20,})";
// PowerShell -enc style. Group 1 = blob. Quotes optional.
const PS_ENC_RE = new RegExp("(?:-e(?:nc)?(?:odedcommand)?)\\s+['\"]?" + B64 + "['\"]?", "gi");
// Linux base64 decode pipelines. Blob may appear before OR after the base64 -d call.
const LNX_ENC_RE = new RegExp(
  "(?:echo\\s+['\"]?" + B64 + "['\"]?\\s*\\|\\s*base64\\s+(?:-d|--decode))" +   // echo BLOB | base64 -d
  "|(?:base64\\s+(?:-d|--decode)\\s*<<<\\s*['\"]?" + B64 + "['\"]?)",          // base64 -d <<< BLOB
  "gi"
);
// Standalone padded blobs (must end in = or ==). Lookbehind/ahead avoid grabbing
// mid-token; trailing boundary is "not a base64 char" rather than \b (which fails next to '=').
const STANDALONE_B64_RE = /(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{20,}={1,2})(?![A-Za-z0-9+/=])/g;

/* Heuristic: is a decoded string mostly readable text? */
function isMostlyPrintable(s) {
  if (!s) return false;
  let ok = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  }
  return ok / s.length > 0.85;
}

/* Strip embedded U+0000 / "\0" from decoded output. PowerShell -enc payloads
   are UTF-16LE so a byte-level decode of them ends up with a \0 between every
   ASCII char; if our UTF-16 heuristic falls back to UTF-8 we still want to
   show readable text, not Cmd[\0]l[\0]i[\0]ne. */
function stripNullBytes(s) {
  return String(s || "").replace(/\0/g, "");
}

/* Decode a base64 blob, trying UTF-16LE first (PowerShell -enc emits this:
   every other byte is 0x00), then falling back to UTF-8. Returns "" on failure. */
function decodeB64Smart(blob, preferUtf16) {
  let bin;
  try {
    let t = blob.replace(/-/g, "+").replace(/_/g, "/");
    while (t.length % 4) t += "=";
    bin = atob(t);
  } catch (_) { return ""; }

  const tryUtf16 = () => {
    // Treat as UTF-16LE: take low byte of every pair, expect high bytes ~0
    if (bin.length < 2) return "";
    let out = "", nulls = 0;
    for (let i = 0; i + 1 < bin.length; i += 2) {
      const lo = bin.charCodeAt(i), hi = bin.charCodeAt(i + 1);
      if (hi === 0) nulls++;
      out += String.fromCharCode(lo | (hi << 8));
    }
    // Only accept if it really looked like UTF-16LE (mostly null high bytes)
    return nulls / (bin.length / 2) > 0.7 ? out : "";
  };
  const tryUtf8 = () => {
    try { return decodeURIComponent(escape(bin)); } catch (_) { return bin; }
  };

  let decoded = preferUtf16 ? (tryUtf16() || tryUtf8()) : (tryUtf8() || tryUtf16());
  if (!isMostlyPrintable(decoded)) decoded = preferUtf16 ? tryUtf8() : decoded;
  return stripNullBytes(decoded);
}

/* Pull all base64 blobs from the page with their source/context. Returns
   array of { blob, decoded, src } so render can show blob + decode together. */
function extractEncoded(text) {
  const found = new Map(); // blob -> {decoded, src}

  const add = (blob, src, preferUtf16) => {
    if (!blob || found.has(blob)) return;
    const decoded = decodeB64Smart(blob, preferUtf16);
    found.set(blob, { decoded, src });
  };

  let m;
  PS_ENC_RE.lastIndex = 0;
  while ((m = PS_ENC_RE.exec(text)) !== null) add(m[1], "powershell -enc", true);

  LNX_ENC_RE.lastIndex = 0;
  while ((m = LNX_ENC_RE.exec(text)) !== null) add(m[1] || m[2], "linux base64 -d", false);

  STANDALONE_B64_RE.lastIndex = 0;
  while ((m = STANDALONE_B64_RE.exec(text)) !== null) add(m[1], "standalone (==)", false);

  return [...found.entries()].map(([blob, info]) => ({ blob, ...info }));
}

function extractByRegex(re, text) {
  const out = new Set();
  let m;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) out.add(m[1]);
  return [...out];
}

/* Pull "Subject: ..." lines out of free text. Email-thread quotes, headers, etc.
   Stops at end-of-line; trims trailing punctuation/quotes. */
const SUBJECT_RE = /^\s*Subject\s*:\s*(.+?)\s*$/gim;

/* User-Agent extractor.
   Two shapes covered:
   1. Browser UAs starting with Mozilla/N.N (...) optionally followed by
      <token>/<version> [(...)] groups (Safari, Firefox, Chrome, Edge, etc.).
   2. Short-form tool UAs: curl/, Wget/, python-requests/, axios/, okhttp/,
      Java/, PostmanRuntime/, HTTPie/, Nikto/, sqlmap/, nmap/, libwww-perl/,
      Go-http-client/, node-fetch/, undici/, GuzzleHttp/, etc.
   We boundary-anchor with \b on the prefix and stop on quotes / angle brackets
   / newlines so we don't run into surrounding markup. */
const UA_BROWSER_RE = /\bMozilla\/[\d.]+\s*\([^)\n]{0,200}\)(?:\s+[\w.\-]+\/[\d.\-]+(?:\s+\([^)\n]{0,200}\))?){0,8}/g;
const UA_TOOL_RE    = /\b(?:curl|Wget|python-requests|Python-urllib|aiohttp|Go-http-client|axios|okhttp|Java|node-fetch|undici|GuzzleHttp|PostmanRuntime|HTTPie|libwww-perl|Nikto|sqlmap|nmap|fasthttp|Scrapy|Apache-HttpClient|Faraday|MSWinHTTP|WinHTTP|WindowsPowerShell|PowerShell|Mediapartners-Google|Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot)\/[\w.\-]+/gi;
function extractUserAgents(text) {
  const out = new Set();
  let m;
  UA_BROWSER_RE.lastIndex = 0;
  while ((m = UA_BROWSER_RE.exec(text)) !== null) out.add(m[0].trim());
  UA_TOOL_RE.lastIndex = 0;
  while ((m = UA_TOOL_RE.exec(text)) !== null) out.add(m[0].trim());
  return [...out];
}

function processIOCs(pageText, sourceUrl, typed, procs) {
  typed = typed || {};
  procs = Array.isArray(procs) ? procs : [];
  lastExtractedUrl = sourceUrl || "";   // remember which page these results came from
  const text = refangText(pageText);
  const clean = arr => [...new Set((arr || []).map(sanitizeValue))].filter(Boolean);

  // Rich encoded-command data (blob + decoded + source); kept separate so the
  // sanitize/defang pipeline doesn't touch the decoded text.
  const prevEncoded = state.encoded || [];        // for append-mode merge
  state.encoded = extractEncoded(pageText); // use ORIGINAL text, not refanged

  // File paths from ORIGINAL text (backslashes/structure must stay intact)
  const paths = extractPaths(pageText);
  // Filenames pulled out of those paths (so C:\...\evil.exe also feeds FILES)
  const pathFiles = paths.map(fileNameFromPath).filter(Boolean);

  const subjects = clean(extractByRegex(SUBJECT_RE, text));

  const extracted = {
    src_ip:  clean(extractByRegex(SRC_RE, text)),
    dest_ip: clean(extractByRegex(DEST_RE, text)),
    ips:     clean([...(text.match(/\b\d{1,3}(\.\d{1,3}){3}\b/g) || []),
                   ...(text.match(new RegExp(IPV6_RE.source, "g")) || [])]),
    domains:   clean(filterDomains(text.match(/\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g))),
    urls:      clean(text.match(/https?:\/\/[^\s"'<>]+/g)),
    emails:    clean(text.match(/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g)),
    email_subjects: subjects,
    hostnames: clean(extractByRegex(HOST_RE, text)),
    paths:     [...new Set(paths)],
    // FILES = standalone filenames + filenames extracted from paths
    files:     [...new Set([...clean(text.match(FILE_RE)), ...pathFiles])],
    md5:    clean(text.match(/\b[a-fA-F0-9]{32}\b/g)),
    sha1:   clean(text.match(/\b[a-fA-F0-9]{40}\b/g)),
    sha256: clean(text.match(/\b[a-fA-F0-9]{64}\b/g)),
    cves:   clean(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi)),
    // UAs are extracted from the ORIGINAL text (not refanged) — refangText
    // would mangle "Mozilla/5.0[.]X11[.]Linux..." for example.
    user_agents: [...new Set(extractUserAgents(pageText))],
    // Just the blob strings, so Copy/OR/AND/IN/Defender work like any category
    encoded: [...new Set(state.encoded.map(e => e.blob))]
  };

  // Site-aware (typed) values from content.js take priority for these
  // categories, because the page has already parsed the field for us — no
  // regex guess can beat a labelled DOM value. We MERGE rather than replace so
  // anything regex picked up that the DOM missed still shows up.
  if (typed && typeof typed === "object") {
    for (const cat of Object.keys(typed)) {
      const dom = (typed[cat] || []).map(sanitizeValue).filter(Boolean);
      if (!dom.length) continue;
      extracted[cat] = [...new Set([...dom, ...(extracted[cat] || [])])];
    }
    // Any IP already typed as src_ip / dest_ip shouldn't double-list under the
    // generic `ips` bucket — the typed bucket is more specific and useful.
    const typedIps = new Set([...(typed.src_ip || []), ...(typed.dest_ip || [])].map(sanitizeValue));
    if (typedIps.size && Array.isArray(extracted.ips)) {
      extracted.ips = extracted.ips.filter(ip => !typedIps.has(ip));
    }
  }

  const appendEl = document.getElementById("append-mode");
  const procKey = (p) => [p.name, p.pid, p.cmd, p.pname, p.ppid].join("|");
  if (appendEl && appendEl.checked && state.raw && Object.keys(state.raw).length) {
    // Merge into existing results (dedup per category)
    const merged = {};
    const keys = new Set([...Object.keys(state.raw), ...Object.keys(extracted)]);
    for (const k of keys) {
      merged[k] = [...new Set([...(state.raw[k] || []), ...(extracted[k] || [])])];
    }
    state.raw = merged;
    // also merge encoded rich data (dedup by blob)
    const seen = new Set((prevEncoded || []).map(e => e.blob));
    state.encoded = [...prevEncoded, ...state.encoded.filter(e => !seen.has(e.blob))];
    // merge process records (dedup by name|pid|cmd|parent)
    const seenProc = new Set((state.procs || []).map(procKey));
    state.procs = [...(state.procs || []), ...procs.filter(p => !seenProc.has(procKey(p)))];
  } else {
    state.raw = extracted;
    state.procs = procs;
  }

  recomputeRendered();
  lastExtractWasFresh = true; // tells renderIOCs to ignore previously-open sections
  renderIOCs();
  renderProcs();
  if (!(appendEl && appendEl.checked)) {
    state.enrichResults = [];   // fresh extraction → previous enrichment is stale
    updateCopyAllEnriched();
  }
  saveToHistory(state.raw, sourceUrl);
  saveLastExtraction();
}

/* Persist the current extraction so closing/reopening the popup doesn't lose it.
   We store raw (string lists) + encoded (rich blob data); rendered is rederived. */
function saveLastExtraction() {
  try {
    const ts = Date.now();
    lastOwnSaveTs = ts;
    chrome.storage.local.set({
      lastExtraction: { raw: state.raw, encoded: state.encoded, procs: state.procs, url: lastExtractedUrl, ts }
    });
  } catch (_) { /* storage full or unavailable — non-fatal */ }
}

/* Restore the last extraction on popup open, if any. onDone (optional) always
   runs after the restore settles — auto-extract chains off it so it can compare
   the current tab against the URL these restored results came from. */
function restoreLastExtraction(onDone) {
  chrome.storage.local.get("lastExtraction", ({ lastExtraction }) => {
    if (!lastExtraction || !lastExtraction.raw) { if (onDone) onDone(); return; }
    try {
      state.raw = (lastExtraction.raw && typeof lastExtraction.raw === "object") ? lastExtraction.raw : {};
      state.encoded = Array.isArray(lastExtraction.encoded)
        ? lastExtraction.encoded.filter(e => e && e.blob)
        : [];
      state.procs = Array.isArray(lastExtraction.procs) ? lastExtraction.procs : [];
      lastExtractedUrl = typeof lastExtraction.url === "string" ? lastExtraction.url : "";
      recomputeRendered();
      renderIOCs();
      renderProcs();
      if (statusEl && !statusEl.textContent) {
        const when = lastExtraction.ts ? new Date(lastExtraction.ts).toLocaleTimeString() : "";
        statusEl.textContent = "Restored" + (when ? " (" + when + ")" : "");
      }
    } catch (err) {
      // Corrupt saved state — clear it so it can't break the popup again
      console.error("restore failed:", err);
      chrome.storage.local.remove("lastExtraction");
      state.raw = {}; state.rendered = {}; state.encoded = []; state.enrichResults = []; state.procs = [];
    }
    if (onDone) onDone();
  });
}

/* Auto-extract: when enabled, re-run extraction as soon as the popup opens so the
   analyst lands on a populated workspace. Only fires when the current tab is a
   *different* page than the one the restored results came from (so reopening on
   the same page keeps any append-accumulated work), and runExtraction({auto})
   itself bails out harmlessly on non-SOC / non-scriptable pages. */
async function maybeAutoExtract() {
  if (!autoExtract) return;
  try {
    const tab = await getTargetTab();
    const url = tab && tab.url ? tab.url : "";
    if (!url) return;
    if (lastExtractedUrl && url === lastExtractedUrl) return; // same page already loaded
    await runExtraction({ auto: true });
  } catch (_) { /* never let auto-extract break popup open */ }
}

/* Process a background extraction that arrived while the popup was closed.
   Called on popup open (after restoreLastExtraction) so any Ctrl+E the analyst
   pressed while the popup was gone is not lost.  Only adopts the result if it is
   strictly newer than whatever was restored from lastExtraction. */
function checkBgExtractPending(onDone) {
  chrome.storage.local.get(["bgExtractPending", "lastExtraction"], (data) => {
    const p    = data.bgExtractPending;
    const last = data.lastExtraction;
    if (!p || typeof p.text !== "string") { if (onDone) onDone(); return; }
    const lastTs = (last && last.ts) ? last.ts : 0;
    if (p.ts > lastTs) {
      try {
        processIOCs(p.text, p.url || "", p.typed || {}, p.procs || []);
        if (statusEl) {
          const site = p.diag && p.diag.splunk ? " · Splunk"
                     : p.diag && p.diag.defender ? " · Defender" : "";
          const when = p.ts ? new Date(p.ts).toLocaleTimeString() : "";
          statusEl.textContent = "Extracted" + (when ? " (" + when + ")" : "") + site;
        }
      } catch (err) { console.error("[IOC] checkBgExtractPending failed:", err); }
    }
    chrome.storage.local.remove("bgExtractPending");
    if (onDone) onDone();
  });
}

function recomputeRendered() {
  const doSanitize = sanitizeEl.checked;
  const doDefang   = defangEl.checked;
  const doRedact   = !!(redactEl && redactEl.checked);
  const rendered = {};
  for (const type of Object.keys(state.raw || {})) {
    // Base64 blobs must stay byte-exact (sanitize/defang would corrupt them).
    // Paths skip sanitize/defang for the same reason, but redaction still
    // applies — analyst may need to hide a hostname or username inside a path.
    if (type === "encoded") {
      rendered[type] = [...(state.raw[type] || [])];
      continue;
    }
    // Paths AND user-agents bypass sanitize/defang — sanitize would chew the
    // trailing ")" off "Mozilla/... (Win64; x64)" and defang would replace
    // every "." with "[.]", destroying the value.
    if (type === "paths" || type === "user_agents") {
      const vals = (state.raw[type] || []).map(v => doRedact ? applyRedaction(String(v)) : String(v));
      rendered[type] = [...new Set(vals)].filter(Boolean);
      continue;
    }
    const vals = (state.raw[type] || []).map(v => {
      let x = String(v);
      if (doSanitize) x = sanitizeValue(x);
      if (doDefang)   x = defangValue(x);
      if (doRedact)   x = applyRedaction(x);
      return x;
    });
    rendered[type] = [...new Set(vals)].filter(Boolean);
  }
  state.rendered = rendered;
}

function getSeparator() {
  switch (separatorEl.value) {
    case "comma": return ", ";
    case "space": return " ";
    default:      return "\n";
  }
}
/* Apply Numbered + Quote-each formatting. Returns an array of formatted lines.
   Separator is NOT applied here — that's only used when joining for clipboard
   or for the All IOCs pane. Per-category textareas always use newlines so
   each line can be edited as its own value. */
function formatListLines(values) {
  let items = values;
  const pre = wildcardPreEl && wildcardPreEl.checked;
  const suf = wildcardSufEl && wildcardSufEl.checked;
  if (pre || suf) items = items.map(v => `${pre ? "*" : ""}${v}${suf ? "*" : ""}`);
  if (singleQuotedEl && singleQuotedEl.checked) items = items.map(v => `'${v}'`);
  else if (quotedEl && quotedEl.checked)         items = items.map(v => `"${v}"`);
  if (numberEl && numberEl.checked) items = items.map((v, i) => `${i + 1}. ${v}`);
  return items;
}
function formatList(values) {
  return formatListLines(values).join(getSeparator());
}

/* Strip number prefix ("1. ", "2) ") and surrounding "..." or '...' from a
   single token. Used to parse a textarea back to raw values regardless of
   which separator/formatter the analyst was looking at. */
function parseFormattedLine(line) {
  let x = String(line).trim();
  x = x.replace(/^\d+[.)\]]\s+/, "");
  if (x.length >= 2 && ((x.startsWith('"') && x.endsWith('"')) || (x.startsWith("'") && x.endsWith("'")))) {
    x = x.slice(1, -1);
  }
  return x;
}

/* Parse whatever's in a textarea (newline / comma / space-separated) into
   raw values. Picks the split character that's actually present so the
   separator dropdown doesn't break editing. */
function parseTextareaList(s) {
  let parts;
  if (/\r?\n/.test(s))      parts = s.split(/\r?\n/);
  else if (/,/.test(s))     parts = s.split(",");
  else if (/;/.test(s))     parts = s.split(";");
  else                      parts = s.split(/\s+/);
  return parts.map(parseFormattedLine).filter(Boolean);
}

/* ---------- render extract output ---------- */
function renderIOCs() {
  const output = document.getElementById("output");

  // Remember which sections were expanded so a toggle re-render doesn't
  // collapse them. On a new extract we skip this — analysts want a clean
  // collapsed view rather than the previous open state.
  const wasOpen = new Set();
  if (!lastExtractWasFresh) {
    // Current DOM (same session re-render)
    output.querySelectorAll("details.ioc-section[open]").forEach(d => {
      const t = d.querySelector("[data-type]");
      if (t && t.dataset && t.dataset.type) wasOpen.add(t.dataset.type);
    });
    // Restored from liveState after popup was closed and reopened
    if (savedOpenSections) { savedOpenSections.forEach(t => wasOpen.add(t)); savedOpenSections = null; }
  }
  lastExtractWasFresh = false;

  output.innerHTML = "";

  const rendered = state.rendered || {};
  const types = Object.keys(rendered).filter(t => !hiddenCats[t]);

  if (!types.length || types.every(t => (rendered[t] || []).length === 0)) {
    output.innerHTML = `<div class="hint" style="margin-top:10px;">
      No IOCs found on this page (or page blocks text extraction).</div>`;
    return;
  }

  for (const type of types) {
    const values = rendered[type];
    if (!values || values.length === 0) continue;

    const title = TITLES[type] || type.toUpperCase();
    // Saved setting beats hardcoded default; analyst's per-session override beats both.
    const savedField = (iocFieldSettings[type] && iocFieldSettings[type].field) ? iocFieldSettings[type].field : "";
    const defaultField = savedField || FIELD_DEFAULTS[type] || "";
    const fieldVal = (type in state.fieldOverrides) ? state.fieldOverrides[type] : defaultField;

    // ENCODED category renders blob + decoded command + source, not a flat list
    if (type === "encoded") {
      const rows = (state.encoded || []).filter(e => e && e.blob).map(e => {
        const dec = e.decoded ? escapeHtml(e.decoded) : "<em>(could not decode)</em>";
        return `<div class="enc-item">
          <div class="enc-src">${escapeHtml(e.src || "")}</div>
          <div class="enc-blob">${escapeHtml(e.blob || "")}</div>
          <div class="enc-arrow">↓ decoded</div>
          <pre class="enc-dec">${dec}</pre>
        </div>`;
      }).join("");

      const det = document.createElement("details");
      det.className = "ioc-section";
      if (wasOpen.has(type)) det.open = true;
      det.innerHTML = `
        <summary>
          <span class="ioc-section-title">${title} (${values.length})</span>
          <button class="copy summary-btn" data-type="${type}">Copy blobs</button>
          <button class="copy-decoded summary-btn" data-type="${type}">Copy decoded</button>
        </summary>
        <div class="ioc-section-body">
          <label style="font-size:12px;">Field:</label>
          <input class="field-input" type="text" list="fieldlist"
                 data-type="${type}" data-default="${defaultField}" value="${fieldVal}"
                 placeholder="custom field" />
          <div style="margin-top:6px;">
            <button class="or"       data-type="${type}">OR</button>
            <button class="and"      data-type="${type}">AND</button>
            <button class="in"       data-type="${type}">IN</button>
            <button class="defender" data-type="${type}">Defender</button>
          </div>
          <div class="enc-list">${rows}</div>
        </div>
      `;
      output.appendChild(det);
      continue;
    }

    const det = document.createElement("details");
    det.className = "ioc-section";
    if (wasOpen.has(type)) det.open = true;
    // Body rows scale with list size, capped so a huge category doesn't blow up the popup.
    const rows = Math.max(3, Math.min(12, values.length));
    det.innerHTML = `
      <summary>
        <span class="ioc-section-title">${title} (${values.length})</span>
        <button class="copy summary-btn" data-type="${type}">Copy</button>
      </summary>
      <div class="ioc-section-body">
        <label style="font-size:12px;">Field:</label>
        <input class="field-input" type="text" list="fieldlist"
               data-type="${type}" data-default="${defaultField}" value="${fieldVal}"
               placeholder="custom field" />
        <div style="margin-top:6px;">
          <button class="or"       data-type="${type}">OR</button>
          <button class="and"      data-type="${type}">AND</button>
          <button class="in"       data-type="${type}">IN</button>
          <button class="defender" data-type="${type}">Defender</button>
          <button class="pivot-toggle" data-type="${type}">Pivot / Enrich</button>
        </div>
        <textarea class="ioc-pane" data-type="${type}" rows="${rows}" spellcheck="false">${escapeHtml(formatListLines(values).join(getSeparator()))}</textarea>
        <div class="pivot-panel" data-type="${type}"></div>
      </div>
    `;
    output.appendChild(det);
  }

  attachEvents();
  // Keep clicks on summary buttons from toggling the section open/closed
  document.querySelectorAll("#output details.ioc-section .summary-btn").forEach(b => {
    b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); });
  });
  try { syncAllPane(); } catch (e) { /* defined later in file; safe to ignore on first paint */ }
}

function attachEvents() {
  document.querySelectorAll(".field-input").forEach(inp => {
    inp.addEventListener("input", () => { state.fieldOverrides[inp.dataset.type] = inp.value; });
  });

  // Per-category textarea: user can add/remove/edit lines freely. We treat
  // the textarea as the authoritative list for that category — debounce
  // writes back to state.raw, then recompute (but DON'T re-render this
  // textarea while focused, to preserve cursor position).
  document.querySelectorAll("textarea.ioc-pane").forEach(ta => {
    let timer = null;
    const persist = () => {
      const type = ta.dataset.type;
      // Parse handles whichever separator was used (newline, comma, space, ;),
      // plus number prefixes and surrounding quotes.
      const lines = parseTextareaList(ta.value);
      state.raw[type] = [...new Set(lines)];
      // Keep state.encoded blob list in sync if user edits the ENCODED textarea
      // (not used for encoded today — encoded keeps its rich blob view — but
      // future-proof in case we collapse encoded into the same pane).
      recomputeRendered();
      saveLastExtraction();
      // Refresh the "All IOCs" pane at the bottom + the header counts.
      try { syncAllPane(); } catch (e) {}
      // Update the "(N)" count in the h3 without nuking this textarea
      const h3 = ta.parentElement && ta.parentElement.querySelector("h3");
      if (h3) {
        const title = TITLES[type] || type.toUpperCase();
        h3.textContent = `${title} (${(state.rendered[type] || []).length})`;
      }
    };
    ta.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(persist, 350);
    });
    ta.addEventListener("blur", () => {
      clearTimeout(timer);
      persist();
    });
  });

  document.querySelectorAll(".copy").forEach(btn =>
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(formatList(state.rendered[btn.dataset.type] || []));
      flashBtn(btn, "Copied");
    }));
  document.querySelectorAll(".copy-decoded").forEach(btn =>
    btn.addEventListener("click", () => {
      const decoded = (state.encoded || []).map(e => e.decoded).filter(Boolean);
      navigator.clipboard.writeText(decoded.join("\n\n"));
      flashBtn(btn, "Copied");
    }));
  document.querySelectorAll(".or").forEach(btn =>
    btn.addEventListener("click", () => buildQuery(btn.dataset.type, "OR")));
  document.querySelectorAll(".and").forEach(btn =>
    btn.addEventListener("click", () => buildQuery(btn.dataset.type, "AND")));
  document.querySelectorAll(".in").forEach(btn =>
    btn.addEventListener("click", () => buildInQuery(btn.dataset.type)));
  document.querySelectorAll(".defender").forEach(btn =>
    btn.addEventListener("click", () => buildDefenderQuery(btn.dataset.type)));
  document.querySelectorAll(".pivot-toggle").forEach(btn =>
    btn.addEventListener("click", () => togglePivotPanel(btn.dataset.type)));
}

/* ---------- query builders ---------- */
/* Returns the Splunk log-context prefix (e.g. "index=win sourcetype=WinEventLog ") for the
   given IOC type, or "" if neither index nor sourcetype has been configured. */
function iocLogPrefix(type) {
  const s = iocFieldSettings[type];
  if (!s) return "";
  const parts = [];
  if (s.index)      parts.push(`index=${s.index}`);
  if (s.sourcetype) parts.push(`sourcetype=${s.sourcetype}`);
  return parts.length ? parts.join(" ") + " " : "";
}
function fieldFor(type) {
  const input = document.querySelector(`.field-input[data-type="${type}"]`);
  return input ? input.value.trim() : "";
}
/* Build wildcard-wrapped + escapeSpl value, shared by all query builders. */
function buildWv() {
  const pre = wildcardPreEl && wildcardPreEl.checked;
  const suf = wildcardSufEl && wildcardSufEl.checked;
  return v => `${pre ? "*" : ""}${escapeSpl(v)}${suf ? "*" : ""}`;
}
/* Controls that cover a given IOC type (have a non-empty field for it). */
function controlsForType(type) {
  return splunkControls.filter(c => c.fields && c.fields[type]);
}
/* Build a single OR/AND clause for one field+values set. */
function singleClause(field, values, operator, wv) {
  return field
    ? `(${values.map(v => `${field}="${wv(v)}"`).join(` ${operator} `)})`
    : `(${values.map(v => `"${wv(v)}"`).join(` ${operator} `)})`;
}
function buildQuery(type, operator) {
  const values = state.rendered[type] || [];
  if (!values.length) return;
  const wv       = buildWv();
  const controls = controlsForType(type);
  if (controls.length) {
    const blocks = controls.map(c => {
      const parts = [];
      if (c.index)      parts.push(`index=${c.index}`);
      if (c.sourcetype) parts.push(`sourcetype=${c.sourcetype}`);
      const prefix = parts.length ? parts.join(" ") + " " : "";
      return prefix + singleClause(c.fields[type], values, operator, wv);
    });
    navigator.clipboard.writeText(blocks.join("\nOR "));
    alert(`Query copied (${controls.length} control${controls.length > 1 ? "s" : ""})`);
  } else {
    const field = fieldFor(type);
    navigator.clipboard.writeText(iocLogPrefix(type) + singleClause(field, values, operator, wv));
    alert("Query copied");
  }
}
function buildInQuery(type) {
  const values = state.rendered[type] || [];
  if (!values.length) return;
  const wv       = buildWv();
  const controls = controlsForType(type);
  if (controls.length) {
    const blocks = controls.map(c => {
      const field = c.fields[type];
      const parts = [];
      if (c.index)      parts.push(`index=${c.index}`);
      if (c.sourcetype) parts.push(`sourcetype=${c.sourcetype}`);
      const prefix = parts.length ? parts.join(" ") + " " : "";
      return `${prefix}${field} IN (${values.map(v => `"${wv(v)}"`).join(", ")})`;
    });
    navigator.clipboard.writeText(blocks.join("\nOR "));
    alert(`IN query copied (${controls.length} control${controls.length > 1 ? "s" : ""})`);
  } else {
    const field = fieldFor(type);
    if (!field) { alert("IN query needs a field name."); return; }
    navigator.clipboard.writeText(iocLogPrefix(type) + `${field} IN (${values.map(v => `"${wv(v)}"`).join(", ")})`);
    alert("IN query copied");
  }
}
/* Controls that cover a given IOC type (have a non-empty col for it). */
function kqlControlsForType(type) {
  return kqlControls.filter(c => c.fields && c.fields[type] && c.fields[type].col);
}
function buildDefenderQuery(type) {
  const values = state.rendered[type] || [];
  if (!values.length) return;
  const list = values.map(v => `"${escapeSpl(v)}"`).join(", ");

  // Per-session field override (analyst typed into the card's custom field input)
  const input      = document.querySelector(`.field-input[data-type="${type}"]`);
  const typed      = input ? input.value.trim() : "";
  const splDef     = input ? (input.dataset.default || "") : "";
  const colOverride = (typed && typed !== splDef) ? typed : null;

  // Use controls when any cover this IOC type (mirrors Splunk multi-source behaviour)
  const controls = kqlControlsForType(type);
  if (controls.length) {
    const blocks = controls.map(ctrl => {
      const col = colOverride || ctrl.fields[type].col;
      const op  = ctrl.fields[type].op || "in~";
      return `${ctrl.name}\n| where ${col} ${op} (${list})`;
    });
    navigator.clipboard.writeText(blocks.join("\n\n"));
    alert(`Defender query copied (${controls.length} table${controls.length > 1 ? "s" : ""})`);
    return;
  }

  // Fallback: simple kqlSettings / hardcoded KQL defaults
  const base   = KQL[type] || { table: "", col: type, op: "in~" };
  const saved  = kqlSettings[type] || {};
  const table  = ("table" in saved) ? saved.table : base.table;
  const op     = saved.op  || base.op;
  const defCol = saved.col || base.col;
  const col    = colOverride || defCol;
  const filter = `where ${col} ${op} (${list})`;
  navigator.clipboard.writeText(table ? `${table}\n| ${filter}` : `| ${filter}`);
  alert("Defender query copied");
}
function escapeSpl(v) { return String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"'); }
function escapeHtml(v) {
  return String(v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function flashBtn(btn, msg) {
  const old = btn.textContent;
  btn.textContent = msg;
  btn.disabled = true;
  setTimeout(() => { btn.textContent = old; btn.disabled = false; }, 900);
}

/* ============================================================
   PROCESSES & COMMAND LINES (Defender)
   state.procs holds structured records collected inside pageExtract:
     { name,pid,cmd,folder,sha256,account, pname,ppid,pcmd,pfolder,
       gpname,gppid, source }
   Flat view = one block per spawn (child + command line + parent).
   Tree view = parent→child forest with children indented (the "child
   indentation" button the analyst asked for). All text is set via
   textContent — command lines are attacker-controlled and must never be
   interpolated into innerHTML.
   ============================================================ */
let procsTreeView = false;

function procLabel(name, pid) {
  name = (name || "").trim();
  pid  = (pid == null ? "" : String(pid)).trim();
  if (!name && !pid) return "";
  return pid ? `${name || "?"} (PID ${pid})` : (name || "?");
}

/* Build a parent→child forest from the flat records, keyed by name#pid so the
   same instance merges across rows. Returns { roots, nodes }. */
function buildProcForest(records) {
  const nodes = new Map();
  const idOf = (name, pid) => (name || pid) ? `${(name || "").toLowerCase()}#${pid || ""}` : "";
  const ensure = (name, pid) => {
    const id = idOf(name, pid);
    if (!id) return null;
    if (!nodes.has(id)) nodes.set(id, { id, name: name || "", pid: pid || "", cmd: "", parent: null, children: [] });
    return nodes.get(id);
  };
  for (const r of records) {
    const child   = ensure(r.name, r.pid);
    const parent  = (r.pname  || r.ppid)  ? ensure(r.pname,  r.ppid)  : null;
    const gparent = (r.gpname || r.gppid) ? ensure(r.gpname, r.gppid) : null;
    if (child) {
      if (r.cmd && !child.cmd) child.cmd = r.cmd;
      if (parent && child.parent == null && child !== parent) child.parent = parent.id;
    }
    if (parent) {
      if (r.pcmd && !parent.cmd) parent.cmd = r.pcmd;
      if (gparent && parent.parent == null && parent !== gparent) parent.parent = gparent.id;
    }
  }
  const byName = (a, b) => (a.name || "").localeCompare(b.name || "") || (a.pid || "").localeCompare(b.pid || "");
  const roots = [];
  for (const node of nodes.values()) {
    if (node.parent && nodes.has(node.parent) && node.parent !== node.id) {
      nodes.get(node.parent).children.push(node);
    } else {
      roots.push(node);
    }
  }
  roots.sort(byName);
  for (const n of nodes.values()) n.children.sort(byName);
  return { roots, nodes };
}

function renderProcs() {
  const group   = document.getElementById("procs-group");
  const out     = document.getElementById("procs-out");
  const countEl = document.getElementById("procs-count");
  if (!group || !out) return;
  const recs = Array.isArray(state.procs) ? state.procs : [];
  group.hidden = recs.length === 0;
  if (!recs.length) { out.innerHTML = ""; if (countEl) countEl.textContent = ""; return; }
  if (countEl) countEl.textContent = recs.length + (recs.length === 1 ? " process" : " processes");

  const toggleBtn = document.getElementById("procs-tree-toggle");
  if (toggleBtn) toggleBtn.textContent = procsTreeView ? "Flat view" : "Tree view";

  out.innerHTML = "";
  const wrapEl = document.getElementById("procs-wrap");
  out.classList.toggle("procs-wrap", !!(wrapEl && wrapEl.checked));

  const addCmd = (parent, text, extraClass) => {
    const c = document.createElement("div");
    c.className = "proc-cmd" + (extraClass ? " " + extraClass : "");
    c.textContent = text;
    parent.appendChild(c);
  };

  if (procsTreeView) {
    const { roots } = buildProcForest(recs);
    const seen = new Set();
    const renderNode = (node, depth) => {
      if (seen.has(node.id)) return;            // cycle guard
      seen.add(node.id);
      const row = document.createElement("div");
      row.className = "proc-node";
      row.style.paddingLeft = (depth * 18) + "px";
      const nm = document.createElement("div");
      nm.className = "proc-name";
      nm.textContent = (depth ? "↳ " : "") + procLabel(node.name, node.pid);
      row.appendChild(nm);
      if (node.cmd) addCmd(row, node.cmd);
      out.appendChild(row);
      for (const ch of node.children) renderNode(ch, depth + 1);
    };
    for (const r of roots) renderNode(r, 0);
  } else {
    for (const r of recs) {
      const card = document.createElement("div");
      card.className = "proc-card";
      const head = document.createElement("div");
      head.className = "proc-head";
      const nm = document.createElement("span");
      nm.className = "proc-name";
      nm.textContent = procLabel(r.name, r.pid) || "(unnamed process)";
      head.appendChild(nm);
      if (r.source) {
        const tag = document.createElement("span");
        tag.className = "proc-tag";
        tag.textContent = r.source;
        head.appendChild(tag);
      }
      card.appendChild(head);
      if (r.cmd) addCmd(card, r.cmd);
      const parentLbl = procLabel(r.pname, r.ppid);
      if (parentLbl) {
        const par = document.createElement("div");
        par.className = "proc-parent";
        par.textContent = "↳ parent: " + parentLbl;
        card.appendChild(par);
        if (r.pcmd) addCmd(card, r.pcmd, "proc-pcmd");
      }
      out.appendChild(card);
    }
  }
}

/* Plain-text tree — always uses the indented tree format regardless of which
   view is active, so Copy always produces a readable hierarchy. */
function procsToText() {
  const recs = Array.isArray(state.procs) ? state.procs : [];
  if (!recs.length) return "";
  const { roots } = buildProcForest(recs);
  const lines = [], seen = new Set();
  const walk = (node, depth) => {
    if (seen.has(node.id)) return;
    seen.add(node.id);
    const prefix = depth ? "  ".repeat(depth) + "↳ " : "";
    lines.push(prefix + procLabel(node.name, node.pid));
    for (const ch of node.children) walk(ch, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return lines.join("\n");
}

/* Plain-text tree with command lines inlined below each node — useful for
   pasting into a triage report where you need both the hierarchy and the
   exact commandlines in one block. */
function procsToTextWithCmds() {
  const recs = Array.isArray(state.procs) ? state.procs : [];
  if (!recs.length) return "";
  const { roots } = buildProcForest(recs);
  const lines = [], seen = new Set();
  const walk = (node, depth) => {
    if (seen.has(node.id)) return;
    seen.add(node.id);
    const indent = depth ? "  ".repeat(depth) : "";
    const arrow  = depth ? "↳ " : "";
    lines.push(indent + arrow + procLabel(node.name, node.pid));
    // Attach this node's command line immediately below, indented one more level
    const rec = recs.find(r => String(r.pid) === String(node.pid) && (r.name || "") === (node.name || ""));
    if (rec && rec.cmd) {
      lines.push(indent + "  ".repeat(depth ? 1 : 1) + "CMD: " + rec.cmd);
    }
    for (const ch of node.children) walk(ch, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return lines.join("\n");
}

/* Deduped command lines only — drops cleanly into a detonation/triage note. */
function procsCmdLines() {
  const recs = Array.isArray(state.procs) ? state.procs : [];
  const set = new Set();
  for (const r of recs) { if (r.cmd) set.add(r.cmd); if (r.pcmd) set.add(r.pcmd); }
  return [...set].join("\n");
}

(function wireProcs() {
  const toggle = document.getElementById("procs-tree-toggle");
  if (toggle) toggle.addEventListener("click", () => { procsTreeView = !procsTreeView; renderProcs(); saveLiveState(); });
  const wrap = document.getElementById("procs-wrap");
  if (wrap) wrap.addEventListener("change", renderProcs);
  const copyView = document.getElementById("procs-copy");
  if (copyView) copyView.addEventListener("click", () => {
    const txt = procsToText();
    if (!txt) return;
    navigator.clipboard.writeText(txt).then(() => flashBtn(copyView, "Copied"));
  });
  const copyCmds = document.getElementById("procs-copy-cmds");
  if (copyCmds) copyCmds.addEventListener("click", () => {
    // Prefer the deduped command lines; but a process tree often has none
    // (collapsed nodes, or lineage-only records). Don't leave the analyst with an
    // empty clipboard — fall back to the process tree itself so the button always
    // yields something useful.
    const cmds = procsCmdLines();
    if (cmds) {
      navigator.clipboard.writeText(cmds).then(() => flashBtn(copyCmds, "Copied"));
      return;
    }
    const tree = procsToText();
    if (!tree) { flashBtn(copyCmds, "none"); return; }
    navigator.clipboard.writeText(tree).then(() => flashBtn(copyCmds, "Copied tree"));
  });
  const copyTreeCmds = document.getElementById("procs-copy-tree-cmds");
  if (copyTreeCmds) copyTreeCmds.addEventListener("click", () => {
    const txt = procsToTextWithCmds();
    if (!txt) { flashBtn(copyTreeCmds, "none"); return; }
    navigator.clipboard.writeText(txt).then(() => flashBtn(copyTreeCmds, "Copied"));
  });
})();

/* ---------- pivot / enrich panel ---------- */
function togglePivotPanel(type) {
  const panel = document.querySelector(`.pivot-panel[data-type="${type}"]`);
  if (!panel) return;
  if (panel.childElementCount > 0) { panel.innerHTML = ""; return; } // toggle off
  buildPivotPanel(panel, type);
}

function buildPivotPanel(panel, type) {
  const values = state.rendered[type] || [];
  const pivots = pivotsForType(type);
  const enrichers = enrichForType(type);

  // ---- Bulk action bar (only if this category supports live enrichment) ----
  if (enrichers.length && values.length) {
    const bar = document.createElement("div");
    bar.className = "bulk-bar";

    const label = document.createElement("span");
    label.className = "bulk-label";
    label.textContent = `Run all (${values.length}):`;
    bar.appendChild(label);

    enrichers.forEach(prov => {
      const b = document.createElement("button");
      b.className = "mini bulk";
      b.textContent = "🔎 All " + (ENRICH_LABEL[prov] || prov);
      b.title = "Run " + (prov === "vt" ? "VirusTotal" : "AbuseIPDB") +
                " against every indicator in this category";
      b.addEventListener("click", () => runEnrichAll(prov, type, panel, b));
      bar.appendChild(b);
    });

    const prog = document.createElement("span");
    prog.className = "bulk-prog";
    bar.appendChild(prog);

    panel.appendChild(bar);

    // Per-category "Copy enriched" bar — populated once any result lands.
    // Lives right under the Run-all bar so the analyst doesn't have to scroll
    // to the bottom of the popup to copy.
    const copyBar = document.createElement("div");
    copyBar.className = "enrich-copyall-bar";
    copyBar.dataset.type = type;
    panel.appendChild(copyBar);
  }

  values.forEach(value => {
    const row = document.createElement("div");
    row.className = "ioc-row";
    row.dataset.value = value;

    const val = document.createElement("span");
    val.className = "ioc-val";
    val.textContent = value;
    row.appendChild(val);

    // Pivot (open tab) buttons
    pivots.forEach(p => {
      const b = document.createElement("button");
      b.className = "mini pv";
      b.textContent = PIVOT_LABEL[p];
      b.title = "Open " + PIVOT_LABEL[p] + " in a new tab";
      b.addEventListener("click", () => chrome.tabs.create({ url: PIVOTS[p](value) }));
      row.appendChild(b);
    });

    // Enrich (live API) buttons + result span
    const result = document.createElement("span");
    result.className = "enrich-result";

    enrichers.forEach(prov => {
      const b = document.createElement("button");
      b.className = "mini en";
      b.dataset.prov = prov; // so bulk runner can find/disable it
      b.textContent = "🔎 " + (ENRICH_LABEL[prov] || prov);
      b.title = "Live lookup (sends this indicator to " + (prov === "vt" ? "VirusTotal" : "AbuseIPDB") + ")";
      b.addEventListener("click", () => runEnrich(prov, type, value, result, b));
      row.appendChild(b);
    });

    row.appendChild(result);
    panel.appendChild(row);
  });
}

/* Run one provider against every indicator in a category, in PARALLEL with a
   configurable concurrency cap (Settings → Enrichment behavior). Paid tiers
   want fan-out; free tiers auto-throttle on first rate-limit response.

   Reliability:
   - Always consume chrome.runtime.lastError (Chrome silently drops later
     callbacks if it's left unread).
   - 30s timeout per call so a stuck worker doesn't hang the whole batch.
   - try/catch per call — one error never breaks the rest.
   - On a "rate limit" / "429" response, the loop falls back to sequential
     with 1s pacing for the remaining work. */
async function runEnrichAll(provider, type, panel, bulkBtn) {
  const provName = ENRICH_NAME[provider] || provider;
  const rows = [...panel.querySelectorAll(".ioc-row")];
  if (!rows.length) return;

  if (!enrichConfirmed) {
    if (!confirm(`Send all ${rows.length} indicators to ${provName}?`)) return;
    enrichConfirmed = true;
  }

  // If keys are encrypted, prompt for passphrase before kicking off the batch
  if (!(await ensureKeysUnlocked())) return;

  const pacing = await readPacing(provider);
  const concurrency = pacing.concurrency;
  const minDelayMs  = pacing.delayMs;
  const prog = panel.querySelector(".bulk-prog");
  bulkBtn.disabled = true;
  const origText = bulkBtn.textContent;

  let throttled = false;             // flipped on by any "rate limit" / "429"
  let completed = 0;
  let flagged = 0, clean = 0, errs = 0;

  const sendOne = (value) => new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      resolve({ error: "timeout (no response in 30s)" });
    }, 30000);
    try {
      chrome.runtime.sendMessage({ action: "enrich", provider, iocType: type, value }, (res) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        const err = chrome.runtime.lastError;
        if (err)        resolve({ error: err.message });
        else if (!res)  resolve({ error: "no response" });
        else            resolve(res);
      });
    } catch (e) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ error: String(e) });
    }
  });

  async function processRow(row) {
    const value    = row.dataset.value;
    const resultEl = row.querySelector(".enrich-result");
    const rowBtn   = row.querySelector(`.en[data-prov="${provider}"]`);
    try {
      resultEl.className = "enrich-result";
      resultEl.textContent = "…";
      if (rowBtn) rowBtn.disabled = true;
      const res = await sendOne(value);
      if (rowBtn) rowBtn.disabled = false;
      if (res && res.error) {
        resultEl.className = "enrich-result err";
        resultEl.textContent = res.error;
        errs++;
        if (/rate limit|429/i.test(res.error)) throttled = true;
      } else {
        renderEnrichResult(resultEl, res, provider, value);
        if (res.level === "bad" || res.level === "warn") flagged++;
        else clean++;
      }
    } catch (e) {
      console.error("[IOC] enrich row failed:", e);
      if (resultEl) {
        resultEl.className = "enrich-result err";
        resultEl.textContent = "iteration error: " + String(e);
      }
      errs++;
    }
    completed++;
    if (prog) prog.textContent = ` ${completed}/${rows.length}` + (throttled ? " · throttled" : "");
  }

  // Workers pull off a shared queue until empty.
  const queue = [...rows];
  const workerCount = Math.min(Math.max(1, concurrency), rows.length);

  async function worker() {
    while (queue.length) {
      const row = queue.shift();
      if (!row) return;
      await processRow(row);
      // Pacing: server-side throttle takes precedence (≥ 1s) over user-set
      // min-delay. Skip the wait when nothing left to dequeue.
      const wait = throttled ? Math.max(1000, minDelayMs) : minDelayMs;
      if (wait > 0 && queue.length) await new Promise(r => setTimeout(r, wait));
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  if (prog) {
    const parts = [];
    if (flagged) parts.push(`${flagged} flagged`);
    if (clean)   parts.push(`${clean} clean`);
    if (errs)    parts.push(`${errs} err`);
    prog.textContent = " done · " + (parts.join(" · ") || "no results");
  }
  bulkBtn.disabled = false;
  bulkBtn.textContent = origText;
}

/* Default per-provider pacing. Conservative numbers: VT/Abuse free-tier safe. */
const ENR_PACING_DEFAULT = {
  vt:        { concurrency: 1,  delayMs: 16000 },
  abuseipdb: { concurrency: 1,  delayMs: 1100  },
  rdap:      { concurrency: 10, delayMs: 0     },
  multigeo:  { concurrency: 10, delayMs: 0     }
};
const ENR_PACING_FREE = ENR_PACING_DEFAULT;
const ENR_PACING_PAID = {
  vt:        { concurrency: 10, delayMs: 0 },
  abuseipdb: { concurrency: 5,  delayMs: 0 },
  rdap:      { concurrency: 10, delayMs: 0 },
  multigeo:  { concurrency: 10, delayMs: 0 }
};

function readPacing(provider) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["enrPacing"], (d) => {
      const cfg = d.enrPacing || ENR_PACING_DEFAULT;
      const p = cfg[provider] || ENR_PACING_DEFAULT[provider] || { concurrency: 10, delayMs: 0 };
      const conc  = Math.min(50, Math.max(1, parseInt(p.concurrency, 10) || 1));
      const delay = Math.max(0, +p.delayMs || 0);
      resolve({ concurrency: conc, delayMs: delay });
    });
  });
}

/* Render an enrichment result with summary + Details expander.
   Stores the full structured response in state.enrichResults so the format-
   aware "Copy all enriched" can render JSON / markdown / by-IOC blocks. */
function renderEnrichResult(resultEl, res, provider, value) {
  resultEl.className = "enrich-result " + (res.level || "ok");

  let displayHtml;
  if (res.multiline && Array.isArray(res.lines)) {
    displayHtml = `<div class="geo-head">${escapeHtml(res.summary || "Geo")}</div>` +
      res.lines.map(l => `<div class="geo-line">${escapeHtml(l)}</div>`).join("");
  } else {
    displayHtml = escapeHtml(res.summary || "done");
  }

  const hasFields = res.fields && Object.keys(res.fields).length > 0;
  resultEl.innerHTML =
    `<span class="er-text">${displayHtml}</span>` +
    (hasFields ? `<button class="mini er-detail" title="Show all returned fields">⋯</button>` : "") +
    `<button class="mini er-copy" title="Copy for case notes">Copy</button>` +
    (hasFields ? `<div class="er-details" hidden></div>` : "");

  const cp = resultEl.querySelector(".er-copy");
  cp.addEventListener("click", (e) => {
    e.stopPropagation();
    // Look up the freshest stored record and rebuild the line so the click
    // honors any Settings toggle changes made since the result landed.
    const k = value + "|" + provider;
    const rec = state.enrichResults.find(r => (r.value + "|" + r.provider) === k);
    const line = rec ? buildCopyLine(rec) : `${value} — ${res.summary || "done"}`;
    navigator.clipboard.writeText(line);
    flashBtn(cp, "✓");
  });

  if (hasFields) {
    const detBtn = resultEl.querySelector(".er-detail");
    const detPanel = resultEl.querySelector(".er-details");
    detBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (detPanel.hidden) {
        detPanel.innerHTML = renderFieldsHtml(res.fields);
        detPanel.hidden = false;
        detBtn.textContent = "×";
      } else {
        detPanel.hidden = true;
        detBtn.textContent = "⋯";
      }
    });
  }

  // Record full result so the format-aware copier can render anything later.
  // We need the IOC category so the per-category copy bar can filter; figure
  // it out by walking up from the resultEl to the pivot-panel that contains it.
  let iocType = "";
  const panel = resultEl && resultEl.closest && resultEl.closest(".pivot-panel");
  if (panel && panel.dataset && panel.dataset.type) iocType = panel.dataset.type;

  const k = value + "|" + provider;
  state.enrichResults = state.enrichResults.filter(r => (r.value + "|" + r.provider) !== k);
  state.enrichResults.push({
    value, provider, iocType,
    level: res.level || "ok",
    summary: res.summary || "",
    fields: res.fields || {},
    lines: res.lines || null
  });
  updateCopyAllEnriched();
}

function renderFieldsHtml(fields) {
  const rows = Object.keys(fields).map(k =>
    `<div class="er-field"><span class="er-key">${escapeHtml(k)}</span><span class="er-val">${escapeHtml(String(fields[k]))}</span></div>`
  ).join("");
  return rows;
}

/* Render one "Copy enriched (N)" bar per category, inside the pivot panel
   that produced those results. The bar appears right under the "Run all"
   buttons so the analyst doesn't scroll to the bottom of the popup. Format
   selector mirrors the Settings default but can be changed per-copy. */
function updateCopyAllEnriched() {
  chrome.storage.local.get(["enrCopyFormat"], (d) => {
    const fmt = d.enrCopyFormat || "grouped";
    document.querySelectorAll(".enrich-copyall-bar").forEach(bar => {
      const type = bar.dataset.type || "";
      const items = type
        ? state.enrichResults.filter(r => r.iocType === type)
        : state.enrichResults;
      if (!items.length) { bar.innerHTML = ""; return; }
      bar.innerHTML = `
        <button class="mini accent copy-all-enriched">Copy enriched (${items.length})</button>
        <select class="mini copy-all-format" title="Output format">
          <option value="grouped">grouped</option>
          <option value="byioc">by IOC</option>
          <option value="json">JSON</option>
          <option value="md">markdown</option>
        </select>
        <span class="hint" style="margin-left:6px;">format</span>
      `;
      const sel = bar.querySelector(".copy-all-format");
      sel.value = fmt;
      const btn = bar.querySelector(".copy-all-enriched");
      btn.addEventListener("click", () => {
        navigator.clipboard.writeText(formatEnrichBatch(items, sel.value));
        flashBtn(btn, "✓ Copied");
      });
    });
  });
}

/* Format a batch of enrich results into one of four shapes for the clipboard.
   - grouped : FLAGGED then CLEAN, one line per result (current default)
   - byioc   : one block per IOC value, showing every provider that ran
   - json    : pretty JSON, full fields, machine-readable
   - md      : Markdown table — IOC | Provider | Level | Summary */
function formatEnrichBatch(results, format) {
  if (format === "json") {
    const grouped = {};
    for (const r of results) {
      grouped[r.value] = grouped[r.value] || { ioc: r.value, providers: {} };
      grouped[r.value].providers[r.provider] = {
        level: r.level,
        summary: r.summary,
        fields: r.fields || {},
        lines: r.lines || undefined
      };
    }
    return JSON.stringify(Object.values(grouped), null, 2);
  }

  if (format === "md") {
    const head = "| IOC | Provider | Level | Summary |";
    const sep  = "|-----|----------|-------|---------|";
    const rows = results.map(r =>
      `| ${mdCell(r.value)} | ${ENRICH_NAME[r.provider] || r.provider} | ${r.level} | ${mdCell(r.summary)} |`);
    return [head, sep, ...rows].join("\n");
  }

  if (format === "byioc") {
    const byValue = new Map();
    for (const r of results) {
      if (!byValue.has(r.value)) byValue.set(r.value, []);
      byValue.get(r.value).push(r);
    }
    const blocks = [];
    for (const [ioc, list] of byValue) {
      const lines = [ioc];
      for (const r of list) {
        // buildCopyLine returns "<ioc> — <provider line>"; we already have the
        // IOC as the block header, so strip it.
        const line = buildCopyLine(r).replace(/^[^—]+ — /, "");
        lines.push(`  [${r.level}] ${line}`);
        if (r.lines && r.lines.length) r.lines.forEach(l => lines.push("    " + l));
      }
      blocks.push(lines.join("\n"));
    }
    return blocks.join("\n\n");
  }

  // grouped (default)
  const dirty = results.filter(r => r.level === "bad" || r.level === "warn");
  const clean = results.filter(r => r.level === "ok");
  const out = [];
  if (dirty.length) {
    out.push(`=== FLAGGED (${dirty.length}) ===`);
    dirty.forEach(r => out.push(buildCopyLine(r)));
  }
  if (clean.length) {
    if (out.length) out.push("");
    out.push(`=== CLEAN (${clean.length}) ===`);
    clean.forEach(r => out.push(buildCopyLine(r)));
  }
  return out.join("\n");
}

let enrichFieldToggles = {};

/* Build the copy line for a single enrichment record from r.fields + current
   toggles. Returns "<ioc> — <provider-line>". For multigeo it's multi-line. */
function buildCopyLine(r) {
  const tg = enrichFieldToggles || {};
  const f  = r.fields || {};
  const verdict = r.level === "bad" ? "malicious"
                : r.level === "warn" ? "suspicious"
                : "clean";

  // multigeo: keep the per-source line list (already populated by background)
  if (r.provider === "multigeo" && Array.isArray(r.lines)) {
    return `${r.value} — ${r.summary || "Geo"}\n` + r.lines.map(l => "  " + l).join("\n");
  }

  const parts = [];
  if (r.provider === "vt") {
    parts.push("VT");
    if (tg.vtScore && (f.malicious !== undefined || f.total !== undefined)) {
      parts.push(`${f.malicious || 0}/${f.total || 0}`);
    }
    if (tg.vtVerdict) parts.push(verdict);
    if (tg.vtPercent && f.total) {
      const flagged = (f.malicious || 0) + (f.suspicious || 0);
      parts.push(`(${Math.round(flagged / f.total * 100)}%)`);
    }
    if (tg.vtSuspicious && f.suspicious) parts.push(`+${f.suspicious} susp`);

    const ctx = [];
    if (tg.vtThreatLabel  && f.threat_label)            ctx.push(f.threat_label);
    if (tg.vtReputation   && f.reputation !== undefined)ctx.push(`rep ${f.reputation}`);
    if (tg.vtFirstSeen    && f.first_seen)              ctx.push(`first ${f.first_seen}`);
    if (tg.vtLastAnalyzed && f.last_analyzed)           ctx.push(`last ${f.last_analyzed}`);
    if (tg.vtCountry      && f.country)                 ctx.push(f.country);
    if (tg.vtAsn          && f.asn)                     ctx.push(`AS${f.asn}`);
    if (tg.vtAsOwner      && f.as_owner)                ctx.push(f.as_owner);
    if (tg.vtRegistrar    && f.registrar)               ctx.push(f.registrar);
    if (tg.vtCategories   && f.categories)              ctx.push(f.categories);
    if (tg.vtFileName     && f.file_name)               ctx.push(f.file_name);
    if (tg.vtFileType     && f.file_type)               ctx.push(f.file_type);
    if (tg.vtTags         && f.tags)                    ctx.push("tags " + f.tags);
    if (tg.vtSigned       && f.signed)                  ctx.push("signed");
    if (ctx.length) parts.push("· " + ctx.join(" · "));

  } else if (r.provider === "abuseipdb") {
    parts.push("Abuse");
    if (tg.abuseScore && f.score !== undefined) parts.push(`${f.score}%`);
    const inParens = [];
    if (tg.abuseReports && f.total_reports !== undefined) inParens.push(`${f.total_reports} reports`);
    if (tg.abuseCountry && f.country_code)                inParens.push(f.country_code);
    if (inParens.length) parts.push(`(${inParens.join(", ")})`);

    const ctx = [];
    if (tg.abuseUsageType    && f.usage_type)    ctx.push(f.usage_type);
    if (tg.abuseIsp          && f.isp)           ctx.push(f.isp);
    if (tg.abuseDomain       && f.domain)        ctx.push(f.domain);
    if (tg.abuseTor          && f.is_tor)        ctx.push("TOR");
    if (tg.abuseLastReported && f.last_reported) ctx.push("last " + f.last_reported);
    if (tg.abuseHostnames    && f.hostnames)     ctx.push(f.hostnames);
    if (ctx.length) parts.push("· " + ctx.join(" · "));

  } else if (r.provider === "rdap") {
    parts.push("WHOIS");
    if (f.type === "ip") {
      const ctx = [];
      if (tg.rdapIpNetwork && f.network)     ctx.push(f.network);
      if (tg.rdapIpCountry && f.country)     ctx.push(f.country);
      if (tg.rdapIpOrg     && f.name)        ctx.push(f.name);
      if (tg.rdapIpAbuse   && f.abuse_email) ctx.push("abuse " + f.abuse_email);
      if (ctx.length) parts.push(ctx.join(" · "));
    } else if (f.type === "domain") {
      const ctx = [];
      if (tg.rdapRegistered && f.registered)  ctx.push("reg " + f.registered);
      if (tg.rdapAge        && f.age_days !== undefined) ctx.push(`(${f.age_days}d old)`);
      if (tg.rdapRegistrar  && f.registrar)   ctx.push(f.registrar);
      if (tg.rdapExpires    && f.expires)     ctx.push("exp " + f.expires);
      if (tg.rdapNameservers&& f.nameservers) ctx.push("ns " + f.nameservers);
      if (ctx.length) parts.push(ctx.join(" · "));
    }
  } else {
    // Unknown provider — fall back to the background summary
    parts.push(r.summary || "");
  }

  // If everything is off, fall back to the background-built summary so the
  // line never goes empty.
  const tail = parts.slice(1).filter(Boolean).join(" ").trim();
  const line = tail ? `${parts[0]} ${tail}` : (r.summary || parts[0] || "");
  return `${r.value} — ${line}`;
}

function mdCell(s) { return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\n/g, " "); }

async function runEnrich(provider, type, value, resultEl, btn) {
  const provName = ENRICH_NAME[provider] || provider;
  if (!enrichConfirmed) {
    if (!confirm(`Send ${value} to ${provName}?`)) return;
    enrichConfirmed = true; // remember for this popup session
  }
  // If keys are encrypted, prompt for passphrase before sending
  if (!(await ensureKeysUnlocked())) return;
  resultEl.className = "enrich-result";
  resultEl.textContent = "…";
  btn.disabled = true;

  chrome.runtime.sendMessage({ action: "enrich", provider, iocType: type, value }, (res) => {
    btn.disabled = false;
    // Consume lastError so it can't poison subsequent message callbacks.
    const err = chrome.runtime.lastError;
    if (err)         { resultEl.className = "enrich-result err"; resultEl.textContent = err.message; return; }
    if (!res)        { resultEl.className = "enrich-result err"; resultEl.textContent = "no response"; return; }
    if (res.error)   { resultEl.className = "enrich-result err"; resultEl.textContent = res.error; return; }
    renderEnrichResult(resultEl, res, provider, value);
  });
}

/* ============================================================
   UTILITIES (decoders/encoders) — display only
   ============================================================ */
const utilIn  = document.getElementById("util-in");
const utilOut = document.getElementById("util-out");

function b64decode(s) {
  // Tolerate whitespace, url-safe alphabet, missing padding
  let t = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  let out;
  try { out = decodeURIComponent(bin.split("").map(c => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")); }
  catch (e) { out = bin; }
  // If high-byte/low-byte alternation indicates UTF-16LE (PowerShell -enc),
  // re-decode pair-wise. Otherwise just strip stray nulls.
  const nullRatio = (bin.match(/\0/g) || []).length / Math.max(1, bin.length);
  if (nullRatio > 0.3 && bin.length >= 2) {
    let u16 = "";
    for (let i = 0; i + 1 < bin.length; i += 2) {
      const lo = bin.charCodeAt(i), hi = bin.charCodeAt(i + 1);
      u16 += String.fromCharCode(lo | (hi << 8));
    }
    out = u16;
  }
  return stripNullBytes(out);
}
function looksB64(s) {
  const t = s.trim();
  return t.length >= 8 && t.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(t);
}
function smartDecode(s) {
  let cur = s.trim();
  const steps = [];
  for (let i = 0; i < 6; i++) {
    let changed = false;
    if (/%[0-9a-fA-F]{2}/.test(cur)) {
      try { const d = decodeURIComponent(cur); if (d !== cur) { cur = d; steps.push("url-decoded"); changed = true; } } catch (e) {}
    }
    if (!changed && looksB64(cur)) {
      try {
        const d = b64decode(cur);
        if (d && /[\x20-\x7e]/.test(d) && d !== cur) { cur = d; steps.push("base64-decoded"); changed = true; }
      } catch (e) {}
    }
    if (!changed) break;
  }
  return steps.length ? `${cur}\n\n[steps: ${steps.join(" → ")}]` : `${cur}\n\n[no decodable layers detected]`;
}

/* XML pretty-print: validate via DOMParser, then indent. Throws on invalid XML. */
function beautifyXml(src) {
  const xml = String(src).trim();
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) throw new Error("Invalid XML");
  const compact = new XMLSerializer().serializeToString(doc).replace(/>\s+</g, "><");
  let out = "", depth = 0;
  compact.replace(/<[^>]+>|[^<]+/g, (tok) => {
    if (/^<\/.+>/.test(tok)) {
      depth = Math.max(0, depth - 1);
      out += "  ".repeat(depth) + tok + "\n";
    } else if (/^<[^!?].*[^/]>$/.test(tok) && !/^<.*\/>$/.test(tok)) {
      out += "  ".repeat(depth) + tok + "\n";
      depth++;
    } else {
      out += "  ".repeat(depth) + tok.trim() + "\n";
    }
    return tok;
  });
  return out.trim();
}
function minifyXml(src) {
  const xml = String(src).trim();
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) throw new Error("Invalid XML");
  return new XMLSerializer().serializeToString(doc).replace(/>\s+</g, "><").trim();
}

/* HTML stripper — return text content of an HTML fragment, no tags. */
function stripHtml(src) {
  const doc = new DOMParser().parseFromString(String(src), "text/html");
  // Drop <script>/<style> first so their contents don't leak through
  doc.querySelectorAll("script,style,noscript").forEach(n => n.remove());
  return (doc.body && doc.body.textContent || "").replace(/ /g, " ").trim();
}

/* HTTP stripper — split a raw HTTP request/response on the first blank line. */
function splitHttp(src) {
  const s = String(src).replace(/\r\n/g, "\n");
  const i = s.indexOf("\n\n");
  if (i === -1) return { head: s, body: "" };
  return { head: s.slice(0, i), body: s.slice(i + 2) };
}
function httpBody(src)    { return splitHttp(src).body; }
function httpHeaders(src) { return splitHttp(src).head; }
function httpRedact(src) {
  // Redact values of common secret-bearing headers while leaving the rest intact.
  // Matches "Header: value" (case-insensitive) until end of line.
  return String(src).replace(
    /^((?:Cookie|Set-Cookie|Authorization|Proxy-Authorization|X-Api-Key|X-Auth-Token|X-Csrf-Token)\s*:\s*)(.*)$/gim,
    (_m, h) => h + "<redacted>"
  );
}

document.querySelectorAll(".util-btns button[data-op]").forEach(btn => {
  btn.addEventListener("click", () => {
    const op = btn.dataset.op;
    const input = utilIn.value;
    try {
      let out;
      switch (op) {
        case "b64decode": out = b64decode(input); break;
        case "urldecode": out = decodeURIComponent(input); break;
        case "smart":     out = smartDecode(input); break;
        case "json-beautify": out = JSON.stringify(JSON.parse(input), null, 2); break;
        case "json-minify":   out = JSON.stringify(JSON.parse(input)); break;
        case "xml-beautify":  out = beautifyXml(input); break;
        case "xml-minify":    out = minifyXml(input); break;
        case "html-strip":    out = stripHtml(input); break;
        case "http-body":     out = httpBody(input); break;
        case "http-headers":  out = httpHeaders(input); break;
        case "http-redact":   out = httpRedact(input); break;
        default: out = "";
      }
      utilOut.textContent = out;
    } catch (e) {
      utilOut.textContent = e.message;
    }
  });
});

document.getElementById("util-copy").addEventListener("click", () =>
  navigator.clipboard.writeText(utilOut.textContent || ""));

document.getElementById("util-extract").addEventListener("click", () => {
  const txt = utilOut.textContent || "";
  if (!txt.trim()) return;
  processIOCs(txt, "(utilities decode)", {});
  document.querySelector('.tab[data-tab="extract"]').click();
});

/* ============================================================
   SETTINGS — API keys
   Two modes:
     - Plaintext: keys stored under vtKey/abuseKey/ipinfoKey in storage.local
     - Encrypted: a single base64 "encKeys" blob in storage.local containing
       AES-GCM(JSON({vtKey, abuseKey, ipinfoKey})), key derived via PBKDF2(passphrase, 250k iters, SHA-256)
   Decrypted values cache in chrome.storage.session.unlockedKeys until Chrome closes.
   The background worker reads unlockedKeys first, falls back to plaintext.
   ============================================================ */
const vtKeyEl    = document.getElementById("vt-key");
const abuseKeyEl = document.getElementById("abuse-key");
const ipinfoKeyEl = document.getElementById("ipinfo-key");
const keysStatus = document.getElementById("keys-status");
const encEnabledEl = document.getElementById("enc-enabled");
const encStatusEl  = document.getElementById("enc-status");
const encActionsEl = document.getElementById("enc-actions");

/* ---------- Crypto primitives (SubtleCrypto) ---------- */
async function _deriveKey(passphrase, salt) {
  const mat = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase),
    "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    mat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function encryptKeysBlob(plainObj, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const k    = await _deriveKey(passphrase, salt);
  const ct   = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, k,
    new TextEncoder().encode(JSON.stringify(plainObj))
  );
  const out = new Uint8Array(16 + 12 + ct.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode(...out));
}
async function decryptKeysBlob(blobB64, passphrase) {
  const u = Uint8Array.from(atob(blobB64), c => c.charCodeAt(0));
  const k = await _deriveKey(passphrase, u.slice(0, 16));
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: u.slice(16, 28) }, k, u.slice(28)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- Passphrase modal ---------- */
function askPassphrase({ title, prompt, confirm }) {
  return new Promise((resolve) => {
    const modal = document.getElementById("pp-modal");
    const pw1   = document.getElementById("pp-pw1");
    const pw2   = document.getElementById("pp-pw2");
    const err   = document.getElementById("pp-error");
    const ok    = document.getElementById("pp-ok");
    const can   = document.getElementById("pp-cancel");
    document.getElementById("pp-title").textContent  = title || "Passphrase";
    document.getElementById("pp-prompt").textContent = prompt || "";
    pw1.value = ""; pw2.value = ""; err.textContent = "";
    pw2.hidden = !confirm;
    modal.hidden = false;
    setTimeout(() => pw1.focus(), 0);
    const done = (val) => {
      modal.hidden = true;
      ok.onclick = null; can.onclick = null; pw1.onkeydown = null; pw2.onkeydown = null;
      resolve(val);
    };
    const submit = () => {
      const a = pw1.value;
      if (confirm) {
        const b = pw2.value;
        if (!a) { err.textContent = "passphrase required"; return; }
        if (a !== b) { err.textContent = "passphrases don't match"; return; }
      } else if (!a) { err.textContent = "passphrase required"; return; }
      done(a);
    };
    ok.onclick = submit;
    can.onclick = () => done(null);
    const keyHandler = (e) => { if (e.key === "Enter") submit(); else if (e.key === "Escape") done(null); };
    pw1.onkeydown = keyHandler;
    pw2.onkeydown = keyHandler;
  });
}

/* ---------- Encrypted-keys state ---------- */
function isEncryptedMode() {
  return new Promise((r) => chrome.storage.local.get(["encKeys"], (d) => r(!!d.encKeys)));
}
function getUnlockedKeys() {
  return new Promise((r) => chrome.storage.session.get(["unlockedKeys"], (d) => r(d.unlockedKeys || null)));
}
async function setUnlockedKeys(keys, passphrase) {
  await chrome.storage.session.set({ unlockedKeys: keys, passphrase });
}
async function clearUnlockedKeys() {
  await chrome.storage.session.remove(["unlockedKeys", "passphrase"]);
}
async function getCachedPassphrase() {
  const d = await chrome.storage.session.get(["passphrase"]);
  return d.passphrase || null;
}

/* Called by runEnrich / runEnrichAll before sending an enrich message. If
   encrypted mode and not yet unlocked this Chrome session, prompts. Returns
   true if keys are now usable (plaintext OR unlocked), false if cancelled. */
async function ensureKeysUnlocked() {
  const encrypted = await isEncryptedMode();
  if (!encrypted) return true;
  const cached = await getUnlockedKeys();
  if (cached) return true;
  const { encKeys } = await chrome.storage.local.get(["encKeys"]);
  while (true) {
    const pw = await askPassphrase({
      title: "Unlock API keys",
      prompt: "Enter your passphrase. Keys stay unlocked until Chrome closes."
    });
    if (!pw) return false;
    try {
      const keys = await decryptKeysBlob(encKeys, pw);
      await setUnlockedKeys(keys, pw);
      return true;
    } catch (_) {
      // Loop again — askPassphrase clears the error on reopen, so re-show with msg
      const err = document.getElementById("pp-error");
      if (err) err.textContent = "wrong passphrase";
      // Re-show modal immediately
      const modal = document.getElementById("pp-modal");
      if (modal) modal.hidden = false;
    }
  }
}

/* ---------- Settings UI ---------- */
function refreshKeyStatusUI(encrypted, unlocked) {
  encEnabledEl.checked = encrypted;
  encActionsEl.hidden = !encrypted;
  if (!encrypted) {
    encStatusEl.textContent = "Plaintext mode — keys readable via Inspect popup. Toggle ON to encrypt with a passphrase.";
    [vtKeyEl, abuseKeyEl, ipinfoKeyEl].forEach(el => el.disabled = false);
  } else if (unlocked) {
    encStatusEl.textContent = "Encrypted · unlocked this session. Keys live in memory until Chrome closes.";
    [vtKeyEl, abuseKeyEl, ipinfoKeyEl].forEach(el => el.disabled = false);
  } else {
    encStatusEl.textContent = "Encrypted · locked. Click any enrich button (or Save keys) to unlock.";
    [vtKeyEl, abuseKeyEl, ipinfoKeyEl].forEach(el => { el.disabled = true; el.value = ""; el.placeholder = "(locked)"; });
  }
}

async function loadKeys() {
  const encrypted = await isEncryptedMode();
  if (encrypted) {
    const unlocked = await getUnlockedKeys();
    if (unlocked) {
      vtKeyEl.value     = unlocked.vtKey     || "";
      abuseKeyEl.value  = unlocked.abuseKey  || "";
      ipinfoKeyEl.value = unlocked.ipinfoKey || "";
    }
    refreshKeyStatusUI(true, !!unlocked);
  } else {
    chrome.storage.local.get(["vtKey", "abuseKey", "ipinfoKey"], (d) => {
      if (d.vtKey)     vtKeyEl.value = d.vtKey;
      if (d.abuseKey)  abuseKeyEl.value = d.abuseKey;
      if (d.ipinfoKey) ipinfoKeyEl.value = d.ipinfoKey;
    });
    refreshKeyStatusUI(false, false);
  }
}

document.getElementById("save-keys").addEventListener("click", async () => {
  const encrypted = await isEncryptedMode();
  const obj = {
    vtKey: vtKeyEl.value.trim(),
    abuseKey: abuseKeyEl.value.trim(),
    ipinfoKey: ipinfoKeyEl.value.trim()
  };
  if (!encrypted) {
    chrome.storage.local.set(obj, () => {
      keysStatus.textContent = "Saved";
      setTimeout(() => keysStatus.textContent = "", 2000);
    });
    return;
  }
  // Encrypted mode — need passphrase (cached if already unlocked, else prompt)
  let pw = await getCachedPassphrase();
  if (!pw) {
    const ok = await ensureKeysUnlocked();
    if (!ok) return;
    pw = await getCachedPassphrase();
  }
  try {
    const blob = await encryptKeysBlob(obj, pw);
    await chrome.storage.local.set({ encKeys: blob });
    await setUnlockedKeys(obj, pw);
    keysStatus.textContent = "Saved (encrypted)";
    setTimeout(() => keysStatus.textContent = "", 2000);
    refreshKeyStatusUI(true, true);
  } catch (e) {
    keysStatus.textContent = "Encrypt failed: " + e.message;
  }
});

document.getElementById("clear-keys").addEventListener("click", async () => {
  await chrome.storage.local.remove(["vtKey", "abuseKey", "ipinfoKey", "encKeys"]);
  await clearUnlockedKeys();
  vtKeyEl.value = ""; abuseKeyEl.value = ""; ipinfoKeyEl.value = "";
  keysStatus.textContent = "Cleared (all modes)";
  setTimeout(() => keysStatus.textContent = "", 2000);
  refreshKeyStatusUI(false, false);
});

/* Toggle encryption on/off. ON: prompt new passphrase + encrypt current keys.
   OFF: confirm + unlock first + write plaintext + drop encKeys. */
encEnabledEl.addEventListener("change", async () => {
  const want = encEnabledEl.checked;
  const encrypted = await isEncryptedMode();
  if (want && !encrypted) {
    // Plaintext → encrypted
    const pw = await askPassphrase({
      title: "Set passphrase",
      prompt: "Pick a passphrase. There's no recovery if you forget it — you'll have to re-paste your API keys.",
      confirm: true
    });
    if (!pw) { encEnabledEl.checked = false; return; }
    const cur = await new Promise(r => chrome.storage.local.get(["vtKey","abuseKey","ipinfoKey"], r));
    const obj = { vtKey: cur.vtKey || "", abuseKey: cur.abuseKey || "", ipinfoKey: cur.ipinfoKey || "" };
    const blob = await encryptKeysBlob(obj, pw);
    await chrome.storage.local.set({ encKeys: blob });
    await chrome.storage.local.remove(["vtKey", "abuseKey", "ipinfoKey"]);
    await setUnlockedKeys(obj, pw);
    refreshKeyStatusUI(true, true);
    keysStatus.textContent = "Encrypted";
    setTimeout(() => keysStatus.textContent = "", 2000);
  } else if (!want && encrypted) {
    // Encrypted → plaintext
    if (!confirm("Disable encryption? API keys will be stored as plaintext again.")) {
      encEnabledEl.checked = true;
      return;
    }
    const ok = await ensureKeysUnlocked();
    if (!ok) { encEnabledEl.checked = true; return; }
    const keys = await getUnlockedKeys();
    await chrome.storage.local.set({
      vtKey: keys.vtKey || "",
      abuseKey: keys.abuseKey || "",
      ipinfoKey: keys.ipinfoKey || ""
    });
    await chrome.storage.local.remove(["encKeys"]);
    await clearUnlockedKeys();
    vtKeyEl.value = keys.vtKey || "";
    abuseKeyEl.value = keys.abuseKey || "";
    ipinfoKeyEl.value = keys.ipinfoKey || "";
    refreshKeyStatusUI(false, false);
    keysStatus.textContent = "Decrypted to plaintext";
    setTimeout(() => keysStatus.textContent = "", 2000);
  }
});

document.getElementById("enc-lock").addEventListener("click", async () => {
  await clearUnlockedKeys();
  refreshKeyStatusUI(true, false);
  keysStatus.textContent = "Locked";
  setTimeout(() => keysStatus.textContent = "", 2000);
});

document.getElementById("enc-change").addEventListener("click", async () => {
  const ok = await ensureKeysUnlocked();
  if (!ok) return;
  const newPw = await askPassphrase({
    title: "Change passphrase",
    prompt: "Pick a new passphrase. The next session unlock will use this one.",
    confirm: true
  });
  if (!newPw) return;
  const keys = await getUnlockedKeys();
  const blob = await encryptKeysBlob(keys, newPw);
  await chrome.storage.local.set({ encKeys: blob });
  await setUnlockedKeys(keys, newPw);
  keysStatus.textContent = "Passphrase changed";
  setTimeout(() => keysStatus.textContent = "", 2000);
});

/* ============================================================
   HISTORY — last 20 unique IOCs (chrome.storage.local)
   Entry: { ioc, type, ts, src }. Rolling buffer, dedupe on ioc+type.
   ============================================================ */
const HISTORY_DEFAULTS = { histEnabled: true, histCap: 20, histLogSrc: true, histGroup: "order" };

function getHistorySettings(cb) {
  chrome.storage.local.get(HISTORY_DEFAULTS, (s) => cb({
    enabled: s.histEnabled !== false,
    cap: Math.max(1, Math.min(50, Number(s.histCap) || 20)),
    logSrc: s.histLogSrc !== false,
    group: s.histGroup === "type" ? "type" : "order"
  }));
}

function saveToHistory(rawByType, sourceUrl) {
  if (!rawByType) return;
  getHistorySettings((cfg) => {
    if (!cfg.enabled) return; // history disabled by the user
    chrome.storage.local.get("history", ({ history = [] }) => {
      const now = Date.now();
      const src = cfg.logSrc ? (sourceUrl || "") : "";
      // Flatten this extraction's IOCs into entries
      const incoming = [];
      for (const type of Object.keys(rawByType)) {
        for (const ioc of (rawByType[type] || [])) {
          incoming.push({ ioc, type, ts: now, src });
        }
      }
      if (!incoming.length) return;

      // Dedupe: if ioc+type already exists, drop the old copy (newest wins)
      const key = e => e.type + "|" + e.ioc;
      const incomingKeys = new Set(incoming.map(key));
      let merged = history.filter(e => !incomingKeys.has(key(e)));
      // Also dedupe within the incoming batch itself
      const seen = new Set();
      const incomingUnique = incoming.filter(e => {
        const k = key(e); if (seen.has(k)) return false; seen.add(k); return true;
      });

      // Newest first, then cap (drop oldest = tail)
      merged = [...incomingUnique, ...merged].slice(0, cfg.cap);
      chrome.storage.local.set({ history: merged }, () => {
        if (document.getElementById("tab-history").classList.contains("active")) renderHistory();
      });
    });
  });
}

function renderHistory() {
  const list = document.getElementById("history-list");
  const filter = (document.getElementById("history-filter").value || "").toLowerCase();
  getHistorySettings((cfg) => {
    chrome.storage.local.get("history", ({ history = [] }) => {
      const rows = history.filter(e =>
        !filter || e.ioc.toLowerCase().includes(filter) || e.type.toLowerCase().includes(filter));

      if (!rows.length) {
        list.innerHTML = `<p class="hint">${history.length ? "No matches." : "No history yet — extract some IOCs."}</p>`;
        return;
      }

      const itemHtml = (e) => {
        const when = new Date(e.ts).toLocaleString();
        const host = srcHost(e.src);
        return `<div class="hist-item">
          <div class="hist-row">
            <span class="hist-type">${escapeHtml((TITLES[e.type] || e.type))}</span>
            <span class="hist-ioc">${escapeHtml(e.ioc)}</span>
            <button class="mini hist-copy" data-ioc="${escapeHtml(e.ioc)}" title="Copy this indicator">Copy</button>
          </div>
          <div class="hist-meta">${escapeHtml(when)}${host ? " · " + escapeHtml(host) : ""}</div>
        </div>`;
      };

      if (cfg.group === "type") {
        // Bucket by type, preserve insertion order within each (newest first since
        // the underlying history array is already newest-first).
        const byType = new Map();
        for (const e of rows) {
          if (!byType.has(e.type)) byType.set(e.type, []);
          byType.get(e.type).push(e);
        }
        // Use the canonical TITLES order so groups always appear in the same order.
        const orderedTypes = [...Object.keys(TITLES).filter(t => byType.has(t)),
                              ...[...byType.keys()].filter(t => !(t in TITLES))];
        list.innerHTML = orderedTypes.map(type => {
          const items = byType.get(type) || [];
          const title = TITLES[type] || type.toUpperCase();
          return `<details class="hist-group">
            <summary>
              <span class="hist-group-title">${escapeHtml(title)} (${items.length})</span>
              <button class="mini hist-copy-group summary-btn" data-type="${escapeHtml(type)}" title="Copy every ${escapeHtml(title)} in history">Copy all</button>
            </summary>
            <div class="hist-group-body">${items.map(itemHtml).join("")}</div>
          </details>`;
        }).join("");
      } else {
        list.innerHTML = rows.map(itemHtml).join("");
      }

      // wire per-entry copy buttons
      list.querySelectorAll(".hist-copy").forEach(btn => {
        btn.addEventListener("click", () => {
          navigator.clipboard.writeText(btn.dataset.ioc);
          flashBtn(btn, "✓");
        });
      });

      // wire per-group copy + stop summary toggle
      list.querySelectorAll(".hist-copy-group").forEach(btn => {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          chrome.storage.local.get("history", ({ history = [] }) => {
            const t = btn.dataset.type;
            const iocs = history.filter(h => h.type === t).map(h => h.ioc);
            if (!iocs.length) return;
            navigator.clipboard.writeText(iocs.join("\n"));
            flashBtn(btn, "✓");
          });
        });
      });
    });
  });
}

/* Show just the hostname of the source, not the full URL (shorter + less noisy) */
function srcHost(url) {
  if (!url) return "";
  if (!/^https?:/i.test(url)) return url; // e.g. "(utilities decode)"
  try { return new URL(url).hostname; } catch (_) { return url; }
}

document.getElementById("history-filter").addEventListener("input", renderHistory);

document.getElementById("history-copy").addEventListener("click", () => {
  chrome.storage.local.get("history", ({ history = [] }) => {
    if (!history.length) return;
    navigator.clipboard.writeText(history.map(e => e.ioc).join("\n"));
    flashBtn(document.getElementById("history-copy"), "✓");
  });
});

document.getElementById("history-json").addEventListener("click", () => {
  chrome.storage.local.get("history", ({ history = [] }) => {
    if (!history.length) return;
    navigator.clipboard.writeText(JSON.stringify(history, null, 2));
    flashBtn(document.getElementById("history-json"), "✓");
  });
});

document.getElementById("history-clear").addEventListener("click", () => {
  if (!confirm("Clear all extraction history?")) return;
  chrome.storage.local.set({ history: [] }, renderHistory);
});

/* ---------- history settings (Settings tab) ---------- */
function loadHistorySettings() {
  getHistorySettings((cfg) => {
    document.getElementById("hist-enabled").checked = cfg.enabled;
    document.getElementById("hist-logsrc").checked  = cfg.logSrc;
    document.getElementById("hist-cap").value        = cfg.cap;
    const groupEl = document.getElementById("hist-group");
    if (groupEl) groupEl.value = cfg.group;
  });
}
document.getElementById("save-hist").addEventListener("click", () => {
  const enabled = document.getElementById("hist-enabled").checked;
  const logSrc  = document.getElementById("hist-logsrc").checked;
  const group   = document.getElementById("hist-group").value === "type" ? "type" : "order";
  let cap = Number(document.getElementById("hist-cap").value) || 20;
  cap = Math.max(1, Math.min(50, cap));
  document.getElementById("hist-cap").value = cap;
  chrome.storage.local.set({ histEnabled: enabled, histCap: cap, histLogSrc: logSrc, histGroup: group }, () => {
    // If the History tab is open, refresh it so the new grouping appears
    if (document.getElementById("tab-history").classList.contains("active")) renderHistory();
    // Trim existing history down to the new cap immediately
    chrome.storage.local.get("history", ({ history = [] }) => {
      if (history.length > cap) {
        chrome.storage.local.set({ history: history.slice(0, cap) }, () => {
          document.getElementById("hist-status").textContent = "Saved";
        });
      } else {
        document.getElementById("hist-status").textContent = "Saved";
      }
    });
  });
});

/* ---------- init ---------- */
loadKeys();
/* ---------- enrichment field toggles ---------- */
const EF_MAP = {
  // VT core
  "ef-vt-score":      "vtScore",
  "ef-vt-verdict":    "vtVerdict",
  "ef-vt-percent":    "vtPercent",
  "ef-vt-suspicious": "vtSuspicious",
  // VT context
  "ef-vt-label":      "vtThreatLabel",
  "ef-vt-rep":        "vtReputation",
  "ef-vt-first":      "vtFirstSeen",
  "ef-vt-last":       "vtLastAnalyzed",
  // VT IPs
  "ef-vt-country":    "vtCountry",
  "ef-vt-asn":        "vtAsn",
  "ef-vt-asowner":    "vtAsOwner",
  // VT domains
  "ef-vt-registrar":  "vtRegistrar",
  "ef-vt-categories": "vtCategories",
  // VT files
  "ef-vt-filename":   "vtFileName",
  "ef-vt-filetype":   "vtFileType",
  "ef-vt-tags":       "vtTags",
  "ef-vt-signed":     "vtSigned",
  // Abuse
  "ef-ab-score":      "abuseScore",
  "ef-ab-reports":    "abuseReports",
  "ef-ab-country":    "abuseCountry",
  "ef-ab-isp":        "abuseIsp",
  "ef-ab-domain":     "abuseDomain",
  "ef-ab-usage":      "abuseUsageType",
  "ef-ab-tor":        "abuseTor",
  "ef-ab-lastrep":    "abuseLastReported",
  "ef-ab-hostnames":  "abuseHostnames",
  // RDAP IP
  "ef-rdap-ip-network": "rdapIpNetwork",
  "ef-rdap-ip-country": "rdapIpCountry",
  "ef-rdap-ip-org":     "rdapIpOrg",
  "ef-rdap-ip-abuse":   "rdapIpAbuse",
  // RDAP domain
  "ef-rdap-registered": "rdapRegistered",
  "ef-rdap-age":        "rdapAge",
  "ef-rdap-registrar":  "rdapRegistrar",
  "ef-rdap-expires":    "rdapExpires",
  "ef-rdap-ns":         "rdapNameservers"
};

/* Default toggles — what the current short summary looks like:
   "VT 10/91 malicious (14%) +3 susp", "Abuse 75% (12 reports, RU)", etc. */
const ENRICH_FIELDS_DEFAULT = {
  vtScore: true, vtVerdict: true, vtPercent: true, vtSuspicious: true,
  vtThreatLabel: true, vtReputation: false, vtFirstSeen: false, vtLastAnalyzed: false,
  vtCountry: false, vtAsn: false, vtAsOwner: false,
  vtRegistrar: false, vtCategories: false,
  vtFileName: false, vtFileType: false, vtTags: false, vtSigned: false,
  abuseScore: true, abuseReports: true, abuseCountry: true,
  abuseIsp: false, abuseDomain: false, abuseUsageType: false,
  abuseTor: true, abuseLastReported: false, abuseHostnames: false,
  rdapIpNetwork: false, rdapIpCountry: true, rdapIpOrg: true, rdapIpAbuse: false,
  rdapRegistered: true, rdapAge: true, rdapRegistrar: true,
  rdapExpires: false, rdapNameservers: false
};

function loadEnrichFields() {
  chrome.storage.local.get(["enrichFields"], (d) => {
    // First-time install gets sensible defaults; existing user gets their saved toggles.
    const stored = d.enrichFields;
    const f = stored && Object.keys(stored).length ? stored : { ...ENRICH_FIELDS_DEFAULT };
    enrichFieldToggles = f;
    for (const [id, key] of Object.entries(EF_MAP)) {
      const el = document.getElementById(id);
      if (el) el.checked = !!f[key];
    }
  });
}
const saveFieldsBtn = document.getElementById("save-fields");
if (saveFieldsBtn) saveFieldsBtn.addEventListener("click", () => {
  const f = {};
  for (const [id, key] of Object.entries(EF_MAP)) {
    const el = document.getElementById(id);
    if (el) f[key] = el.checked;
  }
  chrome.storage.local.set({ enrichFields: f }, () => {
    enrichFieldToggles = f;
    updateCopyAllEnriched(); // refresh the per-category bars so format change is visible
    const st = document.getElementById("fields-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});
const resetFieldsBtn = document.getElementById("reset-fields");
if (resetFieldsBtn) resetFieldsBtn.addEventListener("click", () => {
  enrichFieldToggles = { ...ENRICH_FIELDS_DEFAULT };
  for (const [id, key] of Object.entries(EF_MAP)) {
    const el = document.getElementById(id);
    if (el) el.checked = !!ENRICH_FIELDS_DEFAULT[key];
  }
  chrome.storage.local.set({ enrichFields: enrichFieldToggles }, () => {
    updateCopyAllEnriched();
    const st = document.getElementById("fields-status");
    if (st) { st.textContent = "Reset"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- Enrichment behavior (per-provider pacing + copy format) ----------
   "rdap" and "multigeo" share one row in the UI — they're both keyless and
   have no published rate limit, so a single "other-conc" input drives both. */
function applyPacingToInputs(p) {
  const vc = document.getElementById("enr-vt-conc");     if (vc) vc.value = p.vt.concurrency;
  const vd = document.getElementById("enr-vt-delay");    if (vd) vd.value = (p.vt.delayMs / 1000).toString();
  const ac = document.getElementById("enr-abuse-conc");  if (ac) ac.value = p.abuseipdb.concurrency;
  const ad = document.getElementById("enr-abuse-delay"); if (ad) ad.value = (p.abuseipdb.delayMs / 1000).toString();
  const oc = document.getElementById("enr-other-conc");  if (oc) oc.value = p.rdap.concurrency;
}
function readPacingFromInputs() {
  const num = (id, fb) => {
    const n = parseFloat(document.getElementById(id).value);
    return isFinite(n) ? n : fb;
  };
  const other = Math.max(1, Math.min(50, num("enr-other-conc", 10) | 0));
  return {
    vt:        { concurrency: Math.max(1, Math.min(50, num("enr-vt-conc", 1) | 0)),
                 delayMs:     Math.max(0, Math.round(num("enr-vt-delay", 16) * 1000)) },
    abuseipdb: { concurrency: Math.max(1, Math.min(50, num("enr-abuse-conc", 1) | 0)),
                 delayMs:     Math.max(0, Math.round(num("enr-abuse-delay", 1) * 1000)) },
    rdap:      { concurrency: other, delayMs: 0 },
    multigeo:  { concurrency: other, delayMs: 0 }
  };
}
function loadEnrichmentBehavior() {
  chrome.storage.local.get(["enrPacing", "enrCopyFormat", "enrConcurrency"], (d) => {
    let p = d.enrPacing;
    // One-shot migration from the old single-knob setting.
    if (!p && d.enrConcurrency) {
      const n = Math.max(1, Math.min(50, parseInt(d.enrConcurrency, 10) || 10));
      p = { vt: {concurrency:n, delayMs:0}, abuseipdb: {concurrency:n, delayMs:0},
            rdap: {concurrency:n, delayMs:0}, multigeo: {concurrency:n, delayMs:0} };
    }
    applyPacingToInputs(p || ENR_PACING_DEFAULT);
    const f = document.getElementById("enr-copy-format");
    if (f) f.value = d.enrCopyFormat || "grouped";
  });
}
const enrSaveBtn = document.getElementById("save-enr");
if (enrSaveBtn) enrSaveBtn.addEventListener("click", () => {
  const pacing = readPacingFromInputs();
  applyPacingToInputs(pacing); // clamp/normalise back into the inputs
  const fmt = document.getElementById("enr-copy-format").value || "grouped";
  chrome.storage.local.set({ enrPacing: pacing, enrCopyFormat: fmt }, () => {
    updateCopyAllEnriched();
    const st = document.getElementById("enr-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});
const freeBtn = document.getElementById("enr-preset-free");
if (freeBtn) freeBtn.addEventListener("click", () => {
  applyPacingToInputs(ENR_PACING_FREE);
  const st = document.getElementById("enr-status");
  if (st) { st.textContent = "Free-tier values loaded — click Save to apply"; setTimeout(() => st.textContent = "", 3500); }
});
const paidBtn = document.getElementById("enr-preset-paid");
if (paidBtn) paidBtn.addEventListener("click", () => {
  applyPacingToInputs(ENR_PACING_PAID);
  const st = document.getElementById("enr-status");
  if (st) { st.textContent = "Paid-tier values loaded — click Save to apply"; setTimeout(() => st.textContent = "", 3500); }
});
loadEnrichmentBehavior();

/* ---------- detection thresholds (two-tier: warn + bad) ---------- */
function loadThresholds() {
  chrome.storage.local.get(["thresholds"], (d) => {
    const t = d.thresholds || {};
    const vt     = document.getElementById("th-vt");       if (vt)     vt.value     = t.vt        || 5;
    const vtW    = document.getElementById("th-vt-warn");  if (vtW)    vtW.value    = t.vtWarn    || 1;
    const ab     = document.getElementById("th-abuse");    if (ab)     ab.value     = t.abuse     || 75;
    const abW    = document.getElementById("th-abuse-warn"); if (abW)  abW.value    = t.abuseWarn || 25;
  });
}
const thBtn = document.getElementById("save-thresholds");
if (thBtn) thBtn.addEventListener("click", () => {
  let vt        = Math.max(1, Math.min(50,  parseInt(document.getElementById("th-vt").value,        10) || 5));
  let vtWarn    = Math.max(1, Math.min(vt,  parseInt(document.getElementById("th-vt-warn").value,   10) || 1));
  let abuse     = Math.max(1, Math.min(100, parseInt(document.getElementById("th-abuse").value,     10) || 75));
  let abuseWarn = Math.max(1, Math.min(abuse, parseInt(document.getElementById("th-abuse-warn").value, 10) || 25));
  document.getElementById("th-vt").value        = vt;
  document.getElementById("th-vt-warn").value   = vtWarn;
  document.getElementById("th-abuse").value     = abuse;
  document.getElementById("th-abuse-warn").value = abuseWarn;
  chrome.storage.local.set({ thresholds: { vt, vtWarn, abuse, abuseWarn } }, () => {
    const st = document.getElementById("th-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- default output settings ---------- */
function loadDefaults() {
  chrome.storage.local.get(["outputDefaults"], (d) => {
    const o = d.outputDefaults;
    if (!o) return;
    const m = { "def-sep": ["value","separator"], "def-sanitize":["checked","sanitize"],
               "def-defang":["checked","defang"], "def-numbered":["checked","numbered"],
               "def-quoted":["checked","quoted"], "def-single-quoted":["checked","singleQuoted"],
               "def-wildcard-pre":["checked","wildcardPre"], "def-wildcard-suf":["checked","wildcardSuf"],
               "def-headers":["checked","headers"] };
    for (const [id,[prop,key]] of Object.entries(m)) {
      const el = document.getElementById(id); if (el && o[key] !== undefined) el[prop] = o[key];
    }
    if (o.headers !== undefined) includeHeaders = !!o.headers;
  });
}
/* Apply saved defaults OR last live state to the Extract controls on popup open.
   liveState (last session) takes priority over outputDefaults so the popup
   reopens exactly as the analyst left it. */
function applyDefaultsToExtract() {
  chrome.storage.local.get(["outputDefaults", "liveState"], (d) => {
    const o = d.liveState || d.outputDefaults; // live state wins
    if (!o) return;
    if (o.separator    !== undefined) separatorEl.value  = o.separator;
    if (o.sanitize     !== undefined) sanitizeEl.checked = o.sanitize;
    if (o.defang       !== undefined) defangEl.checked   = o.defang;
    if (o.numbered     !== undefined) numberEl.checked   = o.numbered;
    if (o.quoted       !== undefined) quotedEl.checked   = o.quoted;
    if (o.singleQuoted !== undefined && singleQuotedEl) singleQuotedEl.checked = o.singleQuoted;
    if (o.wildcardPre  !== undefined && wildcardPreEl)  wildcardPreEl.checked  = o.wildcardPre;
    if (o.wildcardSuf  !== undefined && wildcardSufEl)  wildcardSufEl.checked  = o.wildcardSuf;
    if (o.headers      !== undefined) includeHeaders = !!o.headers;
    // Extra state only present in liveState (not outputDefaults)
    const appendEl = document.getElementById("append-mode");
    if (appendEl && o.appendMode    !== undefined) appendEl.checked = o.appendMode;
    if (o.procsTreeView !== undefined) procsTreeView = !!o.procsTreeView;
    if (Array.isArray(o.openSections) && o.openSections.length) {
      savedOpenSections = new Set(o.openSections);
    }
    // Restore active tab (defer so all DOM is ready)
    if (o.activeTab && o.activeTab !== "extract") {
      setTimeout(() => {
        const tabBtn = document.querySelector(`.tab[data-tab="${o.activeTab}"]`);
        if (tabBtn) tabBtn.click();
      }, 0);
    }
  });
}
/* ---------- live state persistence ----------
   Saves a snapshot of every UI toggle + active tab + open IOC sections so
   the popup reopens exactly as the analyst left it. Called on every
   meaningful state change (debounced 200 ms to avoid hammering storage). */
let _saveLiveTimer = null;
function saveLiveState() {
  clearTimeout(_saveLiveTimer);
  _saveLiveTimer = setTimeout(() => {
    const appendEl    = document.getElementById("append-mode");
    const activeTabEl = document.querySelector(".tab.active");
    const openSections = [];
    document.querySelectorAll("#output details.ioc-section[open]").forEach(d => {
      const t = d.querySelector("[data-type]");
      if (t && t.dataset && t.dataset.type) openSections.push(t.dataset.type);
    });
    chrome.storage.local.set({ liveState: {
      sanitize:     sanitizeEl     ? sanitizeEl.checked     : true,
      defang:       defangEl       ? defangEl.checked       : false,
      redact:       redactEl       ? redactEl.checked       : false,
      separator:    separatorEl    ? separatorEl.value      : "newline",
      numbered:     numberEl       ? numberEl.checked       : false,
      quoted:       quotedEl       ? quotedEl.checked       : false,
      singleQuoted: singleQuotedEl ? singleQuotedEl.checked : false,
      wildcardPre:  wildcardPreEl  ? wildcardPreEl.checked  : false,
      wildcardSuf:  wildcardSufEl  ? wildcardSufEl.checked  : false,
      appendMode:   appendEl       ? appendEl.checked       : false,
      activeTab:    activeTabEl    ? activeTabEl.dataset.tab : "extract",
      openSections,
      procsTreeView: !!procsTreeView
    }});
  }, 200);
}

const defBtn = document.getElementById("save-defaults");
if (defBtn) defBtn.addEventListener("click", () => {
  const o = {
    separator: document.getElementById("def-sep").value,
    sanitize:  document.getElementById("def-sanitize").checked,
    defang:    document.getElementById("def-defang").checked,
    numbered:  document.getElementById("def-numbered").checked,
    quoted:       document.getElementById("def-quoted").checked,
    singleQuoted: document.getElementById("def-single-quoted") ? document.getElementById("def-single-quoted").checked : false,
    wildcardPre:  document.getElementById("def-wildcard-pre")  ? document.getElementById("def-wildcard-pre").checked  : false,
    wildcardSuf:  document.getElementById("def-wildcard-suf")  ? document.getElementById("def-wildcard-suf").checked  : false,
    headers:      document.getElementById("def-headers").checked
  };
  chrome.storage.local.set({ outputDefaults: o }, () => {
    includeHeaders = o.headers;
    // Refresh the All IOCs pane so the change takes effect immediately
    try { allPaneDirty = false; allPaneBaseValues = null; syncAllPane(); } catch (_) {}
    const st = document.getElementById("def-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- IOC field names & log locations ---------- */
function loadIocFieldSettings(cb) {
  chrome.storage.local.get(["iocFieldSettings"], (d) => {
    iocFieldSettings = d.iocFieldSettings || {};
    if (cb) cb();
  });
}

function buildIocFieldsGrid() {
  const grid = document.getElementById("ioc-fields-grid");
  if (!grid) return;
  grid.innerHTML = "";

  // Header row
  ["", "Field name", "Index", "Sourcetype"].forEach(txt => {
    const h = document.createElement("div");
    h.className = "ifc-head";
    h.textContent = txt;
    grid.appendChild(h);
  });

  for (const type of Object.keys(TITLES)) {
    const s = iocFieldSettings[type] || {};

    const lbl = document.createElement("div");
    lbl.className = "ifc-label";
    lbl.textContent = TITLES[type];
    grid.appendChild(lbl);

    [
      ["field",      FIELD_DEFAULTS[type] || "field"],
      ["index",      "index"],
      ["sourcetype", "sourcetype"]
    ].forEach(([prop, ph]) => {
      const inp = document.createElement("input");
      inp.className = "ifc-inp";
      inp.type = "text";
      inp.dataset.iocType = type;
      inp.dataset.iocProp = prop;
      inp.placeholder = ph;
      inp.value = s[prop] || "";
      grid.appendChild(inp);
    });
  }
}

const saveIocFieldsBtn = document.getElementById("save-ioc-fields");
if (saveIocFieldsBtn) saveIocFieldsBtn.addEventListener("click", () => {
  const settings = {};
  document.querySelectorAll("#ioc-fields-grid .ifc-inp").forEach(inp => {
    const type = inp.dataset.iocType;
    const prop = inp.dataset.iocProp;
    if (type && prop) {
      if (!settings[type]) settings[type] = {};
      settings[type][prop] = inp.value.trim();
    }
  });
  iocFieldSettings = settings;
  chrome.storage.local.set({ iocFieldSettings: settings }, () => {
    // Re-render IOC cards so field-input values reflect the new defaults
    if (Object.keys(state.raw).length) renderIOCs();
    const st = document.getElementById("ioc-fields-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

const resetIocFieldsBtn = document.getElementById("reset-ioc-fields");
if (resetIocFieldsBtn) resetIocFieldsBtn.addEventListener("click", () => {
  iocFieldSettings = {};
  chrome.storage.local.remove("iocFieldSettings", () => {
    buildIocFieldsGrid();
    if (Object.keys(state.raw).length) renderIOCs();
    const st = document.getElementById("ioc-fields-status");
    if (st) { st.textContent = "Reset"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- Defender KQL table / column / operator settings ---------- */
const KQL_OPS = ["in~", "in", "has_any", "has", "contains"];

function loadKqlSettings(cb) {
  chrome.storage.local.get(["kqlSettings"], (d) => {
    kqlSettings = d.kqlSettings || {};
    if (cb) cb();
  });
}

function buildKqlGrid() {
  const grid = document.getElementById("kql-fields-grid");
  if (!grid) return;
  grid.innerHTML = "";

  // Header row
  ["", "Table", "Column", "Operator"].forEach(txt => {
    const h = document.createElement("div");
    h.className = "ifc-head";
    h.textContent = txt;
    grid.appendChild(h);
  });

  for (const type of Object.keys(TITLES)) {
    const base = KQL[type] || { table: "", col: type, op: "in~" };
    const s    = kqlSettings[type] || {};

    const lbl = document.createElement("div");
    lbl.className = "ifc-label";
    lbl.textContent = TITLES[type];
    grid.appendChild(lbl);

    // Table input
    const tblInp = document.createElement("input");
    tblInp.className = "ifc-inp";
    tblInp.type = "text";
    tblInp.dataset.kqlType = type;
    tblInp.dataset.kqlProp = "table";
    tblInp.placeholder = base.table || "table";
    tblInp.value = ("table" in s) ? s.table : "";
    grid.appendChild(tblInp);

    // Column input
    const colInp = document.createElement("input");
    colInp.className = "ifc-inp";
    colInp.type = "text";
    colInp.dataset.kqlType = type;
    colInp.dataset.kqlProp = "col";
    colInp.placeholder = base.col || "column";
    colInp.value = s.col || "";
    grid.appendChild(colInp);

    // Operator select
    const sel = document.createElement("select");
    sel.className = "ifc-sel";
    sel.dataset.kqlType = type;
    sel.dataset.kqlProp = "op";
    const currentOp = s.op || base.op || "in~";
    KQL_OPS.forEach(o => {
      const opt = document.createElement("option");
      opt.value = o;
      opt.textContent = o;
      if (o === currentOp) opt.selected = true;
      sel.appendChild(opt);
    });
    grid.appendChild(sel);
  }
}

const saveKqlFieldsBtn = document.getElementById("save-kql-fields");
if (saveKqlFieldsBtn) saveKqlFieldsBtn.addEventListener("click", () => {
  const settings = {};
  document.querySelectorAll("#kql-fields-grid [data-kql-type]").forEach(el => {
    const type = el.dataset.kqlType;
    const prop = el.dataset.kqlProp;
    if (type && prop) {
      if (!settings[type]) settings[type] = {};
      settings[type][prop] = el.value.trim();
    }
  });
  kqlSettings = settings;
  chrome.storage.local.set({ kqlSettings: settings }, () => {
    const st = document.getElementById("kql-fields-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

const resetKqlFieldsBtn = document.getElementById("reset-kql-fields");
if (resetKqlFieldsBtn) resetKqlFieldsBtn.addEventListener("click", () => {
  kqlSettings = {};
  chrome.storage.local.remove("kqlSettings", () => {
    buildKqlGrid();
    const st = document.getElementById("kql-fields-status");
    if (st) { st.textContent = "Reset"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ============================================================
   SPLUNK SECURITY CONTROLS
   Each control = { id, name, index, sourcetype, fields:{type:fieldname} }
   When buildQuery / buildInQuery runs and ≥1 control covers the IOC type,
   a separate sub-query is generated per matching control and they're joined
   with "\nOR " so the analyst can paste one multi-source hunt into Splunk.
   ============================================================ */
const DEFAULT_SPL_CONTROLS = [
  { id:"proxy",    name:"Proxy",              index:"proxy",    sourcetype:"bluecoat:proxysg:access:syslog",
    fields:{ src_ip:"c_ip", ips:"c_ip", domains:"cs_host", urls:"cs_uri" } },
  { id:"email",    name:"Email Gateway",      index:"mail",     sourcetype:"exchange:message_tracking",
    fields:{ emails:"sender", email_subjects:"subject", src_ip:"src_ip", domains:"recipient_domain" } },
  { id:"firewall", name:"Firewall",           index:"firewall", sourcetype:"cisco:asa",
    fields:{ src_ip:"src_ip", dest_ip:"dest_ip", ips:"src_ip" } },
  { id:"ids",      name:"IDS/IPS",            index:"ids",      sourcetype:"suricata",
    fields:{ src_ip:"src_ip", dest_ip:"dest_ip", ips:"src_ip", domains:"dns.query", urls:"http.uri" } },
  { id:"sysmon",   name:"Sysmon",             index:"sysmon",   sourcetype:"xmlwineventlog",
    fields:{ hostnames:"Computer", files:"TargetFilename", paths:"TargetFilename",
             md5:"Hashes", sha1:"Hashes", sha256:"Hashes", ips:"DestinationIp", domains:"QueryName" } },
  { id:"winevent", name:"WinEvent Security",  index:"winevent", sourcetype:"WinEventLog:Security",
    fields:{ hostnames:"ComputerName", src_ip:"IpAddress", ips:"IpAddress" } },
  { id:"dns",      name:"DNS",               index:"dns",      sourcetype:"stream:dns",
    fields:{ domains:"query", ips:"answer" } },
  { id:"dlp",      name:"DLP",              index:"dlp",      sourcetype:"symantec:dlp:incident",
    fields:{ emails:"sender_email", files:"filename", domains:"destination_domain" } },
  { id:"edr",      name:"EDR / Endpoint",    index:"edr",      sourcetype:"crowdstrike:events",
    fields:{ md5:"MD5HashData", sha256:"SHA256HashData", sha1:"SHA1HashData",
             files:"FileName", paths:"DirectoryTree", hostnames:"ComputerName", ips:"RemoteAddressIP4" } }
];

/* ============================================================
   DEFAULT KQL CONTROLS
   Mirrors the KQL constant: one card per Defender table, with
   column + operator per IOC type that belongs to it.
   ============================================================ */
const DEFAULT_KQL_CONTROLS = [
  { id:"net", name:"DeviceNetworkEvents",
    fields:{
      src_ip:  { col:"RemoteIP",  op:"in~" },
      dest_ip: { col:"RemoteIP",  op:"in~" },
      ips:     { col:"RemoteIP",  op:"in~" },
      domains: { col:"RemoteUrl", op:"has_any" },
      urls:    { col:"RemoteUrl", op:"has_any" }
    }
  },
  { id:"email", name:"EmailEvents",
    fields:{
      emails:         { col:"SenderFromAddress", op:"in~" },
      email_subjects: { col:"Subject",           op:"has_any" }
    }
  },
  { id:"devinfo", name:"DeviceInfo",
    fields:{
      hostnames: { col:"DeviceName", op:"in~" }
    }
  },
  { id:"file", name:"DeviceFileEvents",
    fields:{
      files:  { col:"FileName",   op:"in~" },
      paths:  { col:"FolderPath", op:"in~" },
      md5:    { col:"MD5",        op:"in~" },
      sha1:   { col:"SHA1",       op:"in~" },
      sha256: { col:"SHA256",     op:"in~" }
    }
  },
  { id:"cloudapp", name:"CloudAppEvents",
    fields:{
      user_agents: { col:"UserAgent", op:"has_any" }
    }
  }
];

function loadSplunkControls(cb) {
  chrome.storage.local.get(["splunkControls"], (d) => {
    splunkControls = Array.isArray(d.splunkControls) ? d.splunkControls : [];
    if (cb) cb();
  });
}

/* Render one control card and append it to `container`. */
function renderControlCard(ctrl, container) {
  const card = document.createElement("div");
  card.className = "spl-ctrl-card";
  card.dataset.ctrlId = ctrl.id;

  // ── header: name input + remove button ──────────────────────
  const hdr = document.createElement("div");
  hdr.className = "spl-ctrl-header";

  const nameInp = document.createElement("input");
  nameInp.className = "spl-ctrl-name";
  nameInp.type = "text";
  nameInp.placeholder = "Control name";
  nameInp.value = ctrl.name || "";

  const removeBtn = document.createElement("button");
  removeBtn.className = "mini";
  removeBtn.textContent = "✕ Remove";
  removeBtn.addEventListener("click", () => card.remove());

  hdr.appendChild(nameInp);
  hdr.appendChild(removeBtn);
  card.appendChild(hdr);

  // ── meta: index + sourcetype ─────────────────────────────────
  const meta = document.createElement("div");
  meta.className = "spl-ctrl-meta";

  const mkMetaLabel = txt => { const l = document.createElement("div"); l.className = "spl-ctrl-mlbl"; l.textContent = txt; return l; };
  const mkMetaInp   = (ph, val) => {
    const i = document.createElement("input");
    i.className = "ifc-inp";
    i.type = "text";
    i.placeholder = ph;
    i.value = val || "";
    return i;
  };
  const idxInp = mkMetaInp("index",      ctrl.index      || "");
  const stInp  = mkMetaInp("sourcetype", ctrl.sourcetype || "");
  meta.appendChild(mkMetaLabel("index"));
  meta.appendChild(idxInp);
  meta.appendChild(mkMetaLabel("sourcetype"));
  meta.appendChild(stInp);
  card.appendChild(meta);

  // ── field mappings per IOC type ──────────────────────────────
  const div = document.createElement("div");
  div.className = "spl-ctrl-divider";
  div.textContent = "Field per IOC type  (blank = not covered)";
  card.appendChild(div);

  const fgrid = document.createElement("div");
  fgrid.className = "spl-ctrl-fields";

  for (const type of Object.keys(TITLES)) {
    const lbl = document.createElement("div");
    lbl.className = "spl-ctrl-fl";
    lbl.textContent = TITLES[type];

    const finp = document.createElement("input");
    finp.className = "ifc-inp";
    finp.type = "text";
    finp.dataset.ctrlField = type;
    finp.placeholder = FIELD_DEFAULTS[type] || type;
    finp.value = (ctrl.fields && ctrl.fields[type]) ? ctrl.fields[type] : "";

    fgrid.appendChild(lbl);
    fgrid.appendChild(finp);
  }
  card.appendChild(fgrid);

  // ── stash references for collection ─────────────────────────
  card._nameInp = nameInp;
  card._idxInp  = idxInp;
  card._stInp   = stInp;
  container.appendChild(card);
}

function buildSplControls() {
  const list = document.getElementById("spl-controls-list");
  if (!list) return;
  list.innerHTML = "";
  for (const ctrl of splunkControls) renderControlCard(ctrl, list);
}

/* Collect current UI state into a plain array (called before saving). */
function collectSplControls() {
  const list = document.getElementById("spl-controls-list");
  if (!list) return [];
  const result = [];
  list.querySelectorAll(".spl-ctrl-card").forEach(card => {
    const name = card._nameInp ? card._nameInp.value.trim() : "";
    if (!name) return; // skip nameless cards
    const fields = {};
    card.querySelectorAll("[data-ctrl-field]").forEach(inp => {
      const v = inp.value.trim();
      if (v) fields[inp.dataset.ctrlField] = v;
    });
    result.push({
      id:         card.dataset.ctrlId || ("ctrl_" + Date.now()),
      name,
      index:      card._idxInp ? card._idxInp.value.trim() : "",
      sourcetype: card._stInp  ? card._stInp.value.trim()  : "",
      fields
    });
  });
  return result;
}

/* "+ Add control" button */
const splCtrlAddBtn = document.getElementById("spl-ctrl-add");
if (splCtrlAddBtn) splCtrlAddBtn.addEventListener("click", () => {
  const list = document.getElementById("spl-controls-list");
  if (!list) return;
  renderControlCard({ id: "ctrl_" + Date.now(), name: "", index: "", sourcetype: "", fields: {} }, list);
});

/* "Load defaults" button */
const splCtrlDefaultsBtn = document.getElementById("spl-ctrl-defaults");
if (splCtrlDefaultsBtn) splCtrlDefaultsBtn.addEventListener("click", () => {
  splunkControls = DEFAULT_SPL_CONTROLS.map(c => Object.assign({}, c, { fields: Object.assign({}, c.fields) }));
  buildSplControls();
});

/* "Save" button */
const saveSplControlsBtn = document.getElementById("save-spl-controls");
if (saveSplControlsBtn) saveSplControlsBtn.addEventListener("click", () => {
  splunkControls = collectSplControls();
  chrome.storage.local.set({ splunkControls }, () => {
    const st = document.getElementById("spl-controls-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- category visibility ---------- */
function loadHiddenCats() {
  chrome.storage.local.get(["hiddenCats"], (d) => { hiddenCats = d.hiddenCats || {}; });
}
function buildCategoryToggles() {
  const wrap = document.getElementById("cat-toggles");
  if (!wrap) return;
  chrome.storage.local.get(["hiddenCats"], (d) => {
    const hidden = d.hiddenCats || {};
    wrap.innerHTML = Object.keys(TITLES).map(type =>
      `<label class="toggle"><input type="checkbox" class="cat-cb" data-type="${type}" ${hidden[type] ? "" : "checked"} /><span>${escapeHtml(TITLES[type])}</span></label>`
    ).join("");
  });
}
const catBtn = document.getElementById("save-cats");
if (catBtn) catBtn.addEventListener("click", () => {
  const hidden = {};
  document.querySelectorAll(".cat-cb").forEach(cb => { if (!cb.checked) hidden[cb.dataset.type] = true; });
  chrome.storage.local.set({ hiddenCats: hidden }, () => {
    hiddenCats = hidden;          // update live cache
    renderIOCs();                 // re-render with new visibility
    const st = document.getElementById("cat-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- auto-extract sites ---------- */
function loadAutoExtractUrls() {
  chrome.storage.local.get(["autoExtractUrls"], (d) => {
    autoExtractUrls = Array.isArray(d.autoExtractUrls) ? d.autoExtractUrls : [];
    const ta = document.getElementById("auto-extract-urls");
    if (ta) ta.value = autoExtractUrls.join("\n");
  });
}
const saveAutoExtractUrlsBtn = document.getElementById("save-auto-extract-urls");
if (saveAutoExtractUrlsBtn) saveAutoExtractUrlsBtn.addEventListener("click", () => {
  const ta = document.getElementById("auto-extract-urls");
  autoExtractUrls = (ta ? ta.value : "").split("\n").map(s => s.trim()).filter(s => s && !s.startsWith("#"));
  chrome.storage.local.set({ autoExtractUrls }, () => {
    const st = document.getElementById("auto-extract-urls-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ============================================================
   DEFENDER KQL CONTROLS
   Mirrors the Splunk security controls system: one card per
   Defender table, with column + operator per IOC type.
   Clicking "Defender" generates one sub-query per matching
   table, joined with a blank line between them.
   ============================================================ */
function loadKqlControls(cb) {
  chrome.storage.local.get(["kqlControls"], (d) => {
    kqlControls = Array.isArray(d.kqlControls) ? d.kqlControls : [];
    if (cb) cb();
  });
}

/* Render one KQL control card and append it to `container`. */
function renderKqlControlCard(ctrl, container) {
  const card = document.createElement("div");
  card.className = "spl-ctrl-card";
  card.dataset.ctrlId = ctrl.id;

  // ── header: table name + remove button ──────────────────────
  const hdr = document.createElement("div");
  hdr.className = "spl-ctrl-header";

  const nameInp = document.createElement("input");
  nameInp.className = "spl-ctrl-name";
  nameInp.type = "text";
  nameInp.placeholder = "Table name (e.g. DeviceNetworkEvents)";
  nameInp.value = ctrl.name || "";

  const removeBtn = document.createElement("button");
  removeBtn.className = "mini";
  removeBtn.textContent = "✕ Remove";
  removeBtn.addEventListener("click", () => card.remove());

  hdr.appendChild(nameInp);
  hdr.appendChild(removeBtn);
  card.appendChild(hdr);

  // ── column + operator per IOC type ──────────────────────────
  const div = document.createElement("div");
  div.className = "spl-ctrl-divider";
  div.textContent = "Column + operator per IOC type  (blank = not covered)";
  card.appendChild(div);

  const fgrid = document.createElement("div");
  fgrid.className = "kql-ctrl-fields";

  for (const type of Object.keys(TITLES)) {
    const lbl = document.createElement("div");
    lbl.className = "spl-ctrl-fl";
    lbl.textContent = TITLES[type];
    fgrid.appendChild(lbl);

    const typeData = (ctrl.fields && ctrl.fields[type]) || {};
    const kqlDef   = KQL[type] || {};

    // Column input
    const colInp = document.createElement("input");
    colInp.className = "ifc-inp";
    colInp.type = "text";
    colInp.dataset.kqlCtrlField = type;
    colInp.dataset.kqlCtrlProp  = "col";
    colInp.placeholder = kqlDef.col || "column";
    colInp.value = typeData.col || "";
    fgrid.appendChild(colInp);

    // Operator select
    const sel = document.createElement("select");
    sel.className = "ifc-sel";
    sel.dataset.kqlCtrlField = type;
    sel.dataset.kqlCtrlProp  = "op";
    const currentOp = typeData.op || kqlDef.op || "in~";
    KQL_OPS.forEach(o => {
      const opt = document.createElement("option");
      opt.value = o;
      opt.textContent = o;
      if (o === currentOp) opt.selected = true;
      sel.appendChild(opt);
    });
    fgrid.appendChild(sel);
  }
  card.appendChild(fgrid);

  card._nameInp = nameInp;
  container.appendChild(card);
}

function buildKqlControls() {
  const list = document.getElementById("kql-controls-list");
  if (!list) return;
  list.innerHTML = "";
  for (const ctrl of kqlControls) renderKqlControlCard(ctrl, list);
}

/* Collect current UI state into a plain array (called before saving). */
function collectKqlControls() {
  const list = document.getElementById("kql-controls-list");
  if (!list) return [];
  const result = [];
  list.querySelectorAll(".spl-ctrl-card").forEach(card => {
    const name = card._nameInp ? card._nameInp.value.trim() : "";
    if (!name) return; // skip nameless cards
    const fields = {};
    card.querySelectorAll("[data-kql-ctrl-field]").forEach(el => {
      const type = el.dataset.kqlCtrlField;
      const prop = el.dataset.kqlCtrlProp;
      if (type && prop) {
        if (!fields[type]) fields[type] = {};
        fields[type][prop] = el.value.trim();
      }
    });
    // Only keep types where col is non-empty
    const cleanFields = {};
    Object.entries(fields).forEach(([t, v]) => { if (v.col) cleanFields[t] = v; });
    result.push({
      id:     card.dataset.ctrlId || ("kql_" + Date.now()),
      name,
      fields: cleanFields
    });
  });
  return result;
}

/* "+ Add table" button */
const kqlCtrlAddBtn = document.getElementById("kql-ctrl-add");
if (kqlCtrlAddBtn) kqlCtrlAddBtn.addEventListener("click", () => {
  const list = document.getElementById("kql-controls-list");
  if (!list) return;
  renderKqlControlCard({ id: "kql_" + Date.now(), name: "", fields: {} }, list);
});

/* "Load defaults" button */
const kqlCtrlDefaultsBtn = document.getElementById("kql-ctrl-defaults");
if (kqlCtrlDefaultsBtn) kqlCtrlDefaultsBtn.addEventListener("click", () => {
  kqlControls = DEFAULT_KQL_CONTROLS.map(c => ({
    ...c, fields: Object.fromEntries(Object.entries(c.fields).map(([t, v]) => [t, { ...v }]))
  }));
  buildKqlControls();
});

/* "Save" button */
const saveKqlControlsBtn = document.getElementById("save-kql-controls");
if (saveKqlControlsBtn) saveKqlControlsBtn.addEventListener("click", () => {
  kqlControls = collectKqlControls();
  chrome.storage.local.set({ kqlControls }, () => {
    const st = document.getElementById("kql-controls-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});

/* ---------- excluded (non-collectable) domains ---------- */
function loadExcludedDomains() {
  chrome.storage.local.get(["excludedDomains"], (d) => {
    const list = d.excludedDomains || DEFAULT_EXCLUDED;
    const ta = document.getElementById("excluded-domains");
    if (ta) ta.value = list.join("\n");
  });
}
const exclSave = document.getElementById("save-excluded");
if (exclSave) exclSave.addEventListener("click", () => {
  const ta = document.getElementById("excluded-domains");
  const list = (ta.value || "").split("\n").map(s => s.trim().toLowerCase()).filter(Boolean);
  chrome.storage.local.set({ excludedDomains: list }, () => {
    const st = document.getElementById("excluded-status");
    if (st) { st.textContent = "Saved"; setTimeout(() => st.textContent = "", 2000); }
  });
});
const exclReset = document.getElementById("reset-excluded");
if (exclReset) exclReset.addEventListener("click", () => {
  document.getElementById("excluded-domains").value = DEFAULT_EXCLUDED.join("\n");
  chrome.storage.local.set({ excludedDomains: DEFAULT_EXCLUDED }, () => {
    const st = document.getElementById("excluded-status");
    if (st) { st.textContent = "Reset"; setTimeout(() => st.textContent = "", 2000); }
  });
});

loadHistorySettings();
loadEnrichFields();
loadThresholds();
loadDefaults();
loadHiddenCats();
buildCategoryToggles();
applyDefaultsToExtract();
loadExcludedDomains();
loadIocFieldSettings(buildIocFieldsGrid);
loadKqlSettings(buildKqlGrid);
loadSplunkControls(buildSplControls);
loadKqlControls(buildKqlControls);
loadAutoExtractUrls();

/* Auto-extract toggle: restore its saved state, then (once results are restored)
   kick off an auto-extraction. Persist the box on change. */
(function wireAutoExtract() {
  /* Popup is now open — clear the red notification dot from the icon. */
  try { chrome.action.setBadgeText({ text: "" }); } catch (_) {}

  const box = document.getElementById("auto-extract");
  chrome.storage.local.get("autoExtract", ({ autoExtract: saved }) => {
    autoExtract = saved !== false;          // default ON (the analyst asked for it)
    if (box) box.checked = autoExtract;
    restoreLastExtraction(() => checkBgExtractPending(maybeAutoExtract));
  });
  if (box) box.addEventListener("change", () => {
    autoExtract = box.checked;
    chrome.storage.local.set({ autoExtract });
    if (autoExtract) maybeAutoExtract();    // turning it on extracts the current page now
  });
})();

/* Live sync: keep every open popup.html instance (the workspace tab, a second
   popup, etc.) in step with each other. When any instance writes lastExtraction
   to storage the onChanged event fires in all other instances — re-render there
   so the workspace tab updates the moment the analyst clicks Extract in the popup.
   We skip echoes of our own saves (matched by timestamp) to avoid a no-op
   re-render flicker. */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  /* Another popup instance (or the workspace tab) wrote a fresh lastExtraction. */
  if (changes.lastExtraction) {
    const nv = changes.lastExtraction.newValue;
    if (!nv || !nv.raw) return;
    if (nv.ts && nv.ts === lastOwnSaveTs) return;   // our own write — already rendered
    try {
      state.raw  = (nv.raw && typeof nv.raw === "object") ? nv.raw : {};
      state.encoded = Array.isArray(nv.encoded) ? nv.encoded.filter(e => e && e.blob) : [];
      state.procs   = Array.isArray(nv.procs) ? nv.procs : [];
      lastExtractedUrl = typeof nv.url === "string" ? nv.url : "";
      recomputeRendered();
      renderIOCs();
      renderProcs();
      if (statusEl) {
        const when = nv.ts ? new Date(nv.ts).toLocaleTimeString() : "";
        statusEl.textContent = "Updated" + (when ? " (" + when + ")" : "");
      }
    } catch (err) {
      console.error("[IOC] storage sync failed:", err);
    }
  }
  /* Background service worker stored a raw pageExtract result while no popup
     was open (analyst pressed Ctrl+E globally). Process it now. */
  if (changes.bgExtractPending) {
    const p = changes.bgExtractPending.newValue;
    if (!p || typeof p.text !== "string") return;
    try {
      processIOCs(p.text, p.url || "", p.typed || {}, p.procs || []);
      if (statusEl) {
        const site = p.diag && p.diag.splunk ? " · Splunk"
                   : p.diag && p.diag.defender ? " · Defender" : "";
        const when = p.ts ? new Date(p.ts).toLocaleTimeString() : "";
        statusEl.textContent = "Extracted" + (when ? " (" + when + ")" : "") + site;
      }
    } catch (err) { console.error("[IOC] bgExtractPending sync failed:", err); }
    chrome.storage.local.remove("bgExtractPending");
  }
});

/* ============================================================
   UTILITIES — extra panels
   User-agent parser, bytes size converter, subnet calc + membership check.
   Each panel writes a copy-friendly string to its own <pre>; the side "Copy"
   button on each just lifts that string to the clipboard.
   ============================================================ */

/* ---------- User-agent parser ----------
   Parse one or many UAs (one per line). Returns an array of
   { raw, browser, bver, os, device, engine } objects. */
function parseOneUA(ua) {
  const u = String(ua).trim();
  let browser = "Unknown", bver = "";
  const b = [
    [/(Edg|Edge)\/([\d.]+)/,      "Edge"],
    [/OPR\/([\d.]+)/,             "Opera"],
    [/Brave\/([\d.]+)/,           "Brave"],
    [/Chrome\/([\d.]+)/,          "Chrome"],
    [/Firefox\/([\d.]+)/,         "Firefox"],
    [/Version\/([\d.]+).+Safari/, "Safari"],
    [/MSIE ([\d.]+);/,            "IE"],
    [/Trident.+rv:([\d.]+)/,      "IE"]
  ];
  for (const [re, name] of b) {
    const m = u.match(re);
    if (m) { browser = name; bver = m[2] || m[1] || ""; break; }
  }
  // Short tool UAs (curl/8.4.0, python-requests/2.31, etc.) — pick the prefix.
  if (browser === "Unknown") {
    const t = u.match(/^([A-Za-z][\w.\-]+)\/([\w.\-]+)/);
    if (t) { browser = t[1]; bver = t[2]; }
  }

  let os = "Unknown";
  if      (/Windows NT 10\.0/.test(u))     os = "Windows 10/11";
  else if (/Windows NT 6\.3/.test(u))      os = "Windows 8.1";
  else if (/Windows NT 6\.1/.test(u))      os = "Windows 7";
  else if (/Windows NT ([\d.]+)/.test(u))  os = "Windows " + RegExp.$1;
  else if (/Mac OS X ([\d_\.]+)/.test(u))  os = "macOS " + RegExp.$1.replace(/_/g, ".");
  else if (/Android ([\d.]+)/.test(u))     os = "Android " + RegExp.$1;
  else if (/iPhone OS ([\d_\.]+)/.test(u)) os = "iOS " + RegExp.$1.replace(/_/g, ".");
  else if (/iPad/.test(u))                 os = "iPadOS";
  else if (/CrOS/.test(u))                 os = "ChromeOS";
  else if (/Linux/.test(u))                os = "Linux";

  let device = /Mobi|Android.+Mobile|iPhone/.test(u) ? "Mobile"
             : /Tablet|iPad/.test(u)                 ? "Tablet"
             : /Bot|Crawler|Spider|curl|wget|python-requests/i.test(u) ? "Bot/Tool"
             : "Desktop";

  let engine = "Unknown";
  if      (/Gecko\//.test(u))               engine = "Gecko";
  else if (/AppleWebKit\/([\d.]+)/.test(u)) engine = "WebKit (" + RegExp.$1 + ")";
  else if (/Trident\/([\d.]+)/.test(u))     engine = "Trident " + RegExp.$1;

  return { raw: u, browser, bver, os, device, engine };
}
function parseUA(input) {
  return String(input).split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(parseOneUA);
}
function renderUACards(parsed) {
  if (!parsed.length) return `<div class="hint">(empty)</div>`;
  return parsed.map(p => {
    const browser = p.browser + (p.bver ? " " + p.bver : "");
    return `<div class="enc-item">
      <div class="enc-src">user-agent</div>
      <div class="enc-blob">${escapeHtml(p.raw)}</div>
      <div class="enc-arrow">↓ parsed</div>
      <div class="ua-fields">
        <div class="ua-field"><span class="ua-label">Browser</span><span class="ua-value">${escapeHtml(browser)}</span></div>
        <div class="ua-field"><span class="ua-label">OS</span><span class="ua-value">${escapeHtml(p.os)}</span></div>
        <div class="ua-field"><span class="ua-label">Device</span><span class="ua-value">${escapeHtml(p.device)}</span></div>
        <div class="ua-field"><span class="ua-label">Engine</span><span class="ua-value">${escapeHtml(p.engine)}</span></div>
      </div>
    </div>`;
  }).join("");
}
function uaPlainText(parsed) {
  return parsed.map(p => {
    const lines = [
      `Browser: ${p.browser}${p.bver ? " " + p.bver : ""}`,
      `OS:      ${p.os}`,
      `Device:  ${p.device}`,
      `Engine:  ${p.engine}`,
      `Raw:     ${p.raw}`
    ];
    return lines.join("\n");
  }).join("\n\n");
}

(function wireUA() {
  const runBtn = document.getElementById("ua-run");
  if (!runBtn) return;
  const inEl = document.getElementById("ua-in");
  const outEl = document.getElementById("ua-out");
  let lastParsed = [];
  runBtn.addEventListener("click", () => {
    lastParsed = parseUA(inEl.value);
    outEl.innerHTML = renderUACards(lastParsed);
  });
  document.getElementById("ua-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(uaPlainText(lastParsed));
    flashBtn(document.getElementById("ua-copy"), "✓");
  });
})();

/* ---------- Bytes size converter ----------
   Single purpose: convert a byte count (with optional unit suffix) into every
   common storage unit. 1024-based — analysts almost always mean binary KB/MB
   when reading log/file sizes. Accepts:
     1024                bare number = bytes
     5 MB                number + unit
     2.5GB / 2.5 gb      space optional, case insensitive
     1_073_741_824       underscores and commas allowed as thousand separators
*/
function bytesConvert(raw) {
  const s = String(raw).trim();
  if (!s) return "(empty)";

  const m = s.match(/^([\d_,.\s]+?)\s*([KMGTPE]?B?)\s*$/i);
  if (!m) return "Examples: 1024  •  5 MB  •  2.5 GB";

  const num = parseFloat(m[1].replace(/[_,\s]/g, ""));
  if (!isFinite(num) || num < 0) return "Invalid number";

  const u = (m[2] || "B").toUpperCase();
  const power = { "B":0, "KB":1, "MB":2, "GB":3, "TB":4, "PB":5, "EB":6,
                  "K":1, "M":2, "G":3, "T":4, "P":5, "E":6 }[u];
  if (power === undefined) return "Unknown unit (use B/KB/MB/GB/TB/PB)";

  const bytes = num * Math.pow(1024, power);

  // Pick the "natural" unit for a friendly auto-line at the end
  const units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
  let v = bytes, ui = 0;
  while (v >= 1024 && ui < units.length - 1) { v /= 1024; ui++; }
  const auto = `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[ui]}`;

  const fmt = (n, decimals) => {
    if (n === 0) return "0";
    if (n < 0.000001) return n.toExponential(3);
    return n.toFixed(decimals).replace(/\.?0+$/, "");
  };

  // Human-relatable comparisons. Reference sizes are rough industry averages —
  // a smartphone JPEG runs 2-5 MB, a 3-min MP3 at 192 kbps ~6 MB, etc.
  const REFS = [
    { lo: 1,             plural: "characters of plain text" },     // 1 B each
    { lo: 5,             plural: "English words" },                 // ~5 B each (incl space)
    { lo: 2 * 1024,      plural: "pages of plain text" },           // ~2 KB / page
    { lo: 75 * 1024,     plural: "average emails (HTML)" },         // ~75 KB
    { lo: 3 * 1024**2,   plural: "smartphone photos" },             // ~3 MB JPEG
    { lo: 6 * 1024**2,   plural: "MP3 songs (3-4 min @ 192 kbps)" },// ~6 MB
    { lo: 75 * 1024**2,  plural: "minutes of 1080p video" },        // ~75 MB/min
    { lo: 350 * 1024**2, plural: "minutes of 4K video" },           // ~350 MB/min
    { lo: 6.5 * 1024**3, plural: "1080p movies (~90 min)" },        // ~6.5 GB
    { lo: 30 * 1024**3,  plural: "4K movies (~90 min)" }            // ~30 GB
  ];
  const compareLines = [];
  for (const ref of REFS) {
    const n = bytes / ref.lo;
    if (n < 0.1) continue;
    let shown;
    if      (n < 1)    shown = n.toFixed(2);
    else if (n < 10)   shown = n.toFixed(1);
    else               shown = Math.round(n).toLocaleString("en-US");
    compareLines.push(`  ~${shown} ${ref.plural}`);
  }

  const out = [
    `Input:   ${num} ${u}`,
    ``,
    `Bytes:   ${Math.round(bytes).toLocaleString("en-US")}`,
    `KB:      ${fmt(bytes / 1024, 3)}`,
    `MB:      ${fmt(bytes / 1024**2, 3)}`,
    `GB:      ${fmt(bytes / 1024**3, 6)}`,
    `TB:      ${fmt(bytes / 1024**4, 9)}`,
    `PB:      ${fmt(bytes / 1024**5, 12)}`,
    ``,
    `Human:   ${auto}`
  ];
  if (compareLines.length) {
    out.push("");
    out.push("Roughly equivalent to:");
    out.push(...compareLines);
  }
  return out.join("\n");
}

(function wireBC() {
  const runBtn = document.getElementById("bc-run");
  if (!runBtn) return;
  const inEl = document.getElementById("bc-in");
  const outEl = document.getElementById("bc-out");
  runBtn.addEventListener("click", () => { outEl.textContent = bytesConvert(inEl.value); });
  document.getElementById("bc-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(outEl.textContent || "");
    flashBtn(document.getElementById("bc-copy"), "✓");
  });
})();

/* ---------- Subnet calculator ----------
   Accepts: "10.0.0.0/24", "10.0.0.5/24", or "10.0.0.5 255.255.255.0". */
function ipToInt(ip) {
  const parts = String(ip).trim().split(".");
  if (parts.length !== 4) throw new Error("bad IP");
  let n = 0;
  for (const p of parts) {
    const o = +p;
    if (!(o >= 0 && o <= 255) || !/^\d+$/.test(p)) throw new Error("bad IP octet");
    n = (n * 256) + o;
  }
  return n;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
function maskToCidr(mask) {
  const n = ipToInt(mask);
  const bits = (n >>> 0).toString(2);
  if (!/^1*0*$/.test(bits.padStart(32, "0"))) throw new Error("non-contiguous mask");
  return bits.replace(/0/g, "").length;
}
function subnetCalc(input) {
  let ipStr, cidr;
  const s = String(input).trim();
  let m;
  if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)\s*\/\s*(\d{1,2})$/))) { ipStr = m[1]; cidr = +m[2]; }
  else if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/))) { ipStr = m[1]; cidr = maskToCidr(m[2]); }
  else throw new Error("expected CIDR (10.0.0.0/24) or IP + mask");

  if (cidr < 0 || cidr > 32) throw new Error("bad prefix length");
  const ip = ipToInt(ipStr);
  const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = cidr === 32 ? 1 : 2 ** (32 - cidr);
  const usable = total <= 2 ? total : total - 2;
  const wildcardMask = (~mask) >>> 0;
  const firstHost = usable < total ? (network + 1) >>> 0 : network;
  const lastHost  = usable < total ? (broadcast - 1) >>> 0 : broadcast;

  const cls = ip < 0x80000000 ? "A"
           : ip < 0xC0000000 ? "B"
           : ip < 0xE0000000 ? "C"
           : ip < 0xF0000000 ? "D (multicast)" : "E (reserved)";
  // Private ranges (RFC1918) + 127/8 loopback + 169.254/16 link-local
  const inRange = (lo, hi) => ip >= lo && ip <= hi;
  let scope = "public";
  if      (inRange(ipToInt("10.0.0.0"),  ipToInt("10.255.255.255"))) scope = "private (10.0.0.0/8)";
  else if (inRange(ipToInt("172.16.0.0"),ipToInt("172.31.255.255"))) scope = "private (172.16.0.0/12)";
  else if (inRange(ipToInt("192.168.0.0"),ipToInt("192.168.255.255"))) scope = "private (192.168.0.0/16)";
  else if (inRange(ipToInt("127.0.0.0"), ipToInt("127.255.255.255"))) scope = "loopback (127.0.0.0/8)";
  else if (inRange(ipToInt("169.254.0.0"),ipToInt("169.254.255.255"))) scope = "link-local";
  else if (inRange(ipToInt("224.0.0.0"), ipToInt("239.255.255.255"))) scope = "multicast";

  return [
    `Input:        ${ipStr}/${cidr}`,
    `Network:      ${intToIp(network)}/${cidr}`,
    `Netmask:      ${intToIp(mask)}`,
    `Wildcard:     ${intToIp(wildcardMask)}`,
    `Broadcast:    ${intToIp(broadcast)}`,
    `First host:   ${intToIp(firstHost)}`,
    `Last host:    ${intToIp(lastHost)}`,
    `Total addrs:  ${total.toLocaleString()}`,
    `Usable hosts: ${usable.toLocaleString()}`,
    `Class:        ${cls}`,
    `Scope:        ${scope}`
  ].join("\n");
}

(function wireSubnet() {
  const runBtn = document.getElementById("sn-run");
  if (!runBtn) return;
  const inEl = document.getElementById("sn-in");
  const outEl = document.getElementById("sn-out");
  runBtn.addEventListener("click", () => {
    try { outEl.textContent = subnetCalc(inEl.value); }
    catch (e) { outEl.textContent = "Error: " + e.message; }
  });
  document.getElementById("sn-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(outEl.textContent || "");
    flashBtn(document.getElementById("sn-copy"), "✓");
  });
})();

/* ---------- Subnet membership check ----------
   Parse a network as CIDR, IP+mask, or "from - to" range; derive a
   [network..broadcast] interval, then test each input IP. A range need not
   be CIDR-aligned (e.g. 10.0.0.5 – 10.0.0.30 is allowed). */
function parseNetwork(netStr) {
  const s = String(netStr).trim();
  let m;

  // Range: "ip - ip", "ip – ip", "ip to ip", "ip..ip"
  if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)\s*(?:-|–|—|\.\.|to)\s*(\d+\.\d+\.\d+\.\d+)$/i))) {
    const from = ipToInt(m[1]);
    const to   = ipToInt(m[2]);
    if (from > to) throw new Error("range start must be ≤ end");
    return { kind: "range", input: `${m[1]} – ${m[2]}`, network: from, broadcast: to };
  }

  // CIDR
  if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)\s*\/\s*(\d{1,2})$/))) {
    const cidr = +m[2];
    if (cidr < 0 || cidr > 32) throw new Error("bad prefix length");
    const ip = ipToInt(m[1]);
    const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
    return {
      kind: "cidr",
      input: m[1], cidr, mask,
      network:   (ip & mask) >>> 0,
      broadcast: ((ip & mask) | (~mask >>> 0)) >>> 0
    };
  }

  // IP + mask
  if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/))) {
    const cidr = maskToCidr(m[2]);
    const ip   = ipToInt(m[1]);
    const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
    return {
      kind: "cidr",
      input: m[1], cidr, mask,
      network:   (ip & mask) >>> 0,
      broadcast: ((ip & mask) | (~mask >>> 0)) >>> 0
    };
  }

  throw new Error("network must be CIDR (172.16.1.0/24), IP + mask, or 'from - to'");
}

function subnetMembership(ipsRaw, netRaw) {
  const net = parseNetwork(netRaw);
  const ips = String(ipsRaw).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!ips.length) throw new Error("enter at least one IP");

  const lines = [];
  const total = net.broadcast - net.network + 1;
  if (net.kind === "range") {
    lines.push(`Range: ${intToIp(net.network)} – ${intToIp(net.broadcast)}  (${total.toLocaleString()} addrs)`);
  } else {
    lines.push(`Network: ${intToIp(net.network)}/${net.cidr}  ` +
               `(range ${intToIp(net.network)} – ${intToIp(net.broadcast)}, ` +
               `mask ${intToIp(net.mask)})`);
    if (net.input !== intToIp(net.network)) {
      lines.push(`  note: input "${net.input}/${net.cidr}" normalises to ${intToIp(net.network)}/${net.cidr}`);
    }
  }
  lines.push("");

  let inside = 0, outside = 0, bad = 0;
  for (const ip of ips) {
    try {
      const n = ipToInt(ip);
      const ok = n >= net.network && n <= net.broadcast;
      if (ok) inside++; else outside++;
      lines.push(`${ok ? "✓ IN " : "✗ OUT"}  ${ip}`);
    } catch (e) {
      bad++;
      lines.push(`?      ${ip}   (invalid: ${e.message})`);
    }
  }

  lines.push("");
  lines.push(`Summary: ${inside} in, ${outside} out` + (bad ? `, ${bad} invalid` : ""));
  return lines.join("\n");
}

(function wireSubnetMembership() {
  const runBtn = document.getElementById("sm-run");
  if (!runBtn) return;
  const ipsEl = document.getElementById("sm-ips");
  const netEl = document.getElementById("sm-net");
  const outEl = document.getElementById("sm-out");
  runBtn.addEventListener("click", () => {
    try { outEl.textContent = subnetMembership(ipsEl.value, netEl.value); }
    catch (e) { outEl.textContent = "Error: " + e.message; }
  });
  document.getElementById("sm-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(outEl.textContent || "");
    flashBtn(document.getElementById("sm-copy"), "✓");
  });
})();

/* ============================================================
   REDACTION — Settings persistence + Extract toggle state
   ============================================================ */
function loadRedaction() {
  chrome.storage.local.get(["redactCfg", "redactOn"], (d) => {
    redactCfg = Object.assign({ list: [], isRegex: false, replacement: "<redacted>" }, d.redactCfg || {});
    const listEl = document.getElementById("redact-list");
    const regexEl = document.getElementById("redact-regex");
    const replEl  = document.getElementById("redact-replacement");
    if (listEl)  listEl.value  = (redactCfg.list || []).join("\n");
    if (regexEl) regexEl.checked = !!redactCfg.isRegex;
    if (replEl)  replEl.value  = redactCfg.replacement || "<redacted>";
    if (redactEl) redactEl.checked = !!d.redactOn;
  });
}
const saveRedactBtn = document.getElementById("save-redact");
if (saveRedactBtn) saveRedactBtn.addEventListener("click", () => {
  const listEl = document.getElementById("redact-list");
  const regexEl = document.getElementById("redact-regex");
  const replEl  = document.getElementById("redact-replacement");
  redactCfg = {
    list: (listEl.value || "").split("\n").map(s => s.trim()).filter(Boolean),
    isRegex: !!regexEl.checked,
    replacement: replEl.value || "<redacted>"
  };
  chrome.storage.local.set({ redactCfg }, () => {
    const st = document.getElementById("redact-status");
    if (st) { st.textContent = `Saved (${redactCfg.list.length} pattern${redactCfg.list.length===1?"":"s"})`; setTimeout(() => st.textContent = "", 2000); }
    // Reflect immediately if the toggle is already on
    if (redactEl && redactEl.checked) { recomputeRendered(); renderIOCs(); }
  });
});
// Persist the Extract-tab toggle so it survives popup re-open
if (redactEl) redactEl.addEventListener("change", () => {
  chrome.storage.local.set({ redactOn: redactEl.checked });
});
loadRedaction();

/* ============================================================
   REDACTOR UTILITY
   Applies the saved redaction patterns to arbitrary pasted text —
   same patterns as the Redact toggle, but without requiring a live
   extraction. Useful for sanitising paste-outs before sharing.
   ============================================================ */
(function wireRedactor() {
  const inEl  = document.getElementById("rd-in");
  const outEl = document.getElementById("rd-out");
  const runBtn  = document.getElementById("rd-run");
  const copyBtn = document.getElementById("rd-copy");
  const clrBtn  = document.getElementById("rd-clear");
  if (!runBtn) return;

  // Apply redactCfg patterns without requiring the Redact checkbox to be on.
  function redactText(s) {
    if (!redactCfg.list.length) return s;
    let out = String(s);
    for (const pat of redactCfg.list) {
      if (!pat) continue;
      try {
        const re = redactCfg.isRegex
          ? new RegExp(pat, "gi")
          : new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
        out = out.replace(re, redactCfg.replacement || "<redacted>");
      } catch (_) {}
    }
    return out;
  }

  runBtn.addEventListener("click", () => {
    if (!inEl || !outEl) return;
    if (!redactCfg.list.length) {
      outEl.textContent = "(No redaction patterns saved — add them in Settings → Redaction.)";
      return;
    }
    outEl.textContent = redactText(inEl.value);
  });
  if (copyBtn) copyBtn.addEventListener("click", () => {
    const txt = outEl ? outEl.textContent : "";
    if (!txt) return;
    navigator.clipboard.writeText(txt).then(() => flashBtn(copyBtn, "Copied"));
  });
  if (clrBtn) clrBtn.addEventListener("click", () => {
    if (inEl)  inEl.value = "";
    if (outEl) outEl.textContent = "";
  });
})();

/* ============================================================
   FIND / REPLACE  (Ctrl+F = find-only, Ctrl+H = find+replace)
   Works in every <textarea> and text <input> in the popup.
   The floating panel pins to the bottom of the viewport.
   ============================================================ */
(function wireFindReplace() {
  let frTarget  = null;   // the textarea/input currently being searched
  let frMatches = [];     // [{start,end}] all match positions in frTarget.value
  let frIdx     = -1;     // which match is selected right now

  const panel   = document.getElementById("fr-panel");
  const findEl  = document.getElementById("fr-find");
  const replRow = document.getElementById("fr-repl-row");
  const replEl  = document.getElementById("fr-repl");
  const countEl = document.getElementById("fr-count");
  if (!panel || !findEl) return;

  function openPanel(el) {
    frTarget = el;
    panel.hidden = false;
    document.body.classList.add("fr-open");
    // Pre-fill the find box with the current selection (if any) — just like
    // every real editor does when you press Ctrl+F with text highlighted.
    if (el && el.selectionStart !== el.selectionEnd) {
      const sel = el.value.slice(el.selectionStart, el.selectionEnd);
      if (sel) { findEl.value = sel; frIdx = 0; }
    }
    findEl.focus();
    findEl.select();
    updateMatches();
  }

  function closePanel() {
    panel.hidden = true;
    document.body.classList.remove("fr-open");
    if (frTarget) { try { frTarget.focus(); } catch (_) {} }
    frTarget = null; frMatches = []; frIdx = -1;
    if (countEl) countEl.textContent = "";
  }

  function updateMatches() {
    const term = findEl.value;
    if (!frTarget || !term) {
      frMatches = []; frIdx = -1;
      if (countEl) countEl.textContent = term ? "no match" : "";
      return;
    }
    const text  = frTarget.value;
    const lower = text.toLowerCase();
    const tLow  = term.toLowerCase();
    frMatches = [];
    let i = 0;
    while (i < text.length) {
      const pos = lower.indexOf(tLow, i);
      if (pos === -1) break;
      frMatches.push({ start: pos, end: pos + term.length });
      i = pos + term.length || pos + 1;
    }
    // Try to keep the current logical position; fall back to first.
    frIdx = frMatches.length ? Math.min(Math.max(frIdx, 0), frMatches.length - 1) : -1;
    jumpTo();
  }

  function jumpTo() {
    if (!frTarget || frIdx < 0 || !frMatches.length) {
      if (countEl) countEl.textContent = frMatches.length ? `?/${frMatches.length}` : "no match";
      return;
    }
    const m = frMatches[frIdx];
    frTarget.focus();
    frTarget.setSelectionRange(m.start, m.end);
    if (countEl) countEl.textContent = `${frIdx + 1}/${frMatches.length}`;
  }

  function next() { if (!frMatches.length) return; frIdx = (frIdx + 1) % frMatches.length; jumpTo(); }
  function prev() { if (!frMatches.length) return; frIdx = (frIdx - 1 + frMatches.length) % frMatches.length; jumpTo(); }

  function replaceOne() {
    if (!frTarget || frIdx < 0 || !frMatches.length) return;
    const m = frMatches[frIdx];
    const rv = replEl ? replEl.value : "";
    frTarget.value = frTarget.value.slice(0, m.start) + rv + frTarget.value.slice(m.end);
    // After replacement, recompute from the same logical position.
    const keepIdx = frIdx;
    updateMatches();
    frIdx = Math.min(keepIdx, frMatches.length - 1);
    jumpTo();
  }

  function replaceAll() {
    if (!frTarget || !findEl.value) return;
    const term = findEl.value;
    const rv   = replEl ? replEl.value : "";
    const re   = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    frTarget.value = frTarget.value.replace(re, rv);
    frIdx = 0;
    updateMatches();
  }

  // Ctrl+F = find, Ctrl+H = find+replace.
  // preventDefault() must be called BEFORE any early return — otherwise Chrome
  // gets Ctrl+H and opens history before the popup's JS can act on it.
  document.addEventListener("keydown", e => {
    if (!e.ctrlKey) return;
    const key = e.key.toLowerCase();
    if (key !== "f" && key !== "h") return;
    e.preventDefault();   // ← stop Chrome opening find-bar / history first
    const t = document.activeElement;
    const isText = t && (t.tagName === "TEXTAREA" ||
      (t.tagName === "INPUT" && t.type !== "checkbox" && t.type !== "radio" && t.type !== "range"));
    if (!isText && panel.hidden) return;
    if (isText) frTarget = t;
    openPanel(frTarget || t);
  }, true);

  // Panel controls
  findEl.addEventListener("input", () => { frIdx = 0; updateMatches(); });
  findEl.addEventListener("keydown", e => {
    if (e.key === "Enter")  { e.preventDefault(); e.shiftKey ? prev() : next(); }
    if (e.key === "Escape") { e.preventDefault(); closePanel(); }
  });
  if (replEl) replEl.addEventListener("keydown", e => {
    if (e.key === "Enter")  { e.preventDefault(); replaceOne(); }
    if (e.key === "Escape") { e.preventDefault(); closePanel(); }
  });
  document.getElementById("fr-prev")?.addEventListener("click", prev);
  document.getElementById("fr-next")?.addEventListener("click", next);
  document.getElementById("fr-close")?.addEventListener("click", closePanel);
  document.getElementById("fr-repl-one")?.addEventListener("click", replaceOne);
  document.getElementById("fr-repl-all")?.addEventListener("click", replaceAll);
})();

/* ============================================================
   ALL-IOCS EDITABLE PANE
   Mirrors state.rendered as plain text grouped by "## TITLE".
   Edits flow back via parseAllPane() on "Apply edits".
   ============================================================ */
const allPaneEl    = document.getElementById("all-pane");
const allCopyBtn   = document.getElementById("all-copy");
const allRevertBtn = document.getElementById("all-revert");
const allStatusEl  = document.getElementById("all-status");

let allPaneDirty = false;      // user has typed in the pane since the last sync
let allPaneBaseValues = null;  // stripped bare values when in custom-text mode; null = mirrors IOCs

/* Strip active formatting (wildcards, quotes, number prefix) from each line so we
   can hold onto the bare values and reapply different formatting when toggles change. */
function stripAllFormatting(text) {
  return text.split(/\r?\n/).map(line => {
    let v = line;
    v = v.replace(/^\d+\.\s*/, "");                                          // "1. value"
    if ((v.startsWith('"') && v.endsWith('"')) ||
        (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);         // "value" / 'value'
    if (v.startsWith("*")) v = v.slice(1);                                   // *value
    if (v.endsWith("*"))   v = v.slice(0, -1);                               // value*
    return v;
  }).filter(v => v.trim() !== "");
}

/* Apply all active output toggles to an array of bare values, same logic as formatListLines. */
function applyOutputFormat(bareArr) {
  let items = bareArr.slice();
  const pre = wildcardPreEl && wildcardPreEl.checked;
  const suf = wildcardSufEl && wildcardSufEl.checked;
  if (pre || suf) items = items.map(v => `${pre ? "*" : ""}${v}${suf ? "*" : ""}`);
  if (singleQuotedEl && singleQuotedEl.checked) items = items.map(v => `'${v}'`);
  else if (quotedEl && quotedEl.checked)         items = items.map(v => `"${v}"`);
  if (numberEl && numberEl.checked) items = items.map((v, i) => `${i + 1}. ${v}`);
  return items;
}

if (allPaneEl) allPaneEl.addEventListener("input", () => {
  allPaneDirty = true;
  allPaneBaseValues = stripAllFormatting(allPaneEl.value);
  if (allStatusEl) allStatusEl.textContent = "custom text — toggles apply · Revert restores IOCs";
});

/* Build the All IOCs pane text.
   - Two modes governed by the Settings "Category headers" toggle:
       OFF (default): one flat deduplicated list, joined by the current Separator.
       ON: one block per category, prefixed with "=== TITLE (N) ===", with
           cross-category dedup OFF so the same IP shown both in SRC IP and IPS
           appears under each header (analyst wants to see which category each
           value lives in). Like the "Copy all enriched" output style.
   - Sanitize/Defang/Redact have already been applied in state.rendered.
   - Numbered + Quote-each are applied per category in headers mode, globally
     in flat mode. */
function renderAllPaneText() {
  const rendered = state.rendered || {};
  const formatItems = (arr) => {
    let items = arr;
    const pre = wildcardPreEl && wildcardPreEl.checked;
    const suf = wildcardSufEl && wildcardSufEl.checked;
    if (pre || suf) items = items.map(v => `${pre ? "*" : ""}${v}${suf ? "*" : ""}`);
    if (singleQuotedEl && singleQuotedEl.checked) items = items.map(v => `'${v}'`);
    else if (quotedEl && quotedEl.checked)         items = items.map(v => `"${v}"`);
    if (numberEl && numberEl.checked) items = items.map((v, i) => `${i + 1}. ${v}`);
    return items;
  };

  if (includeHeaders) {
    const blocks = [];
    for (const type of Object.keys(TITLES)) {
      if (hiddenCats[type]) continue;
      const vals = (rendered[type] || []).filter(Boolean);
      if (!vals.length) continue;
      const items = formatItems(vals);
      blocks.push(`=== ${TITLES[type]} (${vals.length}) ===\n${items.join(getSeparator())}`);
    }
    return blocks.join("\n\n");
  }

  // Flat: dedupe across categories
  const seen = new Set();
  const values = [];
  for (const type of Object.keys(TITLES)) {
    if (hiddenCats[type]) continue;
    for (const v of (rendered[type] || [])) {
      const s = String(v);
      if (seen.has(s)) continue;
      seen.add(s);
      values.push(s);
    }
  }
  return formatItems(values).join(getSeparator());
}

function syncAllPane() {
  if (!allPaneEl) return;
  if (allPaneDirty) return; // preserve user's in-progress edits
  allPaneEl.value = renderAllPaneText();
}

if (allCopyBtn) allCopyBtn.addEventListener("click", (e) => {
  // Button lives inside <summary>, so the default <details> toggle would fire.
  // Stop both so clicking Copy doesn't expand/collapse the section.
  e.preventDefault();
  e.stopPropagation();
  // The textarea reflects the formatted pane when the section is collapsed,
  // but its `.value` is only populated when syncAllPane has run. Force a sync
  // so Copy works even if the section has never been opened.
  if (allPaneEl && (!allPaneEl.value || !allPaneDirty)) {
    try { allPaneDirty = false; syncAllPane(); } catch (_) {}
  }
  navigator.clipboard.writeText(allPaneEl.value || "");
  flashBtn(allCopyBtn, "✓");
});

if (allRevertBtn) allRevertBtn.addEventListener("click", () => {
  allPaneDirty = false;
  allPaneBaseValues = null;
  syncAllPane();
  if (allStatusEl) { allStatusEl.textContent = "refreshed"; setTimeout(() => allStatusEl.textContent = "", 1200); }
});

setTimeout(syncAllPane, 0);

/* ============================================================
   CSV / JSON EXPORT
   ============================================================ */

function csvEscape(cell) {
  const s = String(cell == null ? "" : cell);
  return (s.includes(",") || s.includes('"') || s.includes("\n"))
    ? '"' + s.replace(/"/g, '""') + '"'
    : s;
}

function buildCsv(fmt) {
  const rendered = state.rendered || {};
  const rows = [];

  if (fmt === "grouped") {
    rows.push(["type", "values..."].map(csvEscape).join(","));
    for (const [type, vals] of Object.entries(rendered)) {
      if (!vals || !vals.length) continue;
      rows.push([type, ...vals].map(csvEscape).join(","));
    }
  } else {
    // flat — one row per indicator
    rows.push(["type", "value"].map(csvEscape).join(","));
    for (const [type, vals] of Object.entries(rendered)) {
      for (const v of (vals || [])) {
        rows.push([type, v].map(csvEscape).join(","));
      }
    }
  }

  return rows.join("\n");
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function updateExportPreview() {
  const pre = document.getElementById("export-preview");
  if (!pre) return;
  const fmt = document.getElementById("export-fmt")?.value || "flat";
  const csv = buildCsv(fmt);
  if (!csv) { pre.textContent = "(no IOCs extracted)"; return; }
  const lines = csv.split("\n");
  pre.textContent = lines.slice(0, 10).join("\n") +
    (lines.length > 10 ? `\n… (${lines.length - 1} total rows)` : "");
}

(function wireExport() {
  const group = document.getElementById("export-group");
  if (group) group.addEventListener("toggle", e => { if (e.target.open) updateExportPreview(); });

  document.getElementById("export-fmt")?.addEventListener("change", updateExportPreview);

  document.getElementById("export-csv-dl")?.addEventListener("click", () => {
    const csv = buildCsv(document.getElementById("export-fmt")?.value || "flat");
    if (!csv || csv === "type,value") { alert("No IOCs to export."); return; }
    downloadFile(csv, "socmate-iocs.csv", "text/csv;charset=utf-8");
  });

  document.getElementById("export-json-dl")?.addEventListener("click", () => {
    const rendered = state.rendered || {};
    if (!Object.values(rendered).some(a => a && a.length)) { alert("No IOCs to export."); return; }
    downloadFile(JSON.stringify(rendered, null, 2), "socmate-iocs.json", "application/json");
  });

  document.getElementById("export-csv-copy")?.addEventListener("click", () => {
    const csv = buildCsv(document.getElementById("export-fmt")?.value || "flat");
    navigator.clipboard.writeText(csv || "");
    flashBtn(document.getElementById("export-csv-copy"), "✓ Copied");
  });

  // Quick CSV button next to "Refresh from cards"
  document.getElementById("all-export-csv")?.addEventListener("click", () => {
    const csv = buildCsv("flat");
    if (!csv || csv === "type,value") { alert("No IOCs to export."); return; }
    downloadFile(csv, "socmate-iocs.csv", "text/csv;charset=utf-8");
  });
})();

/* ============================================================
   YARA RULE BUILDER
   ============================================================ */

const YARA_STRING_TYPES = [
  { type: "files",          label: "Files",          prefix: "file" },
  { type: "paths",          label: "Paths",          prefix: "path" },
  { type: "domains",        label: "Domains",        prefix: "net"  },
  { type: "urls",           label: "URLs",           prefix: "net"  },
  { type: "src_ip",         label: "SRC IPs",        prefix: "ip"   },
  { type: "dest_ip",        label: "DEST IPs",       prefix: "ip"   },
  { type: "ips",            label: "IPs",            prefix: "ip"   },
  { type: "hostnames",      label: "Hostnames",      prefix: "host" },
  { type: "email_subjects", label: "Email subjects", prefix: "subj" },
];
const YARA_HASH_TYPES = [
  { type: "md5",    fn: "md5"    },
  { type: "sha1",   fn: "sha1"   },
  { type: "sha256", fn: "sha256" },
];

function initYaraCats() {
  const container = document.getElementById("yara-cats");
  if (!container) return;
  const rendered = state.rendered || {};
  container.innerHTML = "";

  const allTypes = [...YARA_STRING_TYPES, ...YARA_HASH_TYPES.map(h => ({ type: h.type, label: h.type.toUpperCase() }))];
  for (const { type, label } of allTypes) {
    const cnt   = (rendered[type] || []).length;
    const lbl   = document.createElement("label");
    lbl.className = "rule-cat" + (cnt === 0 ? " empty" : "");
    const inp   = document.createElement("input");
    inp.type = "checkbox";
    inp.dataset.type = type;
    inp.checked  = cnt > 0;
    inp.disabled = cnt === 0;
    lbl.appendChild(inp);
    lbl.appendChild(document.createTextNode(` ${label} (${cnt})`));
    container.appendChild(lbl);
  }
}

function buildYaraRule() {
  const nameRaw  = (document.getElementById("yara-name")?.value  || "SOCMate_IOC_Hunt").trim();
  const ruleName = nameRaw.replace(/[^A-Za-z0-9_]/g, "_") || "SOCMate_IOC_Hunt";
  const nocase   = document.getElementById("yara-nocase")?.checked;
  const wide     = document.getElementById("yara-wide")?.checked;
  const condVal  = document.getElementById("yara-cond")?.value || "any";

  const rendered = state.rendered || {};
  const today    = new Date().toISOString().slice(0, 10);

  // Collect selected types from the checkboxes
  const included = new Set();
  document.querySelectorAll("#yara-cats input[type=checkbox]").forEach(cb => {
    if (cb.checked) included.add(cb.dataset.type);
  });

  // ---- Build strings: ----
  const strLines = [];
  let idx = 1;

  for (const { type, prefix } of YARA_STRING_TYPES) {
    if (!included.has(type)) continue;
    const isNet = (prefix === "ip" || prefix === "net");
    const mods  = [
      "ascii",
      (!isNet && wide) ? "wide" : null,
      nocase ? "nocase" : null,
    ].filter(Boolean).join(" ");

    for (const v of (rendered[type] || [])) {
      if (!v) continue;
      strLines.push(`        $s${idx++} = ${JSON.stringify(String(v))} ${mods}`);
    }
  }

  // ---- Build hash conditions: ----
  const hashConds = [];
  for (const { type, fn } of YARA_HASH_TYPES) {
    if (!included.has(type)) continue;
    for (const h of (rendered[type] || [])) {
      if (!h) continue;
      hashConds.push(`hash.${fn}(0, filesize) == "${h.toLowerCase()}"`);
    }
  }

  if (!strLines.length && !hashConds.length) {
    return `/* No IOCs selected or extracted.\n   Extract IOCs first, then open YARA builder. */`;
  }

  const cves = (rendered.cves || []);
  let rule = "";
  if (hashConds.length) rule += `import "hash"\n\n`;

  rule += `rule ${ruleName}\n`;
  rule += `{\n`;
  rule += `    meta:\n`;
  rule += `        description = "IOC hunt — generated by SOC Mate"\n`;
  rule += `        date        = "${today}"\n`;
  if (cves.length) rule += `        references  = "${cves.join(", ")}"\n`;

  if (strLines.length) {
    rule += `\n    strings:\n`;
    rule += strLines.join("\n") + "\n";
  }

  rule += `\n    condition:\n`;

  const condParts = [];
  if (strLines.length) {
    condParts.push(
      condVal === "all"  ? "all of them" :
      condVal === "half" ? `${Math.ceil(strLines.length / 2)} of them` :
      "any of them"
    );
  }
  if (hashConds.length) {
    condParts.push(hashConds.join(" or\n        "));
  }

  if (condParts.length === 1) {
    rule += `        ${condParts[0]}\n`;
  } else {
    rule += `        (${condParts[0]}) or\n        (${condParts[1]})\n`;
  }

  rule += `}`;
  return rule;
}

(function wireYara() {
  const group = document.getElementById("yara-group");
  if (group) group.addEventListener("toggle", e => { if (e.target.open) initYaraCats(); });

  document.getElementById("yara-build")?.addEventListener("click", () => {
    initYaraCats();                                          // refresh counts in case IOCs changed
    const out = document.getElementById("yara-out");
    if (out) out.textContent = buildYaraRule();
  });

  document.getElementById("yara-copy")?.addEventListener("click", () => {
    const out = document.getElementById("yara-out");
    if (!out?.textContent) return;
    navigator.clipboard.writeText(out.textContent);
    flashBtn(document.getElementById("yara-copy"), "✓ Copied");
  });
})();

/* ============================================================
   EMAIL HEADER ANALYSER
   ============================================================ */

function parseEmailHeaders(raw) {
  /* 1. Unfold RFC-2822 folded header lines */
  const unfolded = raw.replace(/\r?\n([ \t]+)/g, ' ');

  /* 2. Split into name / value pairs */
  const headers = [];
  for (const line of unfolded.split(/\r?\n/)) {
    const m = line.match(/^([\w!#$%&'*+\-.^`{|}~]+)\s*:\s*(.*)/);
    if (m) headers.push({ name: m[1].toLowerCase(), raw: m[1], value: m[2].trim() });
  }
  const first = name => headers.find(h => h.name === name)?.value ?? null;
  const all   = name => headers.filter(h => h.name === name).map(h => h.value);

  /* 3. Standard fields */
  const from          = first('from');
  const replyTo       = first('reply-to');
  const returnPath    = first('return-path');
  const to            = first('to');
  const subject       = first('subject');
  const date          = first('date');
  const messageId     = first('message-id');
  const mailer        = first('x-mailer') || first('user-agent');
  const originatingIp = first('x-originating-ip') || first('x-source-ip') || first('x-sender-ip');
  const xSpamScore    = first('x-spam-score') || first('x-spam-level');
  const xSpamStatus   = first('x-spam-status');

  /* 4. Authentication-Results: parse spf/dkim/dmarc */
  const authResults = [];
  for (const av of all('authentication-results')) {
    for (const m of av.matchAll(/(spf|dkim|dmarc|arc)\s*=\s*(\S+?)(?=[\s;]|$)([^;]*)/gi)) {
      authResults.push({
        protocol: m[1].toLowerCase(),
        result:   m[2].toLowerCase().replace(/[;,]$/, ''),
        detail:   m[3].trim(),
      });
    }
  }

  /* 5. Received: chain — reverse so index 0 = origin */
  const hops = all('received').reverse().map(rv => {
    const fmFull  = rv.match(/\bfrom\s+(\S+)\s+\([^)]*\[([^\]]+)\]/i);
    const fmHost  = rv.match(/\bfrom\s+(\S+)/i);
    const fmIpLit = rv.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
    const byM     = rv.match(/\bby\s+(\S+)/i);
    const withM   = rv.match(/\bwith\s+(\S+)/i);
    const tsM     = rv.match(/;\s*(.+?)(?:\s*\(.*?\))?\s*$/);
    const fromHost = fmFull?.[1] || fmHost?.[1] || null;
    const fromIp   = fmFull?.[2] || fmIpLit?.[1] || null;
    const tsRaw    = tsM?.[1]?.trim() || null;
    let ts = null;
    try { if (tsRaw) ts = new Date(tsRaw); } catch (_) {}
    return { fromHost, fromIp, byHost: byM?.[1] || null, protocol: withM?.[1] || null, tsRaw, ts };
  });
  for (let i = 1; i < hops.length; i++) {
    const a = hops[i-1].ts, b = hops[i].ts;
    if (a && b) hops[i].delaySec = Math.round((b - a) / 1000);
  }

  /* 6. Unique IPs */
  const seenIp = new Set();
  const allIps = [];
  const addIp  = ip => { if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !seenIp.has(ip)) { seenIp.add(ip); allIps.push(ip); } };
  if (originatingIp) addIp(originatingIp);
  hops.forEach(h => addIp(h.fromIp));

  /* 7. Unique domains */
  const seenD = new Set();
  const allDomains = [];
  const addD  = d => { if (d && !seenD.has(d)) { seenD.add(d); allDomains.push(d); } };
  const domOf = s  => { const m = s?.match(/@([A-Za-z0-9._-]+)/); return m ? m[1].toLowerCase() : null; };
  [from, replyTo, returnPath].forEach(f => { const d = domOf(f); if (d) addD(d); });
  const midDom = messageId?.match(/@([A-Za-z0-9._-]+)/)?.[1]?.toLowerCase();
  if (midDom) addD(midDom);

  /* 8. Flags */
  const flags = [];
  const fromD = domOf(from), rtD = domOf(replyTo), rpD = domOf(returnPath);
  if (rtD && fromD && rtD !== fromD)
    flags.push({ level:'warn',   msg:`Reply-To domain (${rtD}) differs from From domain (${fromD})` });
  if (rpD && fromD && rpD !== fromD)
    flags.push({ level:'warn',   msg:`Return-Path domain (${rpD}) differs from From domain (${fromD})` });
  for (const ar of authResults) {
    if (['fail','permerror'].includes(ar.result))
      flags.push({ level:'danger', msg:`${ar.protocol.toUpperCase()}: ${ar.result.toUpperCase()}` });
    else if (ar.result === 'softfail')
      flags.push({ level:'warn',   msg:`${ar.protocol.toUpperCase()}: softfail` });
  }
  if (!authResults.length)
    flags.push({ level:'info', msg:'No Authentication-Results header — SPF/DKIM/DMARC unverified' });
  if (date) {
    try {
      const diff = new Date(date).getTime() - Date.now();
      if (diff >  3_600_000)           flags.push({ level:'warn', msg:`Date header is in the future: ${date}` });
      if (diff < -30*24*3_600_000)     flags.push({ level:'info', msg:'Date header is over 30 days old' });
    } catch (_) {}
  }
  if (xSpamScore && parseFloat(xSpamScore) > 5)
    flags.push({ level:'warn', msg:`High spam score: ${xSpamScore}` });

  return { from, replyTo, returnPath, to, subject, date, messageId, mailer,
           originatingIp, xSpamScore, xSpamStatus, authResults, hops, allIps, allDomains, flags };
}

function renderEmailHeaders(p) {
  const e  = s  => s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
  const ac = r  => (['pass'].includes(r) ? 'auth-pass' : ['fail','permerror'].includes(r) ? 'auth-fail' : r === 'softfail' ? 'auth-warn' : 'auth-neutral');
  const mxtIpUrl  = ip => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${encodeURIComponent(ip)}&run=toolpage`;
  const mxtDomUrl = d  => `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3A${encodeURIComponent(d)}&run=toolpage`;
  const mxtMxUrl  = d  => `https://mxtoolbox.com/SuperTool.aspx?action=mx%3A${encodeURIComponent(d)}&run=toolpage`;
  const mxtSpfUrl = d  => `https://mxtoolbox.com/SuperTool.aspx?action=spf%3A${encodeURIComponent(d)}&run=toolpage`;

  let h = '';

  /* Summary */
  const sumRows = [
    ['From', p.from], ['Reply-To', p.replyTo], ['Return-Path', p.returnPath],
    ['To', p.to], ['Subject', p.subject], ['Date', p.date],
    ['Message-ID', p.messageId], ['X-Mailer', p.mailer],
    ['Orig. IP', p.originatingIp], ['Spam Score', p.xSpamScore ? `${p.xSpamScore}${p.xSpamStatus ? ' — ' + p.xSpamStatus : ''}` : null],
  ].filter(r => r[1]);
  if (sumRows.length) {
    h += '<div class="ehdr-section"><div class="ehdr-stitle">Summary</div>';
    h += sumRows.map(([l, v]) => `<div class="ehdr-row"><span class="ehdr-lbl">${e(l)}</span><span class="ehdr-val">${e(v)}</span></div>`).join('');
    h += '</div>';
  }

  /* Authentication */
  if (p.authResults.length) {
    h += '<div class="ehdr-section"><div class="ehdr-stitle">Authentication</div>';
    for (const ar of p.authResults) {
      h += `<div class="ehdr-auth-row"><span class="ehdr-proto">${e(ar.protocol.toUpperCase())}</span>`;
      h += `<span class="auth-badge ${ac(ar.result)}">${e(ar.result)}</span>`;
      if (ar.detail) h += `<span class="ehdr-auth-detail">${e(ar.detail)}</span>`;
      h += '</div>';
    }
    h += '</div>';
  }

  /* Received chain */
  if (p.hops.length) {
    h += `<div class="ehdr-section"><div class="ehdr-stitle">Received chain (${p.hops.length} hop${p.hops.length > 1 ? 's' : ''})</div>`;
    p.hops.forEach((hop, i) => {
      h += `<div class="ehdr-hop"><div class="ehdr-hop-num">Hop ${i+1}${i === 0 ? ' · origin' : ''}</div>`;
      if (hop.fromHost || hop.fromIp)
        h += `<div class="ehdr-hop-ln"><span class="ehdr-hk">From</span> ${e(hop.fromHost || '')}${hop.fromIp ? ` <span class="ehdr-ip">[${e(hop.fromIp)}]</span>` : ''}</div>`;
      if (hop.byHost)
        h += `<div class="ehdr-hop-ln"><span class="ehdr-hk">By</span> ${e(hop.byHost)}${hop.protocol ? ` <span class="ehdr-proto-s">${e(hop.protocol)}</span>` : ''}</div>`;
      if (hop.tsRaw)
        h += `<div class="ehdr-hop-ln"><span class="ehdr-hk">Time</span> ${e(hop.tsRaw)}${hop.delaySec !== undefined ? ` <span class="ehdr-delay">${hop.delaySec >= 0 ? '+' : ''}${hop.delaySec}s</span>` : ''}</div>`;
      h += '</div>';
    });
    h += '</div>';
  }

  /* Extracted IPs */
  if (p.allIps.length) {
    h += '<div class="ehdr-section"><div class="ehdr-stitle">IPs</div>';
    for (const ip of p.allIps) {
      h += `<div class="ehdr-ioc-row"><span class="ehdr-ioc-v">${e(ip)}</span>`;
      h += `<a class="epivot" href="${e(PIVOTS.vt_ip(ip))}"        target="_blank">VT</a>`;
      h += `<a class="epivot" href="${e(PIVOTS.abuse(ip))}"         target="_blank">Abuse</a>`;
      h += `<a class="epivot mxt" href="${e(mxtIpUrl(ip))}"         target="_blank">MXToolbox</a>`;
      h += `<a class="epivot" href="${e(PIVOTS.shodan(ip))}"        target="_blank">Shodan</a>`;
      h += `<a class="epivot" href="${e(PIVOTS.google(ip))}"        target="_blank">Google</a>`;
      h += '</div>';
    }
    h += '</div>';
  }

  /* Extracted domains */
  if (p.allDomains.length) {
    h += '<div class="ehdr-section"><div class="ehdr-stitle">Domains</div>';
    for (const d of p.allDomains) {
      h += `<div class="ehdr-ioc-row"><span class="ehdr-ioc-v">${e(d)}</span>`;
      h += `<a class="epivot" href="${e(PIVOTS.vt_domain(d))}"  target="_blank">VT</a>`;
      h += `<a class="epivot" href="${e(PIVOTS.urlscan(d))}"     target="_blank">URLScan</a>`;
      h += `<a class="epivot mxt" href="${e(mxtDomUrl(d))}"      target="_blank">BL</a>`;
      h += `<a class="epivot mxt" href="${e(mxtMxUrl(d))}"       target="_blank">MX</a>`;
      h += `<a class="epivot mxt" href="${e(mxtSpfUrl(d))}"      target="_blank">SPF</a>`;
      h += '</div>';
    }
    h += '</div>';
  }

  /* Flags */
  if (p.flags.length) {
    h += '<div class="ehdr-section"><div class="ehdr-stitle">Flags</div>';
    for (const f of p.flags) {
      const cls  = f.level === 'danger' ? 'ehdr-flag-d' : f.level === 'warn' ? 'ehdr-flag-w' : 'ehdr-flag-i';
      const icon = f.level === 'danger' ? '⛔' : f.level === 'warn' ? '⚠' : 'ℹ';
      h += `<div class="ehdr-flag ${cls}">${icon} ${e(f.msg)}</div>`;
    }
    h += '</div>';
  }

  return h || '<p class="hint" style="margin:8px 0">Nothing extracted — paste full raw headers.</p>';
}

function summarizeEmailHeaders(p) {
  const L = [];
  L.push('=== Email Header Analysis ===');
  if (p.from)          L.push(`From:        ${p.from}`);
  if (p.replyTo)       L.push(`Reply-To:    ${p.replyTo}`);
  if (p.returnPath)    L.push(`Return-Path: ${p.returnPath}`);
  if (p.subject)       L.push(`Subject:     ${p.subject}`);
  if (p.date)          L.push(`Date:        ${p.date}`);
  if (p.messageId)     L.push(`Message-ID:  ${p.messageId}`);
  if (p.mailer)        L.push(`X-Mailer:    ${p.mailer}`);
  if (p.originatingIp) L.push(`Orig. IP:    ${p.originatingIp}`);
  if (p.authResults.length) {
    L.push(''); L.push('Authentication:');
    p.authResults.forEach(ar => L.push(`  ${ar.protocol.toUpperCase()}: ${ar.result.toUpperCase()}${ar.detail ? '  ' + ar.detail : ''}`));
  }
  if (p.hops.length) {
    L.push(''); L.push(`Received chain (${p.hops.length} hops):`);
    p.hops.forEach((h, i) => {
      L.push(`  Hop ${i+1}${i === 0 ? ' (origin)' : ''}:`);
      if (h.fromHost || h.fromIp) L.push(`    From: ${h.fromHost || ''} [${h.fromIp || 'no IP'}]`);
      if (h.byHost)   L.push(`    By:   ${h.byHost}${h.protocol ? ' via ' + h.protocol : ''}`);
      if (h.tsRaw)    L.push(`    Time: ${h.tsRaw}${h.delaySec !== undefined ? ` (${h.delaySec >= 0 ? '+' : ''}${h.delaySec}s)` : ''}`);
    });
  }
  if (p.allIps.length)     L.push(''); L.push(`IPs:     ${p.allIps.join(', ')}`);
  if (p.allDomains.length) L.push(`Domains: ${p.allDomains.join(', ')}`);
  if (p.flags.length) {
    L.push(''); L.push('Flags:');
    p.flags.forEach(f => L.push(`  • ${f.msg}`));
  }
  return L.join('\n');
}

(function wireEmailHdr() {
  let _lastParsed = null;

  document.getElementById('ehdr-run')?.addEventListener('click', () => {
    const raw = document.getElementById('ehdr-in')?.value?.trim();
    const out = document.getElementById('ehdr-out');
    if (!out) return;
    if (!raw) { out.innerHTML = '<p class="hint" style="margin:8px 0">Paste headers above first.</p>'; return; }
    _lastParsed = parseEmailHeaders(raw);
    out.innerHTML = renderEmailHeaders(_lastParsed);
  });

  document.getElementById('ehdr-inject')?.addEventListener('click', () => {
    if (!_lastParsed) { alert('Analyse headers first.'); return; }
    let added = 0;
    (_lastParsed.allIps || []).forEach(ip => {
      if (!state.raw.ips) state.raw.ips = [];
      if (!state.raw.ips.includes(ip)) { state.raw.ips.push(ip); added++; }
    });
    (_lastParsed.allDomains || []).forEach(d => {
      if (!state.raw.domains) state.raw.domains = [];
      if (!state.raw.domains.includes(d)) { state.raw.domains.push(d); added++; }
    });
    if (added) {
      try { recomputeRendered(); renderIOCs(); saveLastExtraction(); } catch (_) {}
      flashBtn(document.getElementById('ehdr-inject'), `✓ +${added}`);
    } else {
      flashBtn(document.getElementById('ehdr-inject'), 'Already there');
    }
  });

  document.getElementById('ehdr-copy')?.addEventListener('click', () => {
    if (!_lastParsed) { alert('Analyse headers first.'); return; }
    navigator.clipboard.writeText(summarizeEmailHeaders(_lastParsed));
    flashBtn(document.getElementById('ehdr-copy'), '✓ Copied');
  });

  document.getElementById('ehdr-clear')?.addEventListener('click', () => {
    const ta = document.getElementById('ehdr-in');
    if (ta) ta.value = '';
    const out = document.getElementById('ehdr-out');
    if (out) out.innerHTML = '';
    _lastParsed = null;
  });
})();

/* ============================================================
   SIGMA CONVERTER
   Converts Sigma YAML rules to Splunk SPL, Sentinel KQL, Elastic KQL.
   Handles: standard modifiers, boolean conditions, count expressions,
   field mappings for MDE (Sentinel) and ECS (Elastic), multi-doc YAML.
   ============================================================ */

/* ---- Minimal YAML parser tuned for the Sigma rule subset ---- */
function parseSigmaYaml(src) {
  const lines = src.split(/\r?\n/)
    .map(l => l.trimEnd())
    .filter(l => l.trim() && !l.trim().startsWith('#'));

  let pos = 0;

  function curIndent() { return pos < lines.length ? lines[pos].search(/\S/) : -1; }

  function scalar(s) {
    if (s === 'true'  || s === 'yes') return true;
    if (s === 'false' || s === 'no')  return false;
    if (s === 'null'  || s === '~')   return null;
    if (/^-?\d+$/.test(s))            return parseInt(s, 10);
    if (/^-?\d*\.\d+$/.test(s))       return parseFloat(s);
    if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"')))
      return s.slice(1, -1).replace(/''/g, "'");
    return s;
  }

  function parseMapping(parentIndent) {
    const obj = {};
    while (pos < lines.length) {
      const li = lines[pos].search(/\S/);
      if (li <= parentIndent) break;
      const content = lines[pos].trim();
      if (content.startsWith('- ')) break;

      const ci = content.indexOf(':');
      if (ci < 0) { pos++; continue; }
      const key     = content.slice(0, ci).trim();
      const restRaw = content.slice(ci + 1).trim();
      const myLi    = li;
      pos++;

      if (restRaw === '|' || restRaw === '>') {
        /* Block scalar — collect lines as plain text */
        const bLi = curIndent();
        if (bLi > myLi) {
          const bLines = [];
          while (pos < lines.length && lines[pos].search(/\S/) >= bLi) {
            bLines.push(lines[pos].slice(bLi)); pos++;
          }
          obj[key] = bLines.join('\n');
        } else { obj[key] = ''; }
      } else if (restRaw === '') {
        const nextLi = curIndent();
        if (nextLi > myLi) {
          obj[key] = lines[pos].trim().startsWith('- ')
            ? parseList(myLi) : parseMapping(myLi);
        } else { obj[key] = null; }
      } else {
        obj[key] = scalar(restRaw);
      }
    }
    return obj;
  }

  function parseList(parentIndent) {
    const items = [];
    while (pos < lines.length) {
      const li = lines[pos].search(/\S/);
      if (li <= parentIndent) break;
      const content = lines[pos].trim();
      if (!content.startsWith('- ')) break;
      const itemContent = content.slice(2).trim();
      pos++;
      if (itemContent === '') {
        if (curIndent() > li) items.push(parseMapping(li));
      } else {
        items.push(scalar(itemContent));
      }
    }
    return items;
  }

  return parseMapping(-1);
}

/* ---- Logsource → Splunk index/sourcetype hints ---- */
const SIGMA_SPL_HINT = {
  process_creation:       'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1',
  network_connection:     'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3',
  dns_query:              'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22',
  file_event:             'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11',
  registry_event:         'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=12 OR EventCode=13 OR EventCode=14)',
  image_load:             'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7',
  create_remote_thread:   'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8',
  driver_load:            'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6',
  pipe_created:           'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=17 OR EventCode=18)',
  ps_script:              'index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104',
  ps_module:              'index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103',
  proxy:                  'index=proxy',
  webserver:              'index=web sourcetype=access_combined',
  firewall:               'index=firewall',
  email:                  'index=mail',
  dns:                    'index=dns',
};

/* ---- Logsource → Sentinel MDE table + field mapping ---- */
const SENTINEL_MAP = {
  process_creation: {
    table: "DeviceProcessEvents",
    f: { Image:"FolderPath", CommandLine:"ProcessCommandLine",
         ParentImage:"InitiatingProcessFolderPath", ParentCommandLine:"InitiatingProcessCommandLine",
         ProcessId:"ProcessId", User:"AccountName", Computer:"DeviceName",
         Hashes:"SHA256", IntegrityLevel:"ProcessIntegrityLevel" }
  },
  network_connection: {
    table: "DeviceNetworkEvents",
    f: { DestinationIp:"RemoteIP", DestinationIP:"RemoteIP",
         DestinationPort:"RemotePort", DestinationHostname:"RemoteUrl",
         SourceIp:"LocalIP", SourceIP:"LocalIP", SourcePort:"LocalPort",
         Image:"InitiatingProcessFileName", User:"InitiatingProcessAccountName",
         Computer:"DeviceName", Protocol:"Protocol" }
  },
  dns_query: {
    table: "DeviceDnsEvents",
    f: { QueryName:"Name", QueryResults:"IPAddresses",
         Image:"InitiatingProcessFileName", Computer:"DeviceName" }
  },
  file_event: {
    table: "DeviceFileEvents",
    f: { TargetFilename:"FolderPath", Image:"InitiatingProcessFileName",
         User:"RequestAccountName", Computer:"DeviceName", Hashes:"SHA256" }
  },
  registry_event: {
    table: "DeviceRegistryEvents",
    f: { TargetObject:"RegistryKey", Details:"RegistryValueData",
         EventType:"ActionType", Image:"InitiatingProcessFileName" }
  },
  image_load: {
    table: "DeviceImageLoadEvents",
    f: { ImageLoaded:"FolderPath", Image:"InitiatingProcessFileName",
         Hashes:"SHA256", Signed:"IsTrusted", Signature:"Signer" }
  },
  ps_script: {
    table: "DeviceEvents",
    f: { ScriptBlockText:"InitiatingProcessCommandLine",
         ScriptPath:"InitiatingProcessFolderPath" }
  },
  proxy: {
    table: "DeviceNetworkEvents",
    f: { "cs-host":"RemoteUrl", "cs-uri":"RemoteUrl",
         "c-ip":"LocalIP", "cs(User-Agent)":"InitiatingProcessVersionInfoProductName" }
  },
  webserver: {
    table: "W3CIISLog",
    f: { "c-ip":"cIP", "cs-uri":"csUriStem", "cs-host":"sSiteName", "sc-status":"scStatus" }
  },
  email: {
    table: "EmailEvents",
    f: { SenderFromAddress:"SenderFromAddress", RecipientEmailAddress:"RecipientEmailAddress",
         Subject:"Subject", Sender:"SenderDisplayName" }
  },
};

/* ---- Logsource → Elastic ECS index + field mapping ---- */
const ELASTIC_MAP = {
  process_creation: {
    index: "logs-endpoint.events.process-*",
    f: { Image:"process.executable", CommandLine:"process.command_line",
         ParentImage:"process.parent.executable", ParentCommandLine:"process.parent.command_line",
         User:"user.name", Computer:"host.hostname", ProcessId:"process.pid",
         Hashes:"process.hash.sha256" }
  },
  network_connection: {
    index: "logs-endpoint.events.network-*",
    f: { DestinationIp:"destination.ip", DestinationIP:"destination.ip",
         DestinationPort:"destination.port", DestinationHostname:"destination.domain",
         SourceIp:"source.ip", SourceIP:"source.ip", SourcePort:"source.port",
         Image:"process.executable", User:"user.name", Computer:"host.hostname" }
  },
  dns_query: {
    index: "logs-endpoint.events.network-*",
    f: { QueryName:"dns.question.name", QueryResults:"dns.answers.data",
         Image:"process.executable", User:"user.name" }
  },
  file_event: {
    index: "logs-endpoint.events.file-*",
    f: { TargetFilename:"file.path", Image:"process.executable",
         User:"user.name", Hashes:"file.hash.sha256", Computer:"host.hostname" }
  },
  registry_event: {
    index: "logs-endpoint.events.registry-*",
    f: { TargetObject:"registry.path", Details:"registry.data.strings",
         Image:"process.executable", EventType:"event.action" }
  },
  proxy: {
    index: "logs-proxy.*",
    f: { "cs-host":"url.domain", "cs-uri":"url.full",
         "c-ip":"source.ip", "cs(User-Agent)":"user_agent.original" }
  },
  email: {
    index: "logs-email.*",
    f: { SenderFromAddress:"email.from.address",
         RecipientEmailAddress:"email.to.address", Subject:"email.subject" }
  },
};

/* ---- Value clause builders ---- */
function _splClause(field, v, mods) {
  const e = v => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  if (mods.includes('re'))         return `${field}=~"${e(v)}"`;
  if (mods.includes('contains'))   return `${field}="*${e(v)}*"`;
  if (mods.includes('startswith')) return `${field}="${e(v)}*"`;
  if (mods.includes('endswith'))   return `${field}="*${e(v)}"`;
  if (mods.includes('cidr'))       return `cidr(${field},subnet="${v}")`;
  if (v === '*')                   return `${field}=*`;
  return `${field}="${e(v)}"`;
}
function _senClause(field, v, mods) {
  const e = v => v.replace(/"/g, '\\"');
  if (mods.includes('re'))         return `${field} matches regex @"${e(v)}"`;
  if (mods.includes('contains'))   return `${field} has "${e(v)}"`;
  if (mods.includes('startswith')) return `${field} startswith "${e(v)}"`;
  if (mods.includes('endswith'))   return `${field} endswith "${e(v)}"`;
  if (mods.includes('cidr'))       return `ipv4_is_in_range(${field}, "${v}")`;
  if (v === '*')                   return `isnotempty(${field})`;
  return `${field} =~ "${e(v)}"`;
}
function _ecsClause(field, v, mods) {
  const e = v => v.replace(/"/g, '\\"');
  if (mods.includes('re'))         return `${field}: /${v}/`;
  if (mods.includes('contains'))   return `${field}: *${v}*`;
  if (mods.includes('startswith')) return `${field}: ${v}*`;
  if (mods.includes('endswith'))   return `${field}: *${v}`;
  if (v === '*')                   return `${field}: *`;
  return `${field}: "${e(v)}"`;
}

function buildFieldExpr(field, values, mods, hasAll, fmt) {
  const e = v => (v === null || v === undefined) ? '*' : String(v);
  const vals = values.map(e);
  const join = hasAll
    ? (fmt === 'sentinel' ? ' and ' : ' AND ')
    : (fmt === 'sentinel' ? ' or '  : ' OR ');

  /* Sentinel optimisations for multi-value common cases */
  if (fmt === 'sentinel' && !hasAll && vals.length >= 2) {
    if (!mods.length)
      return `${field} in~ (${vals.map(v => `"${v.replace(/"/g,'\\"')}"`).join(', ')})`;
    if (mods.length === 1 && mods[0] === 'contains')
      return `${field} has_any (${vals.map(v => `"${v.replace(/"/g,'\\"')}"`).join(', ')})`;
  }

  const fn = fmt === 'splunk' ? _splClause : fmt === 'sentinel' ? _senClause : _ecsClause;
  const clauses = vals.map(v => fn(field, v, mods));
  return clauses.length === 1 ? clauses[0] : '(' + clauses.join(join) + ')';
}

function nullCheck(field, fmt) {
  if (fmt === 'splunk')   return `NOT ${field}=*`;
  if (fmt === 'sentinel') return `isnull(${field})`;
  return `NOT _exists_: ${field}`;
}

/* ---- Selection block → expression string ---- */
function selectionToExpr(blk, fmt, fieldMap) {
  /* Keyword array (full-text search) */
  if (Array.isArray(blk)) {
    const quoted = blk.map(k => `"${String(k).replace(/"/g,'\\"')}"`);
    if (fmt === 'sentinel') return `(* has_any (${quoted.join(', ')}))`;
    return '(' + quoted.join(fmt === 'splunk' ? ' OR ' : ' OR ') + ')';
  }
  if (!blk || typeof blk !== 'object') return null;

  const AND  = fmt === 'sentinel' ? ' and ' : ' AND ';
  const andClauses = [];

  for (const [spec, raw] of Object.entries(blk)) {
    const parts    = spec.split('|');
    const rawField = parts[0];
    const mods     = parts.slice(1).filter(m => m && m !== 'all');
    const hasAll   = parts.includes('all');
    const field    = fieldMap?.[rawField] || rawField;

    if (raw === null || raw === undefined) {
      andClauses.push(nullCheck(field, fmt)); continue;
    }
    const vals = Array.isArray(raw) ? raw : [raw];
    andClauses.push(buildFieldExpr(field, vals, mods, hasAll, fmt));
  }

  if (!andClauses.length) return null;
  return andClauses.length === 1 ? andClauses[0] : '(' + andClauses.join(AND) + ')';
}

/* ---- Sigma condition expression parser ---- */
function parseCondExpr(condStr, selNames) {
  const toks = condStr.trim()
    .replace(/\(/g, ' ( ').replace(/\)/g, ' ) ')
    .split(/\s+/).filter(Boolean);
  let p = 0;
  const peek = () => toks[p] || null;
  const next = () => toks[p++];

  function parseOr() {
    let l = parseAnd();
    while (peek()?.toLowerCase() === 'or') { next(); l = { op:'OR', l, r:parseAnd() }; }
    return l;
  }
  function parseAnd() {
    let l = parseNot();
    while (peek()?.toLowerCase() === 'and') { next(); l = { op:'AND', l, r:parseNot() }; }
    return l;
  }
  function parseNot() {
    if (peek()?.toLowerCase() === 'not') { next(); return { op:'NOT', v:parseAtom() }; }
    return parseAtom();
  }
  function parseAtom() {
    if (peek() === '(') {
      next();
      const e = parseOr();
      if (peek() === ')') next();
      return e;
    }
    const t = next();
    /* Count expression: "1 of ...", "all of ..." */
    if (t && peek()?.toLowerCase() === 'of') {
      next();
      const target = next();
      let names;
      if (!target || target.toLowerCase() === 'them') {
        names = selNames;
      } else {
        const pat = new RegExp('^' + target.replace(/\*/g, '.*') + '$', 'i');
        names = selNames.filter(n => pat.test(n));
      }
      const isAll = t.toLowerCase() === 'all' || t === String(names.length);
      return { op: isAll ? 'ALL_OF' : 'ONE_OF', names };
    }
    return { op:'REF', name:t };
  }
  return parseOr();
}

/* ---- Condition AST → query string ---- */
function evalCondTree(tree, exprs, fmt) {
  if (!tree) return '(true)';
  const OR  = fmt === 'sentinel' ? ' or '  : ' OR ';
  const AND = fmt === 'sentinel' ? ' and ' : ' AND ';
  const NOT = fmt === 'sentinel' ? 'not'   : 'NOT';
  switch (tree.op) {
    case 'OR':
      return `(${evalCondTree(tree.l,exprs,fmt)}${OR}${evalCondTree(tree.r,exprs,fmt)})`;
    case 'AND':
      return `(${evalCondTree(tree.l,exprs,fmt)}${AND}${evalCondTree(tree.r,exprs,fmt)})`;
    case 'NOT':
      return `(${NOT} ${evalCondTree(tree.v,exprs,fmt)})`;
    case 'ONE_OF': {
      const parts = tree.names.map(n => exprs[n] || `/* ${n}? */`);
      return parts.length === 1 ? parts[0] : '(' + parts.join(OR) + ')';
    }
    case 'ALL_OF': {
      const parts = tree.names.map(n => exprs[n] || `/* ${n}? */`);
      return parts.length === 1 ? parts[0] : '(' + parts.join(AND) + ')';
    }
    case 'REF':
      return exprs[tree.name] || `/* ${tree.name}? */`;
    default:
      return '(true)';
  }
}

/* ---- Convert one Sigma rule document ---- */
function convertOneSigmaRule(yamlText, fmt) {
  let rule;
  try { rule = parseSigmaYaml(yamlText); }
  catch (e) { return `/* YAML parse error: ${e.message} */`; }
  if (!rule || typeof rule !== 'object') return '/* Failed to parse YAML */';

  const title  = rule.title  || '(untitled)';
  const level  = rule.level  ? `[${rule.level}]`  : '';
  const status = rule.status ? `[${rule.status}]` : '';
  const author = typeof rule.author === 'string' ? rule.author : '';
  const date   = rule.date   || '';
  const ls     = rule.logsource || {};
  const det    = rule.detection;
  if (!det) return `/* No detection block: "${title}" */`;

  const condStr  = typeof det.condition === 'string' ? det.condition : 'selection';
  const sels     = {};
  for (const [k, v] of Object.entries(det)) {
    if (k !== 'condition' && k !== 'timeframe') sels[k] = v;
  }

  const lsCat  = (ls.category || ls.service || '').toLowerCase();
  const lsProd = (ls.product  || '').toLowerCase();

  /* Resolve field map and table/index for target format */
  let fieldMap = {}, tableOrIndex = '';
  if (fmt === 'sentinel') {
    const m = SENTINEL_MAP[lsCat] || {};
    fieldMap = m.f || {}; tableOrIndex = m.table || `/* map "${lsCat}" manually */`;
  } else if (fmt === 'elastic') {
    const m = ELASTIC_MAP[lsCat] || {};
    fieldMap = m.f || {}; tableOrIndex = m.index || `/* map "${lsCat}" manually */`;
  }

  /* Build per-selection expressions */
  const selExprs = {};
  for (const [name, blk] of Object.entries(sels)) {
    selExprs[name] = selectionToExpr(blk, fmt, fieldMap) || '(true)';
  }

  /* Evaluate condition tree */
  const condExpr = evalCondTree(
    parseCondExpr(condStr, Object.keys(sels)),
    selExprs, fmt
  );

  /* Format output */
  const lsHint = [lsProd, lsCat].filter(Boolean).join('/');
  const hdr    = [
    `Title:  ${title} ${level} ${status}`,
    author ? `Author: ${author}` : null,
    date   ? `Date:   ${date}`   : null,
    `Source: ${lsHint || 'unknown'}`,
  ].filter(Boolean);

  if (fmt === 'splunk') {
    const hint = SIGMA_SPL_HINT[lsCat] || `/* adjust index/sourcetype for: ${lsHint || 'unknown'} */`;
    return hdr.map(l => `/* ${l} */`).join('\n') +
      `\n\n${hint}\n| search ${condExpr}`;
  }
  if (fmt === 'sentinel') {
    return hdr.map(l => `// ${l}`).join('\n') +
      `\n\n${tableOrIndex}\n| where ${condExpr}`;
  }
  /* elastic */
  return hdr.map(l => `// ${l}`).join('\n') +
    `\n// Index:  ${tableOrIndex}\n\n${condExpr}`;
}

/* ---- Entry point: handles multi-document YAML ---- */
function convertSigma(yamlText, fmt) {
  const docs = yamlText.split(/^---\s*$/m).map(s => s.trim()).filter(Boolean);
  const sep  = fmt === 'splunk'
    ? '\n\n/* ─────────────── next rule ─────────────── */\n\n'
    : '\n\n// ─────────────── next rule ─────────────── \n\n';
  return docs.map(d => convertOneSigmaRule(d, fmt)).join(sep);
}

/* ---- Example rule (for the Load example button) ---- */
const SIGMA_EXAMPLE = `title: Suspicious Encoded PowerShell Command
id: e7ec9a2d-503c-4b51-8e93-5e4d5b6c8dff
status: experimental
description: Detects PowerShell launched with an encoded command argument
author: SOC Mate Example
date: 2026-07-07
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_enc:
        CommandLine|contains:
            - ' -EncodedCommand '
            - ' -enc '
            - ' -e '
    filter_legit:
        CommandLine|contains:
            - 'WindowsUpdate'
    condition: selection_img and selection_enc and not filter_legit
falsepositives:
    - Legitimate admin scripts using encoded commands
level: high`;

(function wireSigmaConverter() {
  document.getElementById("sigma-convert")?.addEventListener("click", () => {
    const yaml = document.getElementById("sigma-in")?.value?.trim();
    const fmt  = document.getElementById("sigma-target")?.value || "splunk";
    const out  = document.getElementById("sigma-out");
    if (!out) return;
    if (!yaml) { out.textContent = "/* Paste a Sigma rule above first */"; return; }
    try { out.textContent = convertSigma(yaml, fmt); }
    catch (e) { out.textContent = `/* Conversion error: ${e.message} */`; }
  });

  document.getElementById("sigma-copy")?.addEventListener("click", () => {
    const out = document.getElementById("sigma-out");
    if (!out?.textContent) return;
    navigator.clipboard.writeText(out.textContent);
    flashBtn(document.getElementById("sigma-copy"), "✓ Copied");
  });

  document.getElementById("sigma-example")?.addEventListener("click", () => {
    const ta = document.getElementById("sigma-in");
    if (ta) { ta.value = SIGMA_EXAMPLE; ta.focus(); }
    const out = document.getElementById("sigma-out");
    if (out) out.textContent = "";
  });

  document.getElementById("sigma-clear-in")?.addEventListener("click", () => {
    const ta = document.getElementById("sigma-in");
    if (ta) ta.value = "";
    const out = document.getElementById("sigma-out");
    if (out) out.textContent = "";
  });

  /* Re-run conversion when target format changes (if output is already populated) */
  document.getElementById("sigma-target")?.addEventListener("change", () => {
    const out = document.getElementById("sigma-out");
    if (!out?.textContent) return;
    const yaml = document.getElementById("sigma-in")?.value?.trim();
    const fmt  = document.getElementById("sigma-target")?.value || "splunk";
    if (yaml) {
      try { out.textContent = convertSigma(yaml, fmt); }
      catch (e) { out.textContent = `/* ${e.message} */`; }
    }
  });
})();

/* ============================================================
   TUTORIAL  —  first-run walkthrough + ? button
   Slides are pure data; the modal renders them dynamically so
   the HTML stays clean. Shown automatically on first open;
   replay any time with the ? button in the header.
   ============================================================ */
(function wireTutorial() {
  const SLIDES = [
    {
      icon: "👋",
      title: "Welcome to SOC Mate",
      body: "Your browser-native analyst toolkit. It extracts <strong>IOCs</strong>, <strong>process trees</strong>, and <strong>network indicators</strong> directly from Splunk and Microsoft Defender — no copy-paste, no switching windows."
    },
    {
      icon: "🔍",
      title: "Extract from page",
      body: "Navigate to a <strong>Splunk search</strong> or <strong>Defender alert</strong>, then click <strong>Extract from page</strong>. SOC Mate reads the DOM and pulls typed IPs, domains, hashes, URLs, and more.<br><br>Enable the <strong>Auto</strong> toggle to extract automatically every time you open on a new page."
    },
    {
      icon: "🌳",
      title: "Process tree",
      body: "On Defender alert pages, click <strong>Expand All</strong> in the alert story's process tree before extracting. SOC Mate reconstructs the full parent→child lineage with command lines.<br><br>Use <strong>Copy view</strong> for a clean indented tree, <strong>Copy command lines</strong> for the raw commands."
    },
    {
      icon: "🔎",
      title: "Find &amp; Replace",
      body: "Press <code>Ctrl+F</code> while focused in any text field to search within it.<br>Press <code>Ctrl+H</code> for find + replace.<br><br>If you have text <strong>selected</strong> when you press the shortcut, it's automatically placed in the search box."
    },
    {
      icon: "🛠",
      title: "Utilities",
      body: "The <strong>Utilities</strong> tab includes:<br>• <strong>Decode / beautify</strong> — Base64, URL, JSON, XML<br>• <strong>User-agent parser</strong> — browser / OS / engine<br>• <strong>Subnet calculator</strong> &amp; membership check<br>• <strong>Redactor</strong> — strip sensitive data with your saved patterns before sharing"
    },
    {
      icon: "🌐",
      title: "Enrichment",
      body: "Click any extracted <strong>IP, domain, or hash</strong> to pivot to VirusTotal, AbuseIPDB, Shodan, RDAP, and Geo.<br><br>Set your <strong>API keys</strong> in Settings first (VT, AbuseIPDB, ipinfo). The verdict badge turns red / orange / green based on your configured thresholds."
    },
    {
      icon: "⚙️",
      title: "Settings &amp; Workspace",
      body: "Use <strong>Open in tab ⤢</strong> for a full-screen workspace that stays open while you browse — it updates automatically when you extract in the popup.<br><br><strong>Settings</strong> → configure API keys, redaction patterns, excluded domains, category visibility, and history options."
    },
    {
      icon: "⌨️",
      title: "Keyboard Shortcuts",
      body: "<strong>Tabs</strong><br>" +
            "<code>Ctrl+1</code> Extract &nbsp; <code>Ctrl+2</code> Utilities<br>" +
            "<code>Ctrl+3</code> History &nbsp; <code>Ctrl+4</code> Settings<br><br>" +
            "<strong>Extract</strong><br>" +
            "<code>Ctrl+E</code> Extract from page<br>" +
            "<code>Ctrl+Shift+E</code> Extract from pasted text<br><br>" +
            "<strong>Processes</strong><br>" +
            "<code>Ctrl+Shift+T</code> Toggle Tree / Flat view<br>" +
            "<code>Ctrl+Shift+C</code> Copy process view<br>" +
            "<code>Ctrl+Shift+L</code> Copy command lines<br>" +
            "<code>Ctrl+Shift+M</code> Copy tree + command lines<br><br>" +
            "<strong>Text fields</strong><br>" +
            "<code>Ctrl+F</code> Find &nbsp; <code>Ctrl+H</code> Find &amp; replace<br><br>" +
            "<strong>General</strong><br>" +
            "<code>Ctrl+/</code> Open this tour"
    }
  ];

  const modal   = document.getElementById("tutorial-modal");
  const iconEl  = document.getElementById("tut-icon");
  const titleEl = document.getElementById("tut-title");
  const bodyEl  = document.getElementById("tut-body");
  const dotsEl  = document.getElementById("tut-dots");
  const stepEl  = document.getElementById("tut-step");
  const prevBtn = document.getElementById("tut-prev");
  const nextBtn = document.getElementById("tut-next");
  const closeBtn= document.getElementById("tut-close");
  if (!modal || !iconEl) return;

  let cur = 0;

  function render(n) {
    cur = Math.max(0, Math.min(n, SLIDES.length - 1));
    const s = SLIDES[cur];
    iconEl.textContent  = s.icon;
    titleEl.innerHTML   = s.title;
    bodyEl.innerHTML    = s.body;
    stepEl.textContent  = `${cur + 1} / ${SLIDES.length}`;
    if (prevBtn) prevBtn.disabled = cur === 0;
    if (nextBtn) nextBtn.textContent = cur === SLIDES.length - 1 ? "Done ✓" : "Next →";
    // Dots
    if (dotsEl) {
      dotsEl.innerHTML = "";
      SLIDES.forEach((_, i) => {
        const d = document.createElement("span");
        d.className = "tut-dot" + (i === cur ? " active" : "");
        d.addEventListener("click", () => render(i));
        dotsEl.appendChild(d);
      });
    }
  }

  function open(startAt = 0) {
    render(startAt);
    modal.hidden = false;
  }

  function close() {
    modal.hidden = true;
    chrome.storage.local.set({ tutorialSeen: true });
  }

  if (prevBtn)  prevBtn.addEventListener("click", () => render(cur - 1));
  if (nextBtn)  nextBtn.addEventListener("click", () => {
    if (cur === SLIDES.length - 1) close(); else render(cur + 1);
  });
  if (closeBtn) closeBtn.addEventListener("click", close);
  modal.addEventListener("click", e => { if (e.target === modal) close(); });
  document.addEventListener("keydown", e => {
    if (modal.hidden) return;
    if (e.key === "ArrowRight" || e.key === "Enter") { e.preventDefault(); cur === SLIDES.length - 1 ? close() : render(cur + 1); }
    if (e.key === "ArrowLeft")  { e.preventDefault(); render(cur - 1); }
    if (e.key === "Escape")     { e.preventDefault(); close(); }
  });

  const tourBtn = document.getElementById("tour-btn");
  if (tourBtn) tourBtn.addEventListener("click", () => open(0));

  // Show automatically on first install.
  chrome.storage.local.get("tutorialSeen", ({ tutorialSeen }) => {
    if (!tutorialSeen) open(0);
  });
})();

/* ============================================================
   GLOBAL KEYBOARD SHORTCUTS
   Called with capture:true so preventDefault fires before
   Chrome (or any other listener) can act on the key.
   Guard: action shortcuts only fire when focus is NOT inside
   a text field (so typing is never interrupted).
   ============================================================ */
(function wireShortcuts() {
  const TABS = ["extract", "utilities", "history", "settings"];

  function notTyping() {
    const t = document.activeElement;
    return !(t && (t.tagName === "TEXTAREA" ||
      (t.tagName === "INPUT" && !["checkbox","radio","range","button"].includes(t.type))));
  }
  function clickId(id) { document.getElementById(id)?.click(); }
  function switchTab(name) { document.querySelector(`.tab[data-tab="${name}"]`)?.click(); }

  document.addEventListener("keydown", e => {
    if (!e.ctrlKey) return;
    const key   = e.key;
    const shift = e.shiftKey;
    const kl    = key.toLowerCase();

    // ── Ctrl+1–4  →  tab navigation ──────────────────────────────
    const n = parseInt(key);
    if (n >= 1 && n <= 4 && !shift) {
      e.preventDefault();
      switchTab(TABS[n - 1]);
      return;
    }

    // ── action shortcuts (skip when typing) ──────────────────────
    if (kl === "e" && !shift) {          // Ctrl+E  → Extract from page
      e.preventDefault();
      if (notTyping()) clickId("extract");
      return;
    }
    if (kl === "e" && shift) {           // Ctrl+Shift+E  → Extract from text
      e.preventDefault();
      if (notTyping()) clickId("extract-paste");
      return;
    }
    if (kl === "t" && shift) {           // Ctrl+Shift+T  → Toggle Tree/Flat
      e.preventDefault();
      if (notTyping()) clickId("procs-tree-toggle");
      return;
    }
    if (kl === "c" && shift) {           // Ctrl+Shift+C  → Copy process view
      e.preventDefault();
      if (notTyping()) clickId("procs-copy");
      return;
    }
    if (kl === "l" && shift) {           // Ctrl+Shift+L  → Copy command lines
      e.preventDefault();
      if (notTyping()) clickId("procs-copy-cmds");
      return;
    }
    if (kl === "m" && shift) {           // Ctrl+Shift+M  → Copy tree+cmds
      e.preventDefault();
      if (notTyping()) clickId("procs-copy-tree-cmds");
      return;
    }
    if (key === "/" && !shift) {         // Ctrl+/  → Open tour
      e.preventDefault();
      clickId("tour-btn");
      return;
    }
    if (kl === "k" && !shift) {          // Ctrl+K  → Feature search
      e.preventDefault();
      clickId("search-btn");
      return;
    }
  }, true);
})();

/* ============================================================
   Feature search  (Ctrl+K / 🔍 button)
   Full-screen overlay — type to filter, ↑↓ to navigate,
   Enter/click to jump to any feature, Esc to close.
   ============================================================ */
(function wireSearch() {
  const panel     = document.getElementById("search-panel");
  const input     = document.getElementById("search-input");
  const resultsEl = document.getElementById("search-results");
  const openBtn   = document.getElementById("search-btn");
  const closeBtn  = document.getElementById("search-close");
  if (!panel || !input || !resultsEl) return;

  /* ── helpers ──────────────────────────────────────────────── */
  function goTab(name) {
    document.querySelector(`.tab[data-tab="${name}"]`)?.click();
  }
  function openGroupById(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.open = true;
    setTimeout(() => el.scrollIntoView({ behavior: "smooth", block: "nearest" }), 60);
  }
  function openSection(hint) {
    // Open the first <details.settings-group> whose summary text matches
    setTimeout(() => {
      const active = document.querySelector(".tabpanel.active");
      if (!active) return;
      for (const d of active.querySelectorAll("details.settings-group")) {
        if ((d.querySelector("summary")?.textContent || "").toLowerCase().includes(hint)) {
          d.open = true;
          d.scrollIntoView({ behavior: "smooth", block: "nearest" });
          return;
        }
      }
    }, 60);
  }
  function focusEl(id) { setTimeout(() => document.getElementById(id)?.focus(), 100); }
  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  /* ── search index ─────────────────────────────────────────── */
  const IDX = [
    // ── Extract ───────────────────────────────────────────────────────
    { icon:"⬇️",  label:"Extract from page",
      desc:"Pull IOCs from the active Splunk / Defender tab",
      keys:"extract page ioc splunk defender scrape",                   tab:"extract",
      run: () => { goTab("extract"); } },
    { icon:"📋",  label:"Extract from pasted text",
      desc:"Paste any text and extract IOCs from it",
      keys:"paste text extract ioc manual",                             tab:"extract",
      run: () => { goTab("extract"); focusEl("paste-in"); } },
    { icon:"🔄",  label:"Auto-extract",
      desc:"Auto-run extraction when popup opens on a SOC page",
      keys:"auto extract automatic toggle enable",                      tab:"extract",
      run: () => { goTab("extract"); } },
    { icon:"🧹",  label:"Sanitize",
      desc:"Trim quotes, brackets, trailing punctuation from values",
      keys:"sanitize clean trim brackets quotes punctuation",           tab:"extract",
      run: () => { goTab("extract"); } },
    { icon:"🔒",  label:"Defang",
      desc:"Replace . with [.] and http with hxxp for safe sharing",
      keys:"defang bracket dot hxxp safe sharing",                      tab:"extract",
      run: () => { goTab("extract"); } },
    { icon:"✂️",  label:"Redact (toggle)",
      desc:"Mask sensitive words in output using the redaction list",
      keys:"redact mask hide replace sensitive output",                  tab:"extract",
      run: () => { goTab("extract"); } },
    { icon:"📄",  label:"All IOCs pane",
      desc:"Combined editable list of every extracted indicator",
      keys:"all iocs copy list combined output pane",                   tab:"extract",
      run: () => { goTab("extract"); openGroupById("all-pane-group"); } },
    { icon:"🌲",  label:"Process tree",
      desc:"Defender process lineage with parent → child indentation",
      keys:"process tree defender parent child lineage indented",       tab:"extract",
      run: () => { goTab("extract"); openGroupById("procs-group"); } },
    { icon:"📋",  label:"Copy process tree view",
      desc:"Copy the indented tree to clipboard  (Ctrl+Shift+C)",
      keys:"copy process tree clipboard ctrl shift c",                  tab:"extract",
      run: () => { goTab("extract"); openGroupById("procs-group"); } },
    { icon:"⌨️",  label:"Copy command lines",
      desc:"Copy command lines only  (Ctrl+Shift+L)",
      keys:"copy command line cmd cli ctrl shift l",                    tab:"extract",
      run: () => { goTab("extract"); openGroupById("procs-group"); } },
    { icon:"🌲",  label:"Copy tree+cmds",
      desc:"Copy process tree with inline command lines  (Ctrl+Shift+M)",
      keys:"copy tree commands inline triage report ctrl shift m",      tab:"extract",
      run: () => { goTab("extract"); openGroupById("procs-group"); clickId("procs-copy-tree-cmds"); } },
    // ── Utilities ─────────────────────────────────────────────────────
    { icon:"🔓",  label:"Base64 decode",
      desc:"Decode a base64-encoded string",
      keys:"base64 decode b64 encoded blob atob",                       tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🔗",  label:"URL decode",
      desc:"Percent-decode a URL-encoded string",
      keys:"url decode percent encoded uri %20",                        tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🧠",  label:"Smart decode",
      desc:"Auto-detect and decode Base64 / URL / hex chains",
      keys:"smart decode auto base64 url hex detect chain",             tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🖋️", label:"JSON beautify / minify",
      desc:"Pretty-print or compact a JSON payload",
      keys:"json beautify minify pretty format compact",                tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"📐",  label:"XML beautify / minify",
      desc:"Pretty-print or compact an XML document",
      keys:"xml beautify minify format compact",                        tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🌐",  label:"HTML → text",
      desc:"Strip all HTML tags, keep plain text",
      keys:"html strip text clean tags remove markup",                  tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"📡",  label:"HTTP body / headers",
      desc:"Split a raw HTTP request or response",
      keys:"http body headers request response split raw",              tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🛡️", label:"Redact Cookie / Auth headers",
      desc:"Strip Authorization and Cookie from HTTP blobs",
      keys:"redact cookie auth http authorization bearer token header", tab:"utilities",
      run: () => { goTab("utilities"); openSection("decode"); focusEl("util-in"); } },
    { icon:"🕵️", label:"User-agent parser",
      desc:"Parse UA strings — browser, OS, device, engine",
      keys:"user agent ua browser os device parse string chrome edge",  tab:"utilities",
      run: () => { goTab("utilities"); openSection("user-agent"); focusEl("ua-in"); } },
    { icon:"📦",  label:"Bytes converter",
      desc:"Convert between B / KB / MB / GB / TB / PB",
      keys:"bytes kb mb gb tb pb size convert units",                   tab:"utilities",
      run: () => { goTab("utilities"); openSection("bytes"); focusEl("bc-in"); } },
    { icon:"🔢",  label:"Subnet calculator",
      desc:"CIDR range, broadcast, host count, network class",
      keys:"subnet cidr calc network mask range broadcast class scope", tab:"utilities",
      run: () => { goTab("utilities"); openSection("subnet calc"); focusEl("sn-in"); } },
    { icon:"✂️",  label:"Redactor utility",
      desc:"Run your saved redaction patterns on any pasted text",
      keys:"redact utility text strip mask replace patterns",           tab:"utilities",
      run: () => { goTab("utilities"); openSection("redactor"); focusEl("rd-in"); } },
    { icon:"🎯",  label:"Subnet membership check",
      desc:"Does an IP belong to a given network / CIDR / range?",
      keys:"subnet membership ip belongs check cidr range network",     tab:"utilities",
      run: () => { goTab("utilities"); openSection("subnet member"); focusEl("sm-ips"); } },
    // ── History ───────────────────────────────────────────────────────
    { icon:"📚",  label:"History",
      desc:"Browse and filter recently extracted indicators",
      keys:"history recent ioc indicator log view browse",              tab:"history",
      run: () => { goTab("history"); focusEl("history-filter"); } },
    { icon:"📋",  label:"Copy history",
      desc:"Copy all history to clipboard",
      keys:"copy history all clipboard export",                         tab:"history",
      run: () => { goTab("history"); } },
    { icon:"🗑️", label:"Clear history",
      desc:"Delete all saved indicator history",
      keys:"clear delete history reset remove purge",                   tab:"history",
      run: () => { goTab("history"); } },
    // ── Settings ──────────────────────────────────────────────────────
    { icon:"🔑",  label:"API keys",
      desc:"VirusTotal, AbuseIPDB, ipinfo tokens",
      keys:"api key virustotal vt abuseipdb ipinfo token secret",       tab:"settings",
      run: () => { goTab("settings"); openSection("api keys"); } },
    { icon:"🔐",  label:"Encrypt API keys",
      desc:"AES-GCM passphrase protection for stored keys",
      keys:"encrypt passphrase password aes gcm keys protect lock",     tab:"settings",
      run: () => { goTab("settings"); openSection("api keys"); } },
    { icon:"📋",  label:"Copy output fields",
      desc:"Choose which enrichment fields go to clipboard",
      keys:"copy fields enrichment output vt abuse rdap format toggle", tab:"settings",
      run: () => { goTab("settings"); openSection("copy output"); } },
    { icon:"⚡",  label:"Enrichment behavior",
      desc:"Parallel requests, min delay, copy format",
      keys:"enrichment parallel delay rate limit throttle concurrent",  tab:"settings",
      run: () => { goTab("settings"); openSection("enrichment"); } },
    { icon:"🚨",  label:"Detection thresholds",
      desc:"Score cutoffs for warn / malicious flag levels",
      keys:"threshold score warn malicious vt abuseipdb level flag",    tab:"settings",
      run: () => { goTab("settings"); openSection("detection"); } },
    { icon:"⚡",  label:"Auto-extraction sites",
      desc:"Custom domains/URLs where Auto-extract also fires",
      keys:"auto extract url site domain custom qradar kibana siem automatic", tab:"settings",
      run: () => { goTab("settings"); openSection("auto-extraction sites"); } },
    { icon:"🚫",  label:"Excluded domains",
      desc:"Domains where extraction is blocked (e.g. virustotal.com)",
      keys:"exclude domain block list extraction virustotal shodan",     tab:"settings",
      run: () => { goTab("settings"); openSection("extraction sources"); } },
    { icon:"🧹",  label:"Redaction list",
      desc:"Words replaced when the Redact toggle is on",
      keys:"redact list words phrases sensitive replace mask settings",  tab:"settings",
      run: () => { goTab("settings"); openSection("redaction list"); } },
    { icon:"⚙️",  label:"Default output",
      desc:"Default separator, Sanitize/Defang/Numbered/Quoted on open",
      keys:"default separator numbered quoted headers defang sanitize", tab:"settings",
      run: () => { goTab("settings"); openSection("default output"); } },
    { icon:"🔧",  label:"Splunk security controls",
      desc:"Per-control index/sourcetype/fields — multi-source OR/AND/IN hunt queries",
      keys:"splunk security control proxy firewall sysmon email dns dlp edr sourcetype index field hunt", tab:"settings",
      run: () => { goTab("settings"); const el = document.getElementById("spl-controls-group"); if (el) { el.open = true; el.scrollIntoView({behavior:"smooth"}); } } },
    { icon:"🗂️", label:"IOC field names & log locations",
      desc:"Set Splunk field name, index, and sourcetype per IOC category",
      keys:"field name index sourcetype splunk log location ioc category query", tab:"settings",
      run: () => { goTab("settings"); const el = document.getElementById("iocfields-group"); if (el) { el.open = true; el.scrollIntoView({behavior:"smooth"}); } } },
    { icon:"🛡️", label:"Defender KQL tables & columns",
      desc:"Define Defender Advanced Hunting tables with column and operator per IOC category",
      keys:"defender kql table column operator advanced hunting mde atp query mtp controls multi source", tab:"settings",
      run: () => { goTab("settings"); const el = document.getElementById("kql-controls-group"); if (el) { el.open = true; el.scrollIntoView({behavior:"smooth"}); } } },
    { icon:"🛡️", label:"Defender KQL simple fallback",
      desc:"Single-table fallback when no KQL control covers an IOC type",
      keys:"defender kql fallback single table column operator", tab:"settings",
      run: () => { goTab("settings"); const el = document.getElementById("kqlfields-group"); if (el) { el.open = true; el.scrollIntoView({behavior:"smooth"}); } } },
    { icon:"👁️", label:"Categories",
      desc:"Show or hide individual IOC category cards",
      keys:"category show hide ips domains hashes files paths emails",  tab:"settings",
      run: () => { goTab("settings"); openSection("categories"); } },
    { icon:"📖",  label:"History settings",
      desc:"Max entries, grouping, URL logging toggle",
      keys:"history cap limit group url log settings keep save",         tab:"settings",
      run: () => { goTab("settings"); openSection("history"); } },
  ];

  /* ── state ────────────────────────────────────────────────── */
  let displayItems = [];
  let activeIdx    = -1;

  /* ── filter ───────────────────────────────────────────────── */
  function norm(s) { return String(s).toLowerCase().replace(/[^a-z0-9 ]/g, " "); }
  function filterIdx(q) {
    if (!q) return IDX;
    const terms = norm(q).split(/\s+/).filter(Boolean);
    return IDX.filter(it => {
      const hay = norm(`${it.label} ${it.keys} ${it.desc || ""}`);
      return terms.every(t => hay.includes(t));
    });
  }

  /* ── render ───────────────────────────────────────────────── */
  const TAB_ORDER = ["extract","utilities","history","settings"];
  function render(items) {
    displayItems = [];
    activeIdx    = -1;
    if (!items.length) {
      resultsEl.innerHTML = `<div class="sr-empty">No results — try different keywords</div>`;
      return;
    }
    const groups = {};
    for (const it of items) (groups[it.tab] = groups[it.tab] || []).push(it);
    let html = "";
    for (const tab of TAB_ORDER) {
      if (!groups[tab]) continue;
      html += `<div class="sr-group">${tab.charAt(0).toUpperCase() + tab.slice(1)}</div>`;
      for (const it of groups[tab]) {
        displayItems.push(it);
        html += `<div class="sr-item" role="option" aria-selected="false">
          <span class="sr-icon">${it.icon}</span>
          <span class="sr-text">
            <span class="sr-label">${esc(it.label)}</span>
            ${it.desc ? `<span class="sr-desc">${esc(it.desc)}</span>` : ""}
          </span>
        </div>`;
      }
    }
    html += `<div class="sr-hint">↑↓ navigate · Enter select · Esc close</div>`;
    resultsEl.innerHTML = html;
    resultsEl.querySelectorAll(".sr-item").forEach((row, i) => {
      row.addEventListener("mousedown", e => { e.preventDefault(); selectItem(i); });
    });
  }

  /* ── active item ──────────────────────────────────────────── */
  function setActive(idx) {
    const rows = resultsEl.querySelectorAll(".sr-item");
    rows.forEach((r, i) => r.setAttribute("aria-selected", i === idx ? "true" : "false"));
    activeIdx = idx;
    if (rows[idx]) rows[idx].scrollIntoView({ block: "nearest" });
  }

  /* ── select ───────────────────────────────────────────────── */
  function selectItem(idx) {
    const it = displayItems[idx];
    if (!it) return;
    closeSearch();
    it.run();
  }

  /* ── open / close ─────────────────────────────────────────── */
  function openSearch() {
    panel.removeAttribute("hidden");
    input.value = "";
    render(IDX);
    input.focus();
  }
  function closeSearch() {
    panel.setAttribute("hidden", "");
    activeIdx = -1;
  }

  /* ── events ───────────────────────────────────────────────── */
  if (openBtn)  openBtn.addEventListener("click", openSearch);
  if (closeBtn) closeBtn.addEventListener("click", closeSearch);

  input.addEventListener("input", () => render(filterIdx(input.value.trim())));

  input.addEventListener("keydown", e => {
    const rows = resultsEl.querySelectorAll(".sr-item");
    if (e.key === "ArrowDown") {
      e.preventDefault(); setActive(Math.min(activeIdx + 1, rows.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault(); setActive(Math.max(activeIdx - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault(); selectItem(activeIdx >= 0 ? activeIdx : 0);
    } else if (e.key === "Escape") {
      closeSearch();
    }
  });

  /* Close on backdrop click (outside the box) */
  panel.addEventListener("mousedown", e => { if (e.target === panel) closeSearch(); });
})();
