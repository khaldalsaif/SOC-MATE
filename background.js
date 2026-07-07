/* Load the shared pageExtract function so the service worker can run it on
   demand (global Ctrl+E) without duplicating the ~660-line body here. */
importScripts("extract.js");

/* Service worker — live enrichment lookups.
   Runs in the extension background context, so with host_permissions it can
   reach the APIs without CORS issues and keep keys out of page/content scope.
   Keys are read from chrome.storage.local (set by the analyst in Settings).
   Nothing here runs automatically — the popup only messages this worker
   when the analyst explicitly clicks an enrich button.

   Every lookup returns the same shape:
     { summary, level, fields, multiline?, lines? }
   - summary: 1-line briefing for the result span
   - level:   "ok" | "warn" | "bad" | "err"
   - fields:  structured key/value map of everything the API gave us back —
              the popup's per-row "Details" expander renders this, and the
              copy formatters (JSON, Markdown, By-IOC) read it.
   - multiline/lines: optional, for multi-source geo where we want to show
                     one line per source. */

chrome.runtime.onMessage.addListener((req, _sender, sendResponse) => {
  if (req && req.action === "enrich") {
    handleEnrich(req).then(sendResponse).catch(e => sendResponse({ error: String(e), level: "err" }));
    return true; // keep channel open for async response
  }
});

/* ============================================================
   Last-active content tab tracker
   The full-page "workspace" view (popup.html?view=tab) is itself the active
   tab, so chrome.tabs.query({active}) would return the extension page, not the
   analyst's Splunk/Defender tab. We remember the most recently focused real
   web page in chrome.storage.session; the workspace reads it to know what to
   extract from. Only http(s) pages qualify (never the extension's own page).
   ============================================================ */
function recordContentTab(tabId) {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    const url = tab.url || "";
    if (!/^https?:\/\//i.test(url)) return; // ignore the extension page, chrome://, etc.
    chrome.storage.session.set({
      lastContentTab: { id: tab.id, windowId: tab.windowId, url, title: tab.title || "", ts: Date.now() }
    });
    autoExtractBadge(tab.id, url).catch(() => {});
  });
}

/* In-memory throttle: skip re-extraction of the same URL within 60 s.
   Resets on service-worker restart, which is fine — fresh SW means fresh context. */
const _badgeThrottle = {};

async function autoExtractBadge(tabId, url) {
  if (!url || !/^https?:\/\//i.test(url)) return;
  if (/^(chrome|edge|about|view-source|chrome-extension):/i.test(url)) return;
  if (/^https:\/\/chrome(web)?store\.google\.com/i.test(url)) return;

  const now = Date.now();
  if (_badgeThrottle[url] && now - _badgeThrottle[url] < 60000) return;
  _badgeThrottle[url] = now;

  let results;
  try {
    results = await chrome.scripting.executeScript({ target: { tabId }, func: pageExtract });
  } catch (_) { return; }

  if (!results || !results[0] || results[0].error) return;
  const payload = results[0].result;
  if (!payload) return;

  const typed = payload.typed || {};
  const hasIOCs = Object.values(typed).some(v => Array.isArray(v) && v.length > 0);
  if (!hasIOCs) return;

  await chrome.storage.local.set({
    bgExtractPending: {
      text:  payload.text  || "",
      typed,
      procs: payload.procs || [],
      diag:  payload.diag  || {},
      url,
      ts: now
    }
  });

  try {
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    chrome.action.setBadgeText({ text: "●" });
  } catch (_) {}
}
chrome.tabs.onActivated.addListener(({ tabId }) => recordContentTab(tabId));
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab && tab.active) recordContentTab(tabId);
});
chrome.windows.onFocusChanged.addListener((winId) => {
  if (winId === chrome.windows.WINDOW_ID_NONE) return;
  chrome.tabs.query({ active: true, windowId: winId }, (tabs) => {
    if (tabs && tabs[0]) recordContentTab(tabs[0].id);
  });
});

async function handleEnrich({ provider, iocType, value }) {
  // Encrypted mode: keys live in chrome.storage.session.unlockedKeys (set by
  // the popup after a passphrase unlock). Plaintext mode: they're in
  // chrome.storage.local. Try session first, fall back to local.
  const sess = await chrome.storage.session.get(["unlockedKeys"]);
  const keys = (sess && sess.unlockedKeys)
    || await chrome.storage.local.get(["vtKey", "abuseKey", "ipinfoKey"]);
  if (provider === "vt")        return vtLookup(iocType, value, keys.vtKey);
  if (provider === "abuseipdb") return abuseLookup(value, keys.abuseKey);
  if (provider === "rdap")      return rdapLookup(iocType, value);
  if (provider === "multigeo")  return multiGeoLookup(value, keys.ipinfoKey);
  return { error: "Unknown provider" };
}

/* ============================================================
   VirusTotal v3
   ============================================================ */
async function vtLookup(iocType, value, key) {
  if (!key) return { error: "No VirusTotal key (add it in Settings)" };

  let url, vtType;
  if (["ips", "src_ip", "dest_ip"].includes(iocType)) {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
    vtType = "ip";
  } else if (iocType === "domains") {
    url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
    vtType = "domain";
  } else if (iocType === "urls") {
    let id;
    try { id = btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
    catch (e) { return { error: "VT: URL not encodable" }; }
    url = `https://www.virustotal.com/api/v3/urls/${id}`;
    vtType = "url";
  } else if (["md5", "sha1", "sha256"].includes(iocType)) {
    url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
    vtType = "file";
  } else {
    return { error: "VT: unsupported type" };
  }

  let res;
  try { res = await fetch(url, { headers: { "x-apikey": key } }); }
  catch (e) { return { error: "VT: network error" }; }

  if (res.status === 404) return { summary: "VT: not found", level: "ok", fields: { not_found: true } };
  if (res.status === 401) return { error: "VT: bad/expired key" };
  if (res.status === 429) return { error: "VT: rate limited" };
  if (!res.ok)            return { error: `VT: HTTP ${res.status}` };

  let json;
  try { json = await res.json(); } catch (e) { return { error: "VT: bad JSON" }; }

  const attr = (json && json.data && json.data.attributes) || {};
  const s = attr.last_analysis_stats || {};
  const malicious  = s.malicious  || 0;
  const suspicious = s.suspicious || 0;
  const harmless   = s.harmless   || 0;
  const undetected = s.undetected || 0;
  const total      = malicious + suspicious + harmless + undetected;
  const flagged    = malicious + suspicious;

  // Two-tier scoring (warn / bad) from Settings
  const t = await getThresholds();
  let level = "ok";
  if      (flagged >= (t.vt     || 5)) level = "bad";
  else if (flagged >= (t.vtWarn || 1)) level = "warn";

  // Build a rich fields map. Skip empties so the Details view is clean.
  const fields = { type: vtType, malicious, suspicious, harmless, undetected, total };
  const put = (k, v) => { if (v !== undefined && v !== null && v !== "") fields[k] = v; };

  put("threat_label", attr.popular_threat_classification && attr.popular_threat_classification.suggested_threat_label);
  put("reputation",   typeof attr.reputation === "number" ? attr.reputation : undefined);
  if (attr.first_submission_date)        put("first_seen",     toIso(attr.first_submission_date));
  if (attr.creation_date)                put("creation_date",  toIso(attr.creation_date));
  if (attr.last_analysis_date)           put("last_analyzed",  toIso(attr.last_analysis_date));
  if (attr.last_modification_date)       put("last_modified",  toIso(attr.last_modification_date));

  // Type-specific extras
  if (vtType === "ip") {
    put("country",    attr.country);
    put("as_owner",   attr.as_owner);
    put("asn",        attr.asn);
    put("network",    attr.network);
  } else if (vtType === "domain") {
    put("registrar",  attr.registrar);
    if (attr.categories && typeof attr.categories === "object") {
      const cats = [...new Set(Object.values(attr.categories))].filter(Boolean);
      if (cats.length) put("categories", cats.join(", "));
    }
  } else if (vtType === "url") {
    put("final_url",  attr.last_final_url || attr.url);
    put("title",      attr.title);
  } else if (vtType === "file") {
    put("file_name",  (attr.meaningful_name) || (Array.isArray(attr.names) ? attr.names[0] : undefined));
    put("file_size",  attr.size);
    put("file_type",  attr.type_description || attr.type_tag);
    put("md5",        attr.md5);
    put("sha1",       attr.sha1);
    put("sha256",     attr.sha256);
    put("signed",     attr.signature_info ? "yes" : undefined);
    if (Array.isArray(attr.tags) && attr.tags.length) put("tags", attr.tags.slice(0, 6).join(", "));
  }

  // Summary line — concise verdict
  const pct = total ? Math.round((flagged / total) * 100) : 0;
  let summary;
  if (level === "ok")        summary = `VT 0/${total} clean`;
  else if (level === "warn") summary = `VT ${malicious}/${total} (low, ${pct}%)`;
  else                       summary = `VT ${malicious}/${total} malicious (${pct}%)`;
  if (suspicious) summary += ` +${suspicious} susp`;
  if (fields.threat_label) summary += " · " + fields.threat_label;

  return { summary, level, fields };
}

/* ============================================================
   AbuseIPDB v2
   ============================================================ */
async function abuseLookup(value, key) {
  if (!key) return { error: "No AbuseIPDB key (add it in Settings)" };

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`;
  let res;
  try { res = await fetch(url, { headers: { Key: key, Accept: "application/json" } }); }
  catch (e) { return { error: "AbuseIPDB: network error" }; }

  if (res.status === 401) return { error: "AbuseIPDB: bad key" };
  if (res.status === 429) return { error: "AbuseIPDB: rate limited" };
  if (!res.ok)            return { error: `AbuseIPDB: HTTP ${res.status}` };

  let json;
  try { json = await res.json(); } catch (e) { return { error: "AbuseIPDB: bad JSON" }; }

  const d = json && json.data;
  if (!d) return { error: "AbuseIPDB: no data" };

  const score = d.abuseConfidenceScore || 0;
  const t = await getThresholds();
  let level = "ok";
  if      (score >= (t.abuse     || 75)) level = "bad";
  else if (score >= (t.abuseWarn || 25)) level = "warn";

  const fields = {};
  const put = (k, v) => { if (v !== undefined && v !== null && v !== "") fields[k] = v; };
  put("score",         score);
  put("total_reports", d.totalReports);
  put("country",       d.countryName);
  put("country_code",  d.countryCode);
  put("isp",           d.isp);
  put("domain",        d.domain);
  put("usage_type",    d.usageType);
  put("is_tor",        d.isTor ? "yes" : undefined);
  put("is_whitelisted",d.isWhitelisted ? "yes" : undefined);
  if (Array.isArray(d.hostnames) && d.hostnames.length) put("hostnames", d.hostnames.slice(0, 5).join(", "));
  if (d.lastReportedAt) put("last_reported", d.lastReportedAt.slice(0, 10));

  let summary = `Abuse ${score}% (${d.totalReports || 0} reports, ${withFlag(d.countryCode, d.countryCode || "??")})`;
  if (d.isTor) summary += " · TOR";
  if (d.isWhitelisted) summary = "Abuse whitelisted (override)";

  return { summary, level, fields };
}

async function getThresholds() {
  const d = await chrome.storage.local.get(["thresholds"]);
  return Object.assign({ vt: 5, vtWarn: 1, abuse: 75, abuseWarn: 25 }, d.thresholds || {});
}

/* ============================================================
   RDAP (free, no key)
   ============================================================ */
async function rdapLookup(iocType, value) {
  let url, kind;
  if (["ips", "src_ip", "dest_ip"].includes(iocType)) {
    url = `https://rdap.org/ip/${encodeURIComponent(value)}`;
    kind = "ip";
  } else if (["domains", "hostnames"].includes(iocType)) {
    url = `https://rdap.org/domain/${encodeURIComponent(value)}`;
    kind = "domain";
  } else {
    return { error: "RDAP: unsupported type" };
  }

  let res;
  try { res = await fetch(url, { headers: { Accept: "application/rdap+json" } }); }
  catch (e) { return { error: "RDAP: network error" }; }

  if (res.status === 404) return { summary: "RDAP: not found", level: "ok", fields: { not_found: true } };
  if (!res.ok)            return { error: `RDAP: HTTP ${res.status}` };

  let json;
  try { json = await res.json(); } catch (e) { return { error: "RDAP: bad JSON" }; }

  const fields = { type: kind };
  const put = (k, v) => { if (v !== undefined && v !== null && v !== "") fields[k] = v; };

  if (kind === "ip") {
    put("network", (json.startAddress && json.endAddress) ? `${json.startAddress} - ${json.endAddress}` : undefined);
    put("name",    json.name);
    put("country", json.country);
    put("handle",  json.handle);
    // Abuse contact (look inside entities)
    for (const ent of (json.entities || [])) {
      if ((ent.roles || []).includes("abuse")) {
        const vcard = ent.vcardArray && ent.vcardArray[1];
        if (Array.isArray(vcard)) {
          const email = vcard.find(f => f[0] === "email");
          if (email) { put("abuse_email", email[3]); break; }
        }
      }
    }
    const bits = [fields.name, fields.country].filter(Boolean);
    return { summary: "RDAP: " + (bits.length ? bits.join(" · ") : "allocated"), level: "ok", fields };
  }

  // Domain
  let created = "", expires = "", lastChanged = "";
  for (const ev of (json.events || [])) {
    if (ev.eventAction === "registration") created = (ev.eventDate || "").slice(0, 10);
    if (ev.eventAction === "expiration")   expires = (ev.eventDate || "").slice(0, 10);
    if (ev.eventAction === "last changed") lastChanged = (ev.eventDate || "").slice(0, 10);
  }
  let registrar = "";
  for (const ent of (json.entities || [])) {
    if ((ent.roles || []).includes("registrar")) {
      const vcard = ent.vcardArray && ent.vcardArray[1];
      if (Array.isArray(vcard)) {
        const fn = vcard.find(f => f[0] === "fn");
        if (fn) registrar = fn[3];
      }
      if (!registrar) registrar = ent.handle || "";
    }
  }
  let nameservers = [];
  if (Array.isArray(json.nameservers)) {
    nameservers = json.nameservers.map(n => (n.ldhName || n.unicodeName || "").toLowerCase()).filter(Boolean);
  }
  let status = [];
  if (Array.isArray(json.status)) status = json.status;

  put("registrar",   registrar);
  put("registered",  created);
  put("expires",     expires);
  put("last_changed",lastChanged);
  if (nameservers.length) put("nameservers", nameservers.slice(0, 4).join(", "));
  if (status.length)      put("status",      status.slice(0, 4).join(", "));

  // Age check — domains <30 days are a phishing tell
  let level = "ok", ageNote = "";
  if (created) {
    const days = Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
    if (!isNaN(days)) {
      put("age_days", days);
      ageNote = ` (${days}d old)`;
      if (days <= 30) level = "warn";
    }
  }

  const bits = [];
  if (created)   bits.push("reg " + created + ageNote);
  if (registrar) bits.push(registrar);
  if (expires)   bits.push("exp " + expires);
  return { summary: "RDAP: " + (bits.length ? bits.join(" · ") : "no dates"), level, fields };
}

/* ============================================================
   Multi-source geo (HTTPS only)
   ============================================================ */
function flagEmoji(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return "";
  const base = 0x1F1E6;
  const up = cc.toUpperCase();
  return String.fromCodePoint(base + (up.charCodeAt(0) - 65), base + (up.charCodeAt(1) - 65));
}
function withFlag(cc, text) {
  const f = flagEmoji(cc);
  return f ? `${f} ${text}` : text;
}

async function multiGeoLookup(value, ipinfoKey) {
  const tasks = [];

  tasks.push((async () => {
    try {
      const r = await fetch(`https://ipwho.is/${encodeURIComponent(value)}`);
      if (!r.ok) return { src: "ipwho.is", text: `HTTP ${r.status}` };
      const j = await r.json();
      if (j.success === false) return { src: "ipwho.is", text: j.message || "no data" };
      return {
        src: "ipwho.is",
        cc: j.country_code || "",
        country: j.country,
        city: j.city,
        region: j.region,
        isp: j.connection && j.connection.isp,
        asn: j.connection && j.connection.asn,
        text: [j.country_code, j.city].filter(Boolean).join(", ") || "no data"
      };
    } catch (_) { return { src: "ipwho.is", text: "network error" }; }
  })());

  tasks.push((async () => {
    try {
      const r = await fetch(`https://rdap.org/ip/${encodeURIComponent(value)}`, { headers: { Accept: "application/rdap+json" } });
      if (!r.ok) return { src: "RDAP (registry)", text: `HTTP ${r.status}` };
      const j = await r.json();
      return {
        src: "RDAP (registry)",
        cc: j.country || "",
        country: j.country,
        name: j.name,
        text: j.country || "allocated"
      };
    } catch (_) { return { src: "RDAP (registry)", text: "network error" }; }
  })());

  if (ipinfoKey) {
    tasks.push((async () => {
      try {
        const r = await fetch(`https://ipinfo.io/${encodeURIComponent(value)}?token=${encodeURIComponent(ipinfoKey)}`, { headers: { Accept: "application/json" } });
        if (!r.ok) return { src: "ipinfo", text: `HTTP ${r.status}` };
        const j = await r.json();
        if (j.bogon) return { src: "ipinfo", text: "bogon/reserved" };
        return {
          src: "ipinfo",
          cc: j.country || "",
          country: j.country,
          city: j.city,
          region: j.region,
          org: j.org,
          hostname: j.hostname,
          text: [j.country, j.city].filter(Boolean).join(", ") || "no data"
        };
      } catch (_) { return { src: "ipinfo", text: "network error" }; }
    })());
  }

  const results = await Promise.all(tasks);
  const ccs = [...new Set(results.map(r => (r.cc || "").toUpperCase()).filter(Boolean))];

  // Flatten into a fields map: ipwho_country, rdap_country, ipinfo_country, etc.
  const fields = {};
  for (const r of results) {
    const prefix = r.src.replace(/[^a-z0-9]+/gi, "_").toLowerCase();
    for (const k of Object.keys(r)) {
      if (k === "src" || k === "cc" || k === "text") continue;
      if (r[k] !== undefined && r[k] !== null && r[k] !== "") fields[`${prefix}_${k}`] = r[k];
    }
  }
  if (ccs.length === 1) fields.country = ccs[0];
  if (ccs.length > 1)   fields.country_disagreement = ccs.join(" vs ");

  const lines = results.map(r => `${r.src}: ${r.cc ? withFlag(r.cc, r.text) : r.text}`);
  const header = ccs.length > 1 ? `Geo (differ: ${ccs.map(c => withFlag(c, c)).join(" vs ")})` : "Geo";

  return {
    multiline: true,
    summary: header,
    lines,
    level: ccs.length > 1 ? "warn" : "ok",
    fields
  };
}

/* Helper: VT timestamps are seconds-since-epoch */
function toIso(secs) {
  if (typeof secs !== "number") return "";
  try { return new Date(secs * 1000).toISOString().slice(0, 10); } catch (_) { return ""; }
}

/* ============================================================
   Global keyboard shortcut — Ctrl+E (Windows/Linux) / Cmd+E (Mac)
   Fires via Chrome Commands API even when the SOC Mate popup is closed.
   Runs pageExtract on the last focused real web page, stores the raw
   result as bgExtractPending in chrome.storage.local.

   Any open popup/workspace tab picks it up immediately via
   chrome.storage.onChanged → processIOCs().  If no popup is open the
   result waits in storage and is consumed the next time SOC Mate opens
   (checkBgExtractPending() runs after restoreLastExtraction() in the
   startup sequence).
   ============================================================ */
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "extract-page") return;

  /* Use the last real content tab recorded by the tab tracker above. */
  const sess = await chrome.storage.session.get(["lastContentTab"]);
  const lct  = sess && sess.lastContentTab;
  if (!lct || !lct.id) return;

  let tab;
  try { tab = await chrome.tabs.get(lct.id); }
  catch (_) { return; }
  const url = (tab && tab.url) || "";
  if (!url || !/^https?:\/\//i.test(url)) return;

  /* Same guard the popup uses — Chrome blocks scripting on these URLs. */
  if (/^(chrome|edge|about|view-source|chrome-extension):/i.test(url) ||
      /^https:\/\/chrome\.google\.com\/webstore/i.test(url) ||
      /^https:\/\/chromewebstore\.google\.com/i.test(url)) return;

  let results;
  try {
    results = await chrome.scripting.executeScript({
      target: { tabId: lct.id },
      func: pageExtract
    });
  } catch (_) { return; }

  if (!results || !results[0] || results[0].error) return;
  const payload = results[0].result;
  if (!payload || typeof payload.text !== "string") return;

  /* Store for any open popup/workspace tab to pick up via onChanged,
     or for the next popup open to consume via checkBgExtractPending(). */
  const ts = Date.now();
  await chrome.storage.local.set({
    bgExtractPending: {
      text:  payload.text,
      typed: payload.typed || {},
      procs: payload.procs || [],
      diag:  payload.diag  || {},
      url,
      ts
    }
  });

  /* Persistent red dot — stays on the icon until the popup is opened. */
  try {
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    chrome.action.setBadgeText({ text: "●" });
  } catch (_) { /* non-fatal if badge API unavailable */ }
});
