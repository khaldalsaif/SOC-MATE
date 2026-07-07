/* ============================================================
   SOC Mate — pageExtract
   Runs INSIDE a target tab via chrome.scripting.executeScript.
   Self-contained: no references to popup.js or background.js.
   Loaded by popup.html (before popup.js) so the name is
   available as a global, and imported by background.js via
   importScripts so the service worker can also call it.
   ============================================================ */
/* Extraction logic that runs INSIDE the target tab. Self-contained — it gets
   serialized to source and shipped over, so it can't reference popup.js
   variables. Returns { text, typed, diag } the same shape the popup expects. */
function pageExtract() {
  const SEP = "[\\s_\\-]?";
  const FIELD_MAP = [
    [new RegExp(`^(src|source|client)(${SEP}(ip|addr|address))?$`, "i"), "src_ip"],
    [new RegExp(`^(sourceip|srcip|c${SEP}ip)$`, "i"), "src_ip"],
    [new RegExp(`^(dst|dest|destination|remote|target|server)(${SEP}(ip|addr|address))?$`, "i"), "dest_ip"],
    [new RegExp(`^(destinationip|destip|remoteip|s${SEP}ip)$`, "i"), "dest_ip"],
    [/^(ip|addr|address)$/i, "ips"],
    [/^(query|domain|dns|host_?domain|dest_?dns)$/i, "domains"],
    [/^(destinationhostname|remoteurl)$/i, "domains"],
    [/^(url|uri|uri_?path|http_?uri|request_?uri|referer|referrer)$/i, "urls"],
    [/^(email|sender|recipient|mail_?from|rcpt_?to)$/i, "emails"],
    [/^(senderfromaddress|recipientemailaddress)$/i, "emails"],
    [/^(subject|email_?subject|mail_?subject)$/i, "email_subjects"],
    [/^(host|hostname|computer|computer_?name|device_?name|workstation|dvc|machine|dns_?hostname)$/i, "hostnames"],
    [/^(file_?name|filename|target_?filename|original_?file_?name)$/i, "files"],
    [/^(file_?path|folder_?path|path|image|parent_?image|target_?object)$/i, "paths"],
    [/^md5(_?hash)?$/i, "md5"],
    [/^sha1(_?hash)?$/i, "sha1"],
    [/^sha256(_?hash)?$/i, "sha256"],
    [/^cve$/i, "cves"],
    [/^(user_?agent|ua|http_?user_?agent|client_?agent)$/i, "user_agents"]
  ];
  /* Defender Advanced Hunting schema columns — direct lookup (key is lowercased
     with all separators stripped) so "RemoteIP", "remote_ip", "remote-ip" all
     hit the same entry. Direction matters: Remote = destination, Local = source. */
  const DEFENDER_FIELD_MAP = {
    remoteip: "dest_ip", localip: "src_ip",
    initiatingprocessremoteip: "dest_ip", initiatingprocesslocalip: "src_ip",
    publicip: "ips", ipaddress: "ips",
    remoteurl: "urls", initiatingprocessurl: "urls",
    urldomain: "domains", domainname: "domains", remoteurldomain: "domains",
    devicename: "hostnames", remotedevicename: "hostnames",
    computerdnsname: "hostnames", dnshostname: "hostnames",
    filename: "files", initiatingprocessfilename: "files",
    parentfilename: "files", parentprocessfilename: "files",
    folderpath: "paths", initiatingprocessfolderpath: "paths",
    sha256: "sha256", initiatingprocesssha256: "sha256", filehashsha256: "sha256",
    sha1: "sha1", initiatingprocesssha1: "sha1", filehashsha1: "sha1",
    md5: "md5", initiatingprocessmd5: "md5", filehashmd5: "md5",
    senderfromaddress: "emails", senderdisplayedfromaddress: "emails",
    recipientemailaddress: "emails", accountupn: "emails",
    subject: "email_subjects", emailsubject: "email_subjects",
    useragent: "user_agents", httpuseragent: "user_agents",
    cveid: "cves"
  };
  const normField = (n) => String(n || "").trim().replace(/^\W+|\W+$/g, "");
  const categoryFor = (n) => {
    const fn = normField(n);
    if (!fn) return null;
    // Defender schema columns first (exact match on normalised name)
    const norm = fn.toLowerCase().replace(/[_\s\-]/g, "");
    if (DEFENDER_FIELD_MAP[norm]) return DEFENDER_FIELD_MAP[norm];
    // Generic regex map (Splunk fields + user-friendly names)
    for (const [re, cat] of FIELD_MAP) if (re.test(fn)) return cat;
    return null;
  };
  function splitHashes(raw) {
    const out = { md5: [], sha1: [], sha256: [] };
    String(raw).split(",").forEach(part => {
      const m = part.match(/^\s*(MD5|SHA1|SHA256|IMPHASH)\s*=\s*([A-Fa-f0-9]+)/i);
      if (!m) return;
      const algo = m[1].toUpperCase(), v = m[2];
      if      (algo === "MD5"     && v.length === 32) out.md5.push(v);
      else if (algo === "SHA1"    && v.length === 40) out.sha1.push(v);
      else if (algo === "SHA256"  && v.length === 64) out.sha256.push(v);
      else if (algo === "IMPHASH" && v.length === 32) out.md5.push(v);
    });
    return out;
  }
  const isSplunkPage = () => {
    if (document.querySelector("table.table-drilldown-cell")) return true;
    if (document.querySelector("table.events-results-table")) return true;
    if (document.querySelector(".search-results-eventspane-fieldsviewer")) return true;
    if (document.querySelector('[data-component^="splunk-"]')) return true;
    if (document.querySelector('[data-test^="search-results"]')) return true;
    if (document.querySelector(".shared-resultstable-resultstabletbody")) return true;
    if (document.querySelector(".results-table-results")) return true;
    if (/\/(en-[A-Z]{2})\/app\//.test(location.pathname)) return true;
    if (/splunk/i.test(document.title)) return true;
    return false;
  };
  function makeSink() {
    const bag = {};
    const push = (cat, val) => {
      if (!cat || val == null) return;
      const s = String(val).trim().replace(/^["']|["']$/g, "");
      if (!s) return;
      if (!bag[cat]) bag[cat] = new Set();
      bag[cat].add(s);
    };
    const pushFieldValue = (field, value) => {
      if (!field || value == null) return;
      if (/^hashes$/i.test(normField(field))) {
        const h = splitHashes(value);
        h.md5.forEach(v => push("md5", v));
        h.sha1.forEach(v => push("sha1", v));
        h.sha256.forEach(v => push("sha256", v));
        return;
      }
      const cat = categoryFor(field);
      if (!cat) return;
      if (/^(image|parent_?image)$/i.test(normField(field))) {
        push("paths", value);
        const seg = String(value).split(/[\\/]/).pop();
        if (seg && /\.[A-Za-z0-9]{1,8}$/.test(seg)) push("files", seg);
        return;
      }
      push(cat, value);
    };
    return {
      push, pushFieldValue,
      snapshot: () => { const o = {}; for (const k of Object.keys(bag)) o[k] = [...bag[k]]; return o; },
      size:     () => { let n = 0; for (const k of Object.keys(bag)) n += bag[k].size; return n; }
    };
  }
  function headerName(th) {
    const cand =
      th.getAttribute("data-sort-key") ||
      th.getAttribute("data-field-name") ||
      th.getAttribute("data-name") ||
      th.getAttribute("data-field") ||
      (th.querySelector("a, span, div") ? th.querySelector("a, span, div").textContent : "") ||
      th.textContent ||
      "";
    return normField(cand);
  }
  function readStatistics(sink, diag) {
    const tables = document.querySelectorAll(
      "table.table-drilldown-cell, table.shared-resultstable, table.results-table-table, .shared-resultstable-resultstabletbody table, .results-table-results table"
    );
    diag.statTables = tables.length;
    tables.forEach(tbl => {
      const heads = [...tbl.querySelectorAll("thead th")].map(headerName);
      if (!heads.filter(Boolean).length) return;
      diag.statHeaders = (diag.statHeaders || []).concat(heads.filter(Boolean));
      tbl.querySelectorAll("tbody tr").forEach(tr => {
        const cells = [...tr.querySelectorAll("td")];
        cells.forEach((td, i) => {
          const ciAttr = td.getAttribute("data-cell-index");
          const ci = ciAttr != null ? +ciAttr : i;
          const field = heads[ci] || heads[i];
          if (!field) return;
          const subcells = td.querySelectorAll(".multivalue-subcell, .multivalue-list .multivalue-subcell");
          if (subcells.length) subcells.forEach(sc => sink.pushFieldValue(field, (sc.textContent || "").trim()));
          else                 sink.pushFieldValue(field, (td.textContent || "").trim());
        });
      });
    });
  }
  function readEvents(sink, diag) {
    const tables = document.querySelectorAll(
      "table.events-results-table, .shared-eventsviewer table, .search-results-eventspane table"
    );
    diag.eventTables = tables.length;
    tables.forEach(table => {
      const chips = table.querySelectorAll("a.f-v[data-field-name], [data-field-name]");
      diag.chipCount = (diag.chipCount || 0) + chips.length;
      chips.forEach(a => {
        const field = a.getAttribute("data-field-name");
        if (!field) return;
        const text = (a.textContent || "").trim();
        const eq = text.indexOf("=");
        const value = eq > 0 ? text.slice(eq + 1).trim() : text;
        sink.pushFieldValue(field, value);
      });
      const trees = table.querySelectorAll(".json-tree");
      diag.jsonTrees = (diag.jsonTrees || 0) + trees.length;
      trees.forEach(tree => {
        tree.querySelectorAll("span.key").forEach(keySpan => {
          const nameEl = keySpan.querySelector(":scope > .key-name, .key-name");
          if (!nameEl) return;
          const field = (nameEl.textContent || "").trim();
          const valEl = keySpan.querySelector(":scope > .t.string, :scope > .t.number, :scope > .t");
          if (!valEl) return;
          sink.pushFieldValue(field, (valEl.textContent || "").trim());
        });
      });
      table.querySelectorAll(".kv .key, [data-field]").forEach(el => {
        const field = el.getAttribute("data-field") || el.textContent;
        const valEl = el.nextElementSibling;
        if (!field || !valEl) return;
        sink.pushFieldValue(field, (valEl.textContent || "").trim());
      });
    });
  }
  function readSidebar(sink, diag) {
    const root = document.querySelector(".search-results-eventspane-fieldsviewer");
    if (!root) return;
    const rows = root.querySelectorAll(".field, [data-field]");
    diag.sidebarRows = rows.length;
    rows.forEach(row => {
      const nameEl = row.querySelector(".field-name, [data-field-name]");
      if (!nameEl) return;
      const field = (nameEl.getAttribute("data-field-name") || nameEl.textContent || "").trim();
      row.querySelectorAll(".field-value").forEach(vEl => {
        sink.pushFieldValue(field, (vEl.textContent || "").trim());
      });
    });
  }

  /* Defender XDR detector. Hosts: security.microsoft.com (current portal) and
     securitycenter.microsoft.com (legacy MDATP). Both render results via
     Fluent UI v8 DetailsList → role="grid" + ms-DetailsList classnames. */
  const isDefenderPage = () => {
    if (!/^(security|securitycenter)\.microsoft\.com$/.test(location.host)) return false;
    if (!document.querySelector('[role="grid"]')) return false;
    if (!document.querySelector('[class*="ms-DetailsList"]')) return false;
    return true;
  };

  /* Defender Fluent v8 DetailsList walker. Handles two grid shapes both based
     on the same DOM scaffolding (role=grid + DetailsList classes):

     1. Advanced Hunting results — columns are KQL column names like RemoteIP,
        SHA256. Use the data-automation-key attribute as the field name and let
        pushFieldValue → categoryFor → DEFENDER_FIELD_MAP do the mapping.

     2. Incident → Evidence and Response — columns are entityName, entityType,
        impactedAssets, etc. The TYPE of the value is in the row's entityType
        cell, not the column header. Per-row: read entityType → map to category,
        read entityName → strip per-type noise (e.g. "cmd.exe (PID: 11948)"
        becomes "cmd.exe").

     Visible cell text doubles because Fluent wraps the value in a visible span
     plus a tooltip; the leaf-text walker dedupes consecutive duplicates. */
  function readDefenderAH(sink, diag) {
    const grid = document.querySelector('[role="grid"]');
    if (!grid) return;
    diag.defGrid = true;

    const headers = [...grid.querySelectorAll('[role="columnheader"][data-item-key]')]
      .map(h => h.getAttribute("data-item-key")).filter(Boolean);
    diag.defHeaders = headers;

    // Fluent UI icons render as private-use-area glyphs (U+E000–U+F8FF, plus
     // supplementary PUA U+F0000–U+FFFFD and U+100000–U+10FFFD). Strip them out
     // before we see the cell text so icon characters don't leak into IOC values.
    const ICON_RE = /[-]|\uD83F[\uDF00-\uDFFD]|[\uDB80-\uDBBF][\uDC00-\uDFFF]/g;
    function leafText(el) {
      const leaves = [];
      (function walk(n) {
        if (n.nodeType === 3) {
          const t = n.textContent.replace(ICON_RE, "").trim();
          if (t) leaves.push(t);
        } else if (n.nodeType === 1) {
          for (const c of n.childNodes) walk(c);
        }
      })(el);
      const uniq = [];
      for (const t of leaves) if (uniq[uniq.length - 1] !== t) uniq.push(t);
      return uniq.join(" ").trim();
    }

    // Push an entity given its type label and display name.
    function pushEntity(type, name) {
      if (!type || !name) return;
      const t = String(type).toLowerCase().trim();
      if (t === "process") {
        // "cmd.exe (PID: 11948)" → "cmd.exe"
        const stripped = name.split(/\s*\(PID:/i)[0].trim();
        sink.push("files", stripped);
      } else if (t === "file") {
        sink.push("files", name);
      } else if (t === "ip address" || t === "ip" || t === "ipv4" || t === "ipv6") {
        sink.push("ips", name);
      } else if (t === "url") {
        sink.push("urls", name);
      } else if (t === "domain" || t === "dns") {
        sink.push("domains", name);
      } else if (t === "device" || t === "machine" || t === "computer") {
        sink.push("hostnames", name);
      } else if (t === "mailbox") {
        sink.push("emails", name);
      } else if (t === "mail message" || t === "mailmessage" || t === "email message") {
        sink.push("email_subjects", name);
      } else if (t === "account" || t === "user" || t === "user account") {
        if (/@/.test(name) || /^[^\\]+$/.test(name)) sink.push("emails", name);
        // else skip "DOMAIN\username" — not an IOC of any category
      }
      // unknown types (Registry key, Cloud application, …) — skip
    }

    // Mode 2: Incident Evidence grid (per-row entityType drives interpretation)
    if (headers.includes("entityType") && headers.includes("entityName")) {
      diag.defMode = "incident-evidence";
      const rows = [...grid.querySelectorAll('[role="row"]')]
        .filter(r => !r.querySelector('[role="columnheader"]'));
      diag.defRows = rows.length;
      let pushed = 0;
      rows.forEach(row => {
        let entityType = "", entityName = "", impactedAssets = "";
        row.querySelectorAll('[role="gridcell"][data-automation-key]').forEach(c => {
          const k = c.getAttribute("data-automation-key");
          if      (k === "entityType")     entityType     = leafText(c);
          else if (k === "entityName")     entityName     = leafText(c);
          else if (k === "impactedAssets") impactedAssets = leafText(c);
        });
        const before = sink.size();
        pushEntity(entityType, entityName);
        if (impactedAssets) sink.push("hostnames", impactedAssets);
        if (sink.size() > before) pushed++;
      });
      diag.defPushed = pushed;
      return;
    }

    // Mode 1: AH-style grid (column header is the field name)
    diag.defMode = "ah";
    const cells = [...grid.querySelectorAll('[role="gridcell"][data-automation-key]')];
    diag.defCells = cells.length;
    cells.forEach(cell => {
      const col = cell.getAttribute("data-automation-key");
      if (!col) return;
      const value = leafText(cell);
      if (!value) return;
      sink.pushFieldValue(col, value);
    });
  }

  /* Defender process lineage + command lines.
     Unlike the IOC walker (which flattens everything into category Sets), this
     keeps each process as a structured record so the popup can render the
     parent→child tree and show command lines verbatim. Two grid shapes:

       • Advanced Hunting — each row carries the whole chain in columns:
         InitiatingProcessParentFileName → InitiatingProcess* (initiator) →
         FileName/Process* (child), each with PID + command line + folder.
       • Incident Evidence — Process entities give "name (PID: N)" only; the
         command line lives in the side flyout, not the grid, so we capture
         name + pid and leave cmd empty.

     Rows are virtualized by Fluent, so only currently-rendered rows are seen —
     same limitation as the IOC walker. Returns an array of records. */
  function collectDefenderProcs(grid) {
    if (!grid) return [];
    const ICON = /[-]|\uD83F[\uDF00-\uDFFD]|[\uDB80-\uDBBF][\uDC00-\uDFFF]/g;
    const txt = (el) => {
      if (!el) return "";
      const leaves = [];
      (function walk(n) {
        if (n.nodeType === 3) { const t = n.textContent.replace(ICON, "").trim(); if (t) leaves.push(t); }
        else if (n.nodeType === 1) { for (const c of n.childNodes) walk(c); }
      })(el);
      const uniq = [];
      for (const t of leaves) if (uniq[uniq.length - 1] !== t) uniq.push(t);
      return uniq.join(" ").trim();
    };
    const norm = (s) => String(s || "").toLowerCase().replace(/[_\s\-]/g, "");
    const headers = [...grid.querySelectorAll('[role="columnheader"][data-item-key]')]
      .map(h => h.getAttribute("data-item-key") || "").filter(Boolean);
    const hset = new Set(headers.map(norm));
    const rows = [...grid.querySelectorAll('[role="row"]')]
      .filter(r => !r.querySelector('[role="columnheader"]'));

    const out = [], seen = new Set();
    const add = (rec) => {
      if (!rec.name && !rec.cmd && !rec.pname) return; // require something useful
      const key = [rec.name, rec.pid, rec.cmd, rec.pname, rec.ppid].join("|");
      if (seen.has(key)) return;
      seen.add(key);
      out.push(rec);
    };

    // Advanced Hunting: any process column present → read the per-row chain.
    const hasProcCols = hset.has("processcommandline") || hset.has("initiatingprocesscommandline")
      || hset.has("initiatingprocessfilename") || (hset.has("filename") && hset.has("processid"));
    if (hasProcCols) {
      for (const row of rows) {
        const cell = {};
        row.querySelectorAll('[role="gridcell"][data-automation-key]').forEach(c => {
          cell[norm(c.getAttribute("data-automation-key"))] = txt(c);
        });
        add({
          name:    cell.filename || "",
          pid:     cell.processid || "",
          cmd:     cell.processcommandline || "",
          folder:  cell.folderpath || "",
          sha256:  cell.sha256 || "",
          account: cell.accountname || cell.accountupn || "",
          pname:   cell.initiatingprocessfilename || "",
          ppid:    cell.initiatingprocessid || "",
          pcmd:    cell.initiatingprocesscommandline || "",
          pfolder: cell.initiatingprocessfolderpath || "",
          gpname:  cell.initiatingprocessparentfilename || "",
          gppid:   cell.initiatingprocessparentid || "",
          source:  "ah"
        });
      }
      return out;
    }

    // Incident Evidence: Process entities only (name + PID).
    if (hset.has("entitytype") && hset.has("entityname")) {
      for (const row of rows) {
        let etype = "", ename = "";
        row.querySelectorAll('[role="gridcell"][data-automation-key]').forEach(c => {
          const k = c.getAttribute("data-automation-key");
          if      (k === "entityType") etype = txt(c);
          else if (k === "entityName") ename = txt(c);
        });
        if (!/process/i.test(etype)) continue;
        const m = ename.match(/^(.*?)\s*\(PID:\s*(\d+)\)\s*$/i);
        add({ name: m ? m[1].trim() : ename.trim(), pid: m ? m[2] : "", cmd: "", source: "evidence" });
      }
      return out;
    }

    return out;
  }

  /* Defender alert-story "Process tree" widget walker.

     The alert story (security.microsoft.com/alerts/...) does NOT render
     processes as a Fluent DetailsList. Each process is a bespoke node:

        [PID] <name>   <tag>          ← header
        Command line          "..."   ← expandable key/value detail grid
        Process id            8268
        Execution details     Token elevation: ..., Integrity level: ...
        Image file path       C:\...\cmd.exe
        Image file SHA1       <hash>
        User                  DOMAIN\user
        ...

     Detail rows only exist in the DOM once a node is EXPANDED — clicking
     "Expand all" in the widget surfaces command lines for every node. Most
     values are plain text, but the copy-enabled fields (command line, hashes)
     keep their real value inside a nested <input> while the cell's textContent
     is just the "Copy to clipboard" affordance.

     Every class name here (item-822, css-fm3am8, css-1am013d, ...) is an
     emotion hash that changes between Defender builds, so we anchor purely on
     the visible LABEL text and DOM shape, never the hashed classes. */
  function collectProcessTree() {
    const out = [], seen = new Set();

    // Direct text of an element, ignoring descendant elements (the Copy button,
    // icons, nested labels) so a label cell reads as just its own caption.
    const directText = (el) => {
      let s = "";
      for (const n of el.childNodes) if (n.nodeType === 3) s += n.nodeValue;
      return s.trim();
    };
    // Value of a key/value "message" cell. Prefer a nested code-snippet input
    // (command line / hashes carry their real value there). Otherwise read the
    // leaf text — but Fluent mirrors each value into a tooltip host, so the same
    // string appears twice in a row; collapse consecutive duplicates and strip
    // transient affordance labels ("Copy to clipboard", "Loading actions").
    const cellValue = (el) => {
      if (!el) return "";
      const inp = el.querySelector("input, textarea");
      if (inp && inp.value) return inp.value.trim();
      const leaves = [];
      (function walk(n) {
        if (n.nodeType === 3) { const t = n.nodeValue.replace(/\s+/g, " ").trim(); if (t) leaves.push(t); }
        else if (n.nodeType === 1) { for (const c of n.childNodes) walk(c); }
      })(el);
      const uniq = [];
      for (const t of leaves) if (uniq[uniq.length - 1] !== t) uniq.push(t);
      return uniq.join(" ")
        .replace(/\s*Copy to clipboard\s*/gi, " ")
        .replace(/\s*Loading actions\s*/gi, " ")
        .replace(/\s+/g, " ").trim();
    };
    // True when an element actually occupies layout space. Fluent mirrors each
    // value into a hidden tooltip host, so every [PID] bracket exists twice — the
    // real one with geometry and a 0x0 ghost. Indentation/lineage need the real one.
    const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 || r.height > 0; };
    // First *visible* "[12345]" PID-bracket header inside an element (marks a node).
    const bracketEl = (el) => {
      for (const e of el.querySelectorAll("div, span")) {
        if (/^\[\d+\]$/.test(directText(e)) && visible(e)) return e;
      }
      return null;
    };
    // Inline command line carried in the node header: "[PID] name <args...>".
    // The header line is the nearest ancestor of the bracket whose text begins
    // with the [PID] followed by the name; everything past the name is the args.
    const inlineCmd = (br, pid) => {
      let n = br;
      for (let i = 0; i < 5 && n; i++) {
        const t = (n.innerText || "").replace(/\s+/g, " ").trim();
        if (new RegExp("^\\[" + pid + "\\]\\s+\\S").test(t)) {
          const m = t.match(/^\[\d+\]\s+(\S+)\s*(.*)$/);
          if (m) return m[2] ? (m[1] + " " + m[2]).trim() : "";
        }
        n = n.parentElement;
      }
      return "";
    };
    // The filename-looking caption sitting next to a [PID] header is the name.
    const nameNear = (br) => {
      const brTxt = directText(br);
      let scan = br.parentElement;
      for (let lvl = 0; lvl < 3 && scan; lvl++) {
        for (const e of scan.querySelectorAll("div, span")) {
          const t = directText(e);
          if (t && t !== brTxt && t.length < 60 && /\.[A-Za-z0-9]{1,5}$/.test(t) && !/\s/.test(t)) return t;
        }
        scan = scan.parentElement;
      }
      return "";
    };

    // Anchor on every "Process id" caption, then climb to the nearest ancestor
    // that also holds a [PID] header — that ancestor is the process-node box.
    // Non-tree "Process id" labels (right-rail panels) have no bracket ancestor
    // and are naturally filtered out.
    const containers = [];
    for (const lab of document.querySelectorAll("div, span")) {
      if (directText(lab) !== "Process id") continue;
      let node = lab.parentElement;
      for (let i = 0; i < 12 && node; i++) {
        if (bracketEl(node)) { if (!containers.includes(node)) containers.push(node); break; }
        node = node.parentElement;
      }
    }
    // Each "Process id" caption climbs to its own nearest [PID] box, so
    // `containers` already holds exactly one tight box per process node (for
    // nested trees both the parent and child boxes are present, which the
    // containment-based lineage pass below relies on).
    const nodeBoxes = containers;

    const WANT = {
      "command line": "cmd",
      "process id": "pid",
      "image file path": "folder",
      "image file sha256": "sha256",
      "image file sha1": "sha1",
      "user": "account",
      "account name": "account"
    };

    const recs = [];
    for (const box of nodeBoxes) {
      const rec = { name: "", pid: "", cmd: "", folder: "", sha256: "", account: "", source: "tree" };
      const br = bracketEl(box);
      if (br) {
        rec.pid = directText(br).replace(/[\[\]]/g, "");
        rec.name = nameNear(br);
        const r = br.getBoundingClientRect();
        rec._left = r.left; rec._top = r.top;
        rec._inline = inlineCmd(br, rec.pid);
      }
      // Key/value detail rows: caption element + its sibling value cell.
      for (const lab of box.querySelectorAll("div, span")) {
        const key = directText(lab).toLowerCase();
        const field = WANT[key];
        if (!field) continue;
        const wrap = lab.parentElement;
        if (!wrap) continue;
        let val = "";
        for (const c of wrap.children) {
          if (c === lab || c.contains(lab)) continue;
          const v = cellValue(c);
          if (v) { val = v; break; }
        }
        if (!val) continue;
        if (field === "cmd") { if (!rec.cmd) rec.cmd = val; }
        else if (field === "pid") { if (!rec.pid) rec.pid = val.replace(/[^\d]/g, ""); }
        else if (field === "folder") {
          rec.folder = val.replace(/[\\/][^\\/]*$/, "");
          if (!rec.name) { const base = val.split(/[\\/]/).pop(); if (base) rec.name = base; }
        }
        else if (field === "sha256") { rec.sha256 = val; }
        else if (field === "sha1") { if (!rec.sha256) rec.sha256 = val; }
        else if (field === "account") { if (!rec.account) rec.account = val.trim(); }
      }
      // Expanded panel had no Command line field → fall back to the header args.
      if (!rec.cmd && rec._inline) rec.cmd = rec._inline;
      if (rec.name || rec.pid) recs.push(rec);
    }

    // Collapsed nodes: a [PID] header is present whether or not its detail panel
    // is expanded, but the key/value fields (command line, image path, hash) only
    // exist once expanded. Capture any header whose PID we didn't already get so
    // the analyst sees the full process list even before clicking "Expand all" —
    // command lines fill in for the nodes they expand.
    const havePid = new Set(recs.map(r => r.pid).filter(Boolean));
    for (const e of document.querySelectorAll("div, span")) {
      const m = directText(e).match(/^\[(\d+)\]$/);
      if (!m || !visible(e)) continue;
      const pid = m[1];
      if (havePid.has(pid)) continue;
      havePid.add(pid);
      const r = e.getBoundingClientRect();
      recs.push({
        name: nameNear(e), pid, cmd: inlineCmd(e, pid),
        folder: "", sha256: "", account: "", source: "tree",
        _left: r.left, _top: r.top
      });
    }

    // Lineage by indentation. The tree's nesting is conveyed *visually*: nodes are
    // flat siblings in the DOM, each indented further right than its parent (≈30px
    // per level). Sort top-to-bottom, then walk a stack where the parent of a node
    // is the nearest preceding node with a strictly smaller left edge. Equal-left
    // nodes are siblings. (AH/Evidence grid records still merge by name#pid later,
    // backfilling lineage for any node without on-screen geometry.)
    const geo = recs.filter(r => typeof r._left === "number").sort((a, b) => a._top - b._top);
    const stack = [];
    for (const r of geo) {
      while (stack.length && stack[stack.length - 1]._left >= r._left - 4) stack.pop();
      if (stack.length) { const p = stack[stack.length - 1]; r.pname = p.name; r.ppid = p.pid; }
      stack.push(r);
    }

    for (const r of recs) {
      delete r._left; delete r._top; delete r._inline;
      const key = [r.name, r.pid, r.cmd, r.pname, r.ppid].join("|");
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(r);
    }
    return out;
  }

  const text = document.body ? document.body.innerText : "";
  let typed = {};
  let procs = [];
  const diag = { splunk: false, defender: false };
  if (isSplunkPage()) {
    diag.splunk = true;
    const sink = makeSink();
    try { readStatistics(sink, diag); } catch (e) { diag.statErr = String(e); }
    try { readEvents(sink, diag); }     catch (e) { diag.eventErr = String(e); }
    try { readSidebar(sink, diag); }    catch (e) { diag.sideErr = String(e); }
    typed = sink.snapshot();
    diag.typedSize = sink.size();
    diag.typedCats = Object.keys(typed);
  } else if (isDefenderPage()) {
    diag.defender = true;
    const sink = makeSink();
    try { readDefenderAH(sink, diag); } catch (e) { diag.defErr = String(e); }
    // Merge process records from every source: each Fluent grid on the page
    // (AH results, Incident Evidence) plus the alert-story process-tree widget.
    // De-dup across all of them by the same identity key.
    const seenProc = new Set();
    const mergeProcs = (list) => {
      for (const r of (list || [])) {
        const k = [r.name, r.pid, r.cmd, r.pname, r.ppid].join("|");
        if (seenProc.has(k)) continue;
        seenProc.add(k); procs.push(r);
      }
    };
    try {
      for (const grid of document.querySelectorAll('[role="grid"]')) {
        mergeProcs(collectDefenderProcs(grid));
      }
    } catch (e) { diag.procErr = String(e); }
    try { const tree = collectProcessTree(); diag.treeCount = tree.length; mergeProcs(tree); }
    catch (e) { diag.treeErr = String(e); }
    diag.procCount = procs.length;
    typed = sink.snapshot();
    diag.typedSize = sink.size();
    diag.typedCats = Object.keys(typed);
  }
  console.log("[IOC] diag:", diag, "typed:", typed, "procs:", procs);
  return { text, typed, procs, diag };
}
