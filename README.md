# SOC Mate

**SOC Mate** is a browser extension for security analysts that works on **Chrome, Edge, and any Chromium-based browser**. It extracts indicators of compromise (IOCs) directly from Splunk and Microsoft Defender pages, builds ready-to-paste hunt queries, runs live enrichment, and ships a set of utilities that cover the most common analyst workflows — all without leaving the browser.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Extract Tab](#extract-tab)
   - [Extracting IOCs](#extracting-iocs)
   - [Output Toggles](#output-toggles)
   - [Per-Category Cards](#per-category-cards)
   - [Query Builders](#query-builders)
   - [Pivot & Enrich Panel](#pivot--enrich-panel)
   - [Encoded Commands](#encoded-commands)
   - [Process Tree (Defender)](#process-tree-defender)
   - [All IOCs Pane](#all-iocs-pane)
4. [Utilities Tab](#utilities-tab)
   - [Decode / Beautify / Strip](#decode--beautify--strip)
   - [User-Agent Parser](#user-agent-parser)
   - [Bytes Size Converter](#bytes-size-converter)
   - [Subnet Calculator](#subnet-calculator)
   - [Redactor](#redactor)
   - [Subnet Membership Check](#subnet-membership-check)
   - [Email Header Analyser](#email-header-analyser)
   - [Export IOCs](#export-iocs)
   - [YARA Rule Builder](#yara-rule-builder)
   - [Sigma Converter](#sigma-converter)
5. [History Tab](#history-tab)
6. [Settings](#settings)
7. [Keyboard Shortcuts](#keyboard-shortcuts)
8. [Privacy & Data Handling](#privacy--data-handling)

---

## Installation

SOC Mate is a local unpacked extension (not published to a browser store). It works on **Chrome, Edge, Brave, Opera, Vivaldi**, and any other Chromium-based browser.

**Chrome / Brave / Vivaldi / Opera**
1. Clone or download this repository.
2. Navigate to `chrome://extensions`.

   ![Chrome extensions page](screenshots/install-01-chrome-extensions-page.png)

3. Enable **Developer mode** (top-right toggle).

   ![Enable Developer mode](screenshots/install-02-developer-mode.png)

4. Click **Load unpacked** and select the folder containing `manifest.json`.

   ![Load unpacked button](screenshots/install-03-load-unpacked.png)

5. The SOC Mate icon appears in your toolbar — pin it for quick access.

   ![Extension pinned in toolbar](screenshots/install-04-pinned.png)

**Microsoft Edge**
1. Clone or download this repository.
2. Navigate to `edge://extensions`.
3. Enable **Developer mode** (left sidebar toggle).
4. Click **Load unpacked** and select the folder containing `manifest.json`.
5. Pin SOC Mate from the Extensions menu in the toolbar.

> **Tip:** Click **⤢ Open in tab** to promote the popup to a persistent browser tab that survives while you work in other tabs.

---

## Quick Start

1. Open a Splunk search results page or a Defender Advanced Hunting / alert page.
2. Click the SOC Mate icon (or press **Ctrl+E**).
3. IOCs are extracted automatically and grouped by category.
4. Click **OR**, **AND**, **IN**, or **Defender** on any category to copy a ready-to-use hunt query.
5. Click **Pivot / Enrich** to open per-indicator links to VT, AbuseIPDB, Shodan, MXToolbox, and more.

---

## Extract Tab

### Extracting IOCs

| Method | How |
|---|---|
| **Extract from page** | Click the button or press **Ctrl+E** while on a Splunk or Defender tab. SOC Mate runs inside the page and reads typed field values from table cells. |
| **Extract from text** | Paste any text (Ctrl+C from a page, OCR output, email body, etc.) into the paste box and click **Extract from text** or press **Ctrl+Shift+E**. |
| **Auto** toggle | When enabled, SOC Mate runs extraction automatically every time you open the popup on a recognised SOC page. Skips non-SOC pages silently so your collected work is never wiped. |
| **Append** toggle | Merges new results into the current set instead of replacing them. Useful for combining Splunk and Defender data for the same incident. |

**Site awareness:** SOC Mate recognises Splunk stat/event tables and Defender Advanced Hunting and Evidence columns. Field names (`src_ip`, `RemoteIP`, `SHA256`, `Subject`, etc.) map to the correct IOC category automatically. Custom SIEM URLs can be added in Settings → Auto-extraction sites.

**IOC categories extracted:**

| Category | What's captured |
|---|---|
| SRC IP / DEST IP | IPs labelled with src/source/client or dst/dest/destination in field names |
| IP | All other IPv4 and IPv6 addresses |
| Domains | Hostnames with valid TLDs (false-positives filtered by TLD allowlist) |
| URLs | Full `http://` and `https://` URLs |
| Emails | Email addresses |
| Email Subjects | `Subject:` lines from email headers or Defender `EmailEvents` |
| Hostnames | Computer/device names from labelled fields |
| Files | Filenames with known extensions (also extracted from full paths) |
| File Paths | Full Windows and Unix paths |
| MD5 / SHA1 / SHA256 | Hex hashes by length |
| CVEs | `CVE-YYYY-NNNNN` identifiers |
| User Agents | Browser and tool UAs (`Mozilla/…`, `curl/…`, etc.) |
| Encoded CMD | Base64 blobs from PowerShell `-enc`, Linux `base64 -d`, or standalone padded blobs — decoded inline |

---

### Output Toggles

All toggles affect **both** the per-category textareas and the All IOCs pane in real time.

| Toggle | Effect |
|---|---|
| **Sanitize** | Strips leading/trailing quotes, brackets, trailing punctuation from each value |
| **Defang** | Converts `https` → `hxxps`, `.` → `[.]`, `://` → `[://]`, `@` → `[@]` for safe sharing |
| **Redact** | Replaces words/patterns from your saved Redaction list with `<redacted>` |
| **Separator** | Newline (default), comma, or space — controls how values join in Copy and the All IOCs pane |
| **Numbered** | Prepends `1.`, `2.`, … to each value |
| **"Double"** | Wraps each value in double quotes |
| **'Single'** | Wraps each value in single quotes (mutually exclusive with Double) |
| **\*Prefix** | Prepends `*` for left-wildcard Splunk searches |
| **Suffix\*** | Appends `*` for right-wildcard Splunk searches |

---

### Per-Category Cards

Each IOC category appears as a collapsible card. Inside:

- **Field input** — pre-filled with the Splunk field name for that category (e.g. `src_ip`). Edit it to change the field used in queries. Autocomplete suggests common field names.
- **OR / AND / IN** — copy Splunk search clause (see [Query Builders](#query-builders))
- **Defender** — copy Microsoft Defender Advanced Hunting KQL snippet
- **Pivot / Enrich** — open per-value pivot links and run live enrichment (see [Pivot & Enrich Panel](#pivot--enrich-panel))
- **Inline textarea** — edit the values in this category directly; changes write back to the IOC state automatically

---

### Query Builders

#### Splunk — OR / AND / IN

Clicking **OR**, **AND**, or **IN** on a category copies a Splunk search clause to the clipboard.

```
# OR example (src_ip with two values)
(src_ip="1.2.3.4" OR src_ip="5.6.7.8")

# IN example
src_ip IN ("1.2.3.4", "5.6.7.8")
```

- If you have **Security Controls** configured in Settings, SOC Mate generates one sub-query per matching control and joins them with `OR` — covering your proxy, firewall, Sysmon, etc. in one copy.
- `index=` and `sourcetype=` are prepended when configured in Settings → IOC field names.
- The **Wildcard prefix/suffix** toggles apply to query values as well.

#### Defender — KQL

Clicking **Defender** copies a Defender Advanced Hunting KQL snippet.

```kql
# Example — domains
DeviceNetworkEvents
| where RemoteUrl has_any ("evil.com", "badactor.net")

# Example — file hashes
DeviceFileEvents
| where SHA256 in~ ("abc123...", "def456...")
```

Tables and operators are pre-configured per category (Settings → Defender KQL) and can be overridden per-session using the field input on each card.

---

### Pivot & Enrich Panel

Click **Pivot / Enrich** on any category card to expand a per-value panel.

#### Pivot links (open in a new tab — no data sent without clicking)

| Button | Destination |
|---|---|
| **VT** | VirusTotal — IP address, domain, URL, or file hash lookup |
| **AbuseIPDB** | AbuseIPDB confidence check (IPs) |
| **Shodan** | Shodan host page (IPs) |
| **URLScan** | urlscan.io search (domains, URLs) |
| **MXToolbox** | MXToolbox blacklist check (IPs, domains, email domains) |
| **Google** | Quoted Google search for any indicator |

#### Live Enrichment (sends the indicator to a third-party API)

> **Note:** A one-time confirmation is shown before the first lookup per session.

| Button | Provider | IOC types | Requires key |
|---|---|---|---|
| 🔎 **VT** | VirusTotal | IPs, domains, URLs, hashes | Yes (free tier: 4 req/min) |
| 🔎 **Abuse** | AbuseIPDB | IPs | Yes (free tier: 1000/day) |
| 🔎 **Geo** | Multi-source (ipwho.is + ipinfo) | IPs | Optional (ipinfo token) |
| 🔎 **WHOIS** | RDAP (no key needed) | IPs, domains | No |

**Bulk enrichment:** Click **🔎 All VT** (or Abuse) at the top of the panel to run the provider against every indicator in that category. Progress is shown in real time. The loop auto-throttles on rate-limit responses.

**Copy enriched results:** After enrichment a **Copy enriched (N)** button appears with a format selector — choose grouped (FLAGGED / CLEAN), by-IOC, JSON, or Markdown table.

Enrichment field details (score, ASN, registrar, TOR flag, etc.) can be toggled in **Settings → Copy output fields**.

---

### Encoded Commands

When a base64 blob is found, SOC Mate shows both the raw blob and the decoded command:

```
source: powershell -enc
blob:   SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==
↓ decoded
Invoke-Expression
```

- **Copy blobs** — copies the raw base64 strings only
- **Copy decoded** — copies only the decoded commands (useful for pasting into a triage note)

---

### Process Tree (Defender)

When Defender Advanced Hunting or Evidence pages contain process records, a **Processes & command lines** section appears automatically.

- **Tree view** — indented parent → child hierarchy. Each child shows `↳ parent: ProcessName (PID)` with its command line.
- **Flat view** — one card per spawned process.
- **Wrap lines** — toggles word-wrap for long command lines.
- **Copy view** — plain-text process tree to clipboard.
- **Copy command lines** — deduped command lines only.
- **Copy tree+cmds** — tree hierarchy with each command line inlined directly beneath its process.

---

### All IOCs Pane

The **All IOCs · editable** section at the bottom of the Extract tab shows a flat, deduplicated list of all extracted indicators.

- All output toggles (Sanitize, Defang, Redact, Separator, Numbered, Quotes, Wildcards) apply to this pane.
- **Edit freely** — type or paste anything into the pane. Your changes are preserved while you work. Toggles continue to apply to whatever you've typed.
- **Refresh from cards** — discards your edits and rebuilds from the current IOC state.
- **⬇ CSV** — quick CSV download of all IOCs.
- **Copy all** — copies the entire pane content.
- Enable **Category headers** in Settings → Default output to split the pane into labelled sections (`=== SRC IP (3) ===` etc.).

---

## Utilities Tab

### Decode / Beautify / Strip

**Input → operation → Output** panel. Paste text, click an operation, copy or extract IOCs from the result.

| Operation | What it does |
|---|---|
| **Base64 decode** | Decodes Base64; handles URL-safe alphabet, missing padding, UTF-16LE (PowerShell) |
| **URL decode** | `decodeURIComponent()` |
| **Smart decode** | Auto-detects and chains URL-decode and Base64-decode for up to 6 layers |
| **JSON beautify / minify** | Pretty-print or compact JSON |
| **XML beautify / minify** | Indent or strip whitespace from XML |
| **HTML → text** | Strips all tags, returns readable text |
| **HTTP body** | Returns everything after the first blank line of an HTTP request/response |
| **HTTP headers** | Returns the header block only |
| **Redact Cookie/Auth** | Blanks out `Cookie:`, `Authorization:`, `X-Api-Key:`, and similar header values |

After decoding, click **Extract IOCs from output** to send the result straight to the Extract tab.

---

### User-Agent Parser

Paste one or more User-Agent strings (one per line). Each is parsed into:
- **Browser** + version (Edge, Chrome, Firefox, Safari, IE, Opera, Brave, or the tool name for `curl/`, `python-requests/`, etc.)
- **OS** (Windows 10/11, macOS, Android, iOS, Linux, ChromeOS)
- **Device type** (Desktop, Mobile, Tablet, Bot/Tool)
- **Rendering engine** (Gecko, WebKit, Trident)

**Copy** outputs a plain-text block for each UA, suitable for triage notes.

---

### Bytes Size Converter

Converts any file/log size between B, KB, MB, GB, TB, PB (1024-based). Accepts:
- Bare number: `524288` → bytes
- Number + unit: `5 MB`, `2.5GB`, `1_073_741_824`

Output shows all units plus a human-readable comparison (smartphone photos, MP3 songs, 1080p video minutes, etc.).

---

### Subnet Calculator

Accepts CIDR (`10.0.0.0/24`) or IP + mask (`10.0.0.5 255.255.255.0`). Returns:

```
Network:      10.0.0.0/24
Netmask:      255.255.255.0
Wildcard:     0.0.0.255
Broadcast:    10.0.0.255
First host:   10.0.0.1
Last host:    10.0.0.254
Total addrs:  256
Usable hosts: 254
Class:        C
Scope:        private (192.168.0.0/16)
```

---

### Redactor

Apply your saved redaction patterns to arbitrary pasted text — independent of an active extraction. Useful for sanitising log excerpts or raw events before sharing. Patterns are pulled from **Settings → Redaction list** (plain text or regex).

---

### Subnet Membership Check

Test a list of IPs against a network. The network accepts:
- CIDR: `172.16.1.0/24`
- IP + mask: `172.16.1.0 255.255.255.0`
- Range: `172.16.1.0 - 172.16.1.255`

Output marks each IP as **✓ IN** or **✗ OUT**, with a summary count.

---

### Email Header Analyser

Paste raw email headers (or full `.eml` source). SOC Mate parses:

**Summary** — From, Reply-To, Return-Path, Subject, Date, Message-ID, X-Mailer, originating IP, spam score.

**Authentication** — SPF, DKIM, DMARC, and ARC results with colour-coded badges (pass / fail / softfail / neutral).

**Received chain** — Each `Received:` hop displayed in chronological order (origin → destination), showing the sending host, IP, receiving host, protocol, timestamp, and inter-hop delay in seconds.

**IPs** — All IPs extracted from the hop chain and originating-IP header, each with pivot links:
- VT · AbuseIPDB · MXToolbox (blacklist) · Shodan · Google

**Domains** — Domains extracted from From, Reply-To, Return-Path, and Message-ID, with:
- VT · URLScan · MXToolbox BL · MXToolbox MX · MXToolbox SPF

**Flags** — Automatic suspicious indicators:
- ⛔ DANGER: SPF/DKIM/DMARC fail or permerror
- ⚠ WARN: Reply-To ≠ From domain, Return-Path ≠ From domain, SPF softfail, date in the future, high spam score
- ℹ INFO: No Authentication-Results header, date over 30 days old

**Buttons:**
- **→ Add to IOCs** — injects all extracted IPs and domains into the main Extract tab IOC state
- **Copy summary** — plain-text report for case notes
- **Clear** — resets the analyser

---

### Export IOCs

Download or copy all extracted IOCs in structured formats.

| Format | Description |
|---|---|
| **Flat CSV** | One row per indicator: `type,value` |
| **Grouped CSV** | One row per category: `type,v1,v2,v3,…` |
| **JSON** | Full `{ category: [values] }` object, pretty-printed |

**Buttons:** ⬇ Download CSV · ⬇ Download JSON · Copy CSV

A live preview of the first 10 rows appears when the panel is open.

> The **⬇ CSV** button in the All IOCs pane is a quick shortcut that always downloads flat CSV without opening this panel.

---

### YARA Rule Builder

Generate a YARA detection rule from the currently extracted IOCs.

**Options:**
| Option | Description |
|---|---|
| Rule name | Identifier for the generated rule (special characters auto-sanitised) |
| `nocase` | Case-insensitive matching for all strings |
| `wide` (UTF-16) | Add `wide` modifier for UTF-16LE encoded strings (not applied to IP/network strings) |
| Condition | `any of them` / `all of them` / `≥ 50% of them` |

**IOC type checkboxes** — Choose which categories to include. Types with no extracted values are greyed out.

**String types** → `strings:` block entries: files, paths, domains, URLs, IPs, hostnames, email subjects.

**Hash types** → `condition:` entries via the YARA `hash` module:
```yara
import "hash"

rule SOCMate_IOC_Hunt
{
    meta:
        description = "IOC hunt — generated by SOC Mate"
        date        = "2026-07-07"

    strings:
        $s1 = "evil.com" ascii nocase
        $s2 = "C:\\Windows\\Temp\\payload.exe" ascii nocase

    condition:
        (any of them) or
        (hash.sha256(0, filesize) == "abc123..." or
         hash.md5(0, filesize) == "def456...")
}
```

---

### Sigma Converter

Paste a Sigma rule (YAML) and convert it to a ready-to-run SIEM query.

**Supported targets:**
- **Splunk SPL** — uses `SIGMA_SPL_HINT` table for category → index/sourcetype hints
- **Microsoft Sentinel KQL** — field names mapped to MDE schema (`DeviceProcessEvents`, `DeviceNetworkEvents`, `EmailEvents`, etc.)
- **Elastic KQL (ECS)** — field names mapped to ECS equivalents

**Supported Sigma features:**
| Feature | Example |
|---|---|
| String modifiers | `contains`, `startswith`, `endswith`, `re` (regex), `cidr` |
| Boolean conditions | `1 of selection*`, `all of them`, `selection1 and not selection2` |
| Multi-doc rules | Multiple rules in one YAML file separated by `---` |
| Nested selections | `selection_main` AND `selection_filter` style patterns |

**Buttons:** Convert · Copy output · Load example · Clear

**Example input:**
```yaml
title: Suspicious Encoded PowerShell Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
    condition: selection
level: high
```

**Splunk output:**
```
index=win EventCode=4688 (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *")
```

---

## History Tab

SOC Mate keeps a rolling log of every unique IOC it extracts.

- **Filter** — real-time search across all indicators and types
- **Copy all** — every IOC in history, newline-separated
- **JSON** — full history export as JSON (includes type, timestamp, source URL)
- **Clear** — removes all history (confirmation required)

**Grouping modes** (Settings → History):
- **By order** — newest first, flat list
- **By type** — grouped by category with a **Copy all** button per type

Each entry shows the indicator value, its category, the timestamp, and the source hostname.

---

## Settings

All settings are stored locally in Chrome storage. Click any section header to expand.

### API Keys & Sources
Store your VirusTotal, AbuseIPDB, and ipinfo.io API keys. Keys are saved in `chrome.storage.local` and never transmitted except to the respective API.

**Passphrase encryption (AES-GCM):** Toggle **Encrypt keys with passphrase** to wrap all keys in AES-256-GCM encrypted storage, derived via PBKDF2 (250,000 iterations, SHA-256). Keys are decrypted into `chrome.storage.session` (memory only) and re-locked when Chrome closes. A **Lock now** button forces immediate re-lock.

### Copy Output Fields
Choose exactly which enrichment fields appear when you click **Copy** on an enrichment result. Separate toggles for: VT score, verdict, percentage, threat label, reputation, dates, country, ASN, AS owner, registrar, categories, filename, file type, tags, signed flag; AbuseIPDB score, reports, country, ISP, domain, usage type, TOR flag, last reported, hostnames; RDAP network, country, org, abuse contact, registration date, age, registrar, expiry, nameservers.

### Enrichment Behavior
Per-provider concurrency (parallel requests) and minimum delay between requests. **Free-tier defaults** are conservative (VT: 1 parallel, 16s delay; AbuseIPDB: 1 parallel, 1s delay). **Paid-tier defaults** fan out to 10 parallel with no delay. The loop auto-throttles to 1-at-a-time on any `429` response.

Also sets the default format for **Copy enriched** output (grouped / by IOC / JSON / Markdown).

### Detection Thresholds
Two-tier thresholds per provider. Yellow warning below the malicious threshold, red flag at or above.

- **VT suspicious if ≥ N vendors** (default: 1)
- **VT malicious if ≥ N vendors** (default: 5)
- **AbuseIPDB suspicious if ≥ N%** (default: 25%)
- **AbuseIPDB malicious if ≥ N%** (default: 75%)

### Auto-Extraction Sites
Extra domains or URL prefixes where the **Auto** toggle fires (in addition to built-in Splunk and Defender detection). One entry per line. Supports exact domain (`qradar.corp.local`), wildcard subdomain (`*.kibana.company.com`), and URL prefix (`https://siem.corp.local/alerts`).

### Extraction Sources
Blocklist of domains SOC Mate will never extract from. By default includes `virustotal.com`, `abuseipdb.com`, `urlscan.io`, `shodan.io` — sites whose pages are full of IOCs from other cases. Matches the exact hostname and all subdomains.

### Redaction List
Words, phrases, or regex patterns to replace when the **Redact** toggle is on. Case-insensitive. Useful for stripping customer names, internal hostnames, or analyst usernames before sharing copied IOCs. Custom replacement text (default: `<redacted>`).

### Default Output
Starting state of all Extract tab toggles each time the popup opens. Changes here don't affect on-the-fly toggle changes — those are just live overrides.

### Splunk Security Controls
Define each log source (proxy, firewall, Sysmon, EDR, etc.) with its `index`, `sourcetype`, and the Splunk field name for each IOC type. When you click **OR / AND / IN** on a category card, one sub-query is generated per matching control and joined with `OR`.

### IOC Field Names & Log Locations
Simple fallback field names, index, and sourcetype per IOC type. Used when no security control covers that type.

### Defender KQL — Tables & Columns
Default Advanced Hunting table and column for each IOC category. Operators: `in~` (case-insensitive exact — best for IPs/hashes), `in` (case-sensitive), `has_any` (token match — best for domains/URLs/paths).

### Categories
Hide individual IOC categories. Hidden categories are skipped in extraction results, the All IOCs pane, queries, and exports. Useful for cleaner output when certain indicator types aren't relevant to your environment.

### History
- Enable/disable history logging
- Log source page URL with each indicator
- Group by order (newest first) or by type
- Maximum entries to retain (1–50, default 20)

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+E` | Extract from the active page (works even when the popup is closed) |
| `Ctrl+Shift+E` | Extract from pasted text |
| `Ctrl+1` | Switch to Extract tab |
| `Ctrl+2` | Switch to Utilities tab |
| `Ctrl+3` | Switch to History tab |
| `Ctrl+4` | Switch to Settings tab |
| `Ctrl+K` | Open feature search (find any button or setting instantly) |
| `Ctrl+F` | Open Find panel in the active textarea |
| `Ctrl+H` | Open Find & Replace panel in the active textarea |
| `Ctrl+Shift+T` | Toggle Tree / Flat view in the Processes pane |
| `Ctrl+Shift+C` | Copy process view |
| `Ctrl+Shift+L` | Copy command lines |
| `Ctrl+Shift+M` | Copy tree with command lines |
| `?` button | Open the quick-start tour |

---

## Privacy & Data Handling

- All settings and extracted IOCs are stored in **Chrome's local storage on your machine only**. Nothing is synced.
- **Live enrichment** sends the indicator value to VirusTotal, AbuseIPDB, or ipinfo.io. A confirmation prompt is shown the first time per session.
- **Pivot links** (VT, Shodan, MXToolbox, etc.) open in a new tab. No data is sent until you click the link.
- API keys are stored locally. When passphrase encryption is enabled they are stored as an AES-GCM ciphertext blob; the plaintext keys exist only in session memory while Chrome is open.
- SOC Mate never sends any data to any backend or telemetry service.
