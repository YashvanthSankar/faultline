/* Faultline report renderer.
 * Security model: every value in the report is untrusted (it comes from packets).
 * Data is read from the embedded JSON data block and turned into DOM nodes with
 * createElement / textContent only. No HTML string is ever parsed. */
(function () {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";
  var doc = document;
  var root = doc.getElementById("app");
  var R = null;
  try { R = JSON.parse(doc.getElementById("faultline-data").textContent); } catch (e) { R = null; }
  if (!root) { return; }
  if (!R || typeof R !== "object" || Array.isArray(R)) {
    root.textContent = "This report could not be read. The embedded data is damaged.";
    return;
  }
  var EMBEDDED = doc.documentElement.getAttribute("data-embedded") === "1";
  var REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ------------------------------------------------------------------ utils
  function str(v) { return v === null || v === undefined ? "" : String(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return v && typeof v === "object" && !Array.isArray(v) ? v : {}; }
  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }

  var SAFE_ATTR = /^(class|id|role|tabindex|title|type|for|colspan|scope|hidden|disabled|lang|dir|href|target|rel|download|aria-[a-z-]+|data-[a-z-]+|viewBox|width|height|x|y|x1|x2|y1|y2|cx|cy|r|rx|d|points|transform|text-anchor|dominant-baseline|offset|gradientTransform|pathLength|preserveAspectRatio|focusable|fill|stroke|stroke-width|stroke-linecap|stroke-linejoin)$/;

  function setAttrs(el, attrs) {
    if (!attrs) { return; }
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) { return; }
      if (k === "text") { el.textContent = str(v); return; }
      if (k.slice(0, 2) === "on" && typeof v === "function") { el.addEventListener(k.slice(2), v); return; }
      if (!SAFE_ATTR.test(k)) { return; }
      if (k === "href") {
        v = str(v);
        if (!(v.charAt(0) === "#" || v === "/" || v.slice(0, 5) === "blob:")) { return; }
      }
      el.setAttribute(k, v === true ? "" : str(v));
    });
  }
  function append(el, kids) {
    for (var i = 0; i < kids.length; i++) {
      var k = kids[i];
      if (k === null || k === undefined || k === false) { continue; }
      if (Array.isArray(k)) { append(el, k); continue; }
      el.appendChild(typeof k === "object" && k.nodeType ? k : doc.createTextNode(str(k)));
    }
    return el;
  }
  function h(tag, attrs) {
    var el = doc.createElement(tag);
    setAttrs(el, attrs);
    return append(el, Array.prototype.slice.call(arguments, 2));
  }
  function s(tag, attrs) {
    var el = doc.createElementNS(SVGNS, tag);
    setAttrs(el, attrs);
    return append(el, Array.prototype.slice.call(arguments, 2));
  }
  function fmtInt(v) { v = num(v); return v === null ? "?" : Math.round(v).toLocaleString("en-US"); }
  function fmtBytes(v) {
    v = num(v); if (v === null) { return "?"; }
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (i === 0 ? String(Math.round(v)) : v.toFixed(v < 10 ? 1 : 0)) + " " + u[i];
  }
  function fmtDur(sec) {
    sec = num(sec); if (sec === null) { return "?"; }
    if (sec < 1) { return Math.round(sec * 1000) + " ms"; }
    if (sec < 60) { return sec.toFixed(sec < 10 ? 1 : 0) + " s"; }
    var m = Math.floor(sec / 60), sx = Math.round(sec % 60);
    if (m < 60) { return m + " min" + (sx ? " " + sx + " s" : ""); }
    var hr = Math.floor(m / 60); m = m % 60;
    return hr + " h" + (m ? " " + m + " min" : "");
  }
  function pad(n, w) { n = String(n); while (n.length < w) { n = "0" + n; } return n; }
  function fmtClock(sec, ms) {
    sec = Math.max(0, num(sec) || 0);
    var hr = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), sx = Math.floor(sec % 60);
    var out = (hr ? hr + ":" + pad(m, 2) : String(m)) + ":" + pad(sx, 2);
    if (ms) { out += "." + pad(Math.floor((sec % 1) * 1000), 3); }
    return out;
  }
  function fmtDate(ts) {
    ts = num(ts); if (ts === null) { return "?"; }
    try { return new Date(ts * 1000).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "medium" }); }
    catch (e) { return new Date(ts * 1000).toISOString(); }
  }
  function plural(n, one, many) { return n === 1 ? one : many; }
  function safeFileStem(v) {
    var x = str(v).replace(/\.(pcapng|pcap|cap)(\.gz)?$/i, "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[.-]+/, "").slice(0, 60);
    return x || "capture";
  }

  // ----------------------------------------------------------- vocabulary
  var CAT = {
    attack: { one: "Attack", many: "attacks", chip: "Attacks", hyp: "Points to an attack" },
    fault: { one: "Fault", many: "faults", chip: "Faults", hyp: "Points to a fault" },
    misconfig: { one: "Misconfiguration", many: "misconfigs", chip: "Misconfigs", hyp: "Points to a misconfiguration" },
    info: { one: "Note", many: "notes", chip: "Notes", hyp: "Neutral" }
  };
  function cat(c) { return CAT.hasOwnProperty(c) ? c : "info"; }
  var STATUS = {
    under_attack: { word: "Under attack", share: "UNDER ATTACK" },
    faulty: { word: "Faulty", share: "FAULTY" },
    minor_issues: { word: "Minor issues", share: "MINOR ISSUES" },
    healthy: { word: "Healthy", share: "HEALTHY" }
  };
  var SEV = ["Info", "Low", "Medium", "High", "Critical"];
  function sevIdx(v) { v = num(v); return v === null ? 0 : clamp(Math.round(v), 0, 4); }

  // ------------------------------------------------------------ the data
  var tool = obj(R.tool), capture = obj(R.capture), verdict = obj(R.verdict), stats = obj(R.stats);
  var findings = arr(R.findings).filter(function (f) { return f && typeof f === "object"; });
  var incidents = arr(R.incidents).filter(function (i) { return i && typeof i === "object"; });
  var hosts = arr(R.hosts).filter(function (x) { return x && typeof x === "object"; });
  var evidence = obj(R.evidence);
  var redacted = R.redacted === true;
  var status = STATUS.hasOwnProperty(verdict.status) ? verdict.status : "healthy";
  var byId = {};
  findings.forEach(function (f) { if (typeof f.id === "string") { byId[f.id] = f; } });
  var t0 = num(capture.first_ts);
  var tl = obj(stats.timeline);
  if (t0 === null) { t0 = num(tl.start); }
  if (t0 === null) { t0 = 0; }
  function rel(ts) { ts = num(ts); return ts === null ? null : ts - t0; }

  doc.documentElement.setAttribute("data-status", status);

  // --------------------------------------------------------- rich text
  // Backticks become <code>; finding ids (F1, F2 ...) become jump links.
  function rich(text) {
    var out = [];
    str(text).split("`").forEach(function (part, i) {
      if (i % 2 === 1) { out.push(h("code", null, part)); return; }
      var re = /\bF\d{1,4}\b/g, last = 0, m;
      while ((m = re.exec(part)) !== null) {
        if (!byId[m[0]]) { continue; }
        if (m.index > last) { out.push(part.slice(last, m.index)); }
        out.push(jump(m[0], m[0]));
        last = m.index + m[0].length;
      }
      if (last < part.length) { out.push(part.slice(last)); }
    });
    return out;
  }
  function jump(id, label) {
    return h("button", { type: "button", "class": "linkish", onclick: function () { goto(id); } }, label);
  }

  // ------------------------------------------------------------- icons
  function chevron() {
    return s("svg", { width: 12, height: 12, viewBox: "0 0 12 12", "aria-hidden": "true", focusable: "false" },
      s("path", { d: "M2 4.5 6 8.5 10 4.5", fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  }
  function icon(d) {
    return s("svg", { width: 14, height: 14, viewBox: "0 0 16 16", "aria-hidden": "true", focusable: "false" },
      s("path", { d: d, fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  }
  var I_DOWN = "M8 2v8M4.5 7 8 10.5 11.5 7M3 13.5h10";
  var I_COPY = "M5.5 5.5h7v8h-7zM3.5 10.5v-8h7";
  var I_SHARE = "M8 10V2.5M5 5.5 8 2.5l3 3M3.5 9v4.5h9V9";
  function brandMark() {
    return s("svg", { width: 24, height: 24, viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" },
      s("rect", { x: 1, y: 1, width: 22, height: 22, rx: 6, fill: "none", stroke: "currentColor", "stroke-width": 1.4, "class": "brand-box" }),
      s("path", { d: "M3.5 13h4l2-6 3 10 2.4-7 1.6 3h4", fill: "none", stroke: "currentColor", "stroke-width": 1.9, "stroke-linecap": "round", "stroke-linejoin": "round", "class": "brand-trace" }));
  }
  function statusGlyph() {
    var p = {
      under_attack: "M12 3 22 20H2z M12 9.5v5 M12 17.2v.2",
      faulty: "M2 12h6l2-4 4 8 2-4h6",
      minor_issues: "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z M12 8v.2 M12 11v6",
      healthy: "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z M7.5 12.5l3 3 6-6.5"
    }[status];
    return s("svg", { "class": "glyph", viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" },
      s("path", { d: p, fill: "none", stroke: "currentColor", "stroke-width": 2.2, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  }

  // ---------------------------------------------------------- feedback
  var toastEl = h("div", { "class": "toast", role: "status", "aria-live": "polite" });
  var toastTimer = null;
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove("show"); }, 2200);
  }
  function copyText(text, okMsg) {
    function fallback() {
      var ta = h("textarea", { "aria-hidden": "true" });
      ta.value = text;
      ta.style.position = "fixed"; ta.style.opacity = "0"; ta.style.top = "0";
      doc.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = doc.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      toast(ok ? okMsg : "Copy failed. Select the text and press Ctrl+C.");
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(okMsg); }, fallback);
    } else { fallback(); }
  }
  function download(filename, mime, data) {
    var blob = new Blob([data], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = h("a", { href: url, download: filename, hidden: true });
    doc.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
  }
  function b64bytes(b64) {
    if (typeof b64 !== "string" || !/^[A-Za-z0-9+/=\s]+$/.test(b64)) { return null; }
    try {
      var bin = atob(b64.replace(/\s+/g, "")), out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
      return out;
    } catch (e) { return null; }
  }
  function downloadEvidence(f) {
    var bytes = b64bytes(evidence[f.id]);
    if (!bytes) { toast("Evidence file is not available."); return; }
    var id = str(f.id).replace(/[^A-Za-z0-9_-]/g, "") || "finding";
    download(id + "-evidence.pcap", "application/vnd.tcpdump.pcap", bytes);
    toast("Saved " + id + "-evidence.pcap");
  }
  function exportHtml() {
    var clone = doc.documentElement.cloneNode(true);
    clone.removeAttribute("data-embedded");
    clone.removeAttribute("data-status");
    var app = clone.querySelector("#app");
    while (app && app.firstChild) { app.removeChild(app.firstChild); }
    var b = clone.querySelector("body");
    if (b) { b.removeAttribute("class"); }
    Array.prototype.forEach.call(clone.querySelectorAll("body > :not(#app):not(script):not(noscript)"), function (n) { n.remove(); });
    return "<!DOCTYPE html>\n" + clone.outerHTML;
  }

  // ------------------------------------------------------- share summary
  function shareText() {
    var L = [];
    L.push("Faultline verdict for " + str(capture.name || "capture") + ": " + STATUS[status].share +
      " (health " + (num(verdict.score) === null ? "?" : Math.round(verdict.score)) + "/100)");
    if (verdict.headline) { L.push(str(verdict.headline)); }
    if (verdict.summary) { L.push(""); L.push(str(verdict.summary)); }
    if (incidents.length) {
      L.push(""); L.push("Fix this first:");
      incidents.forEach(function (inc) {
        L.push("- " + str(inc.title));
        arr(inc.first_fix).forEach(function (step, i) { L.push("    " + (i + 1) + ". " + str(step).replace(/`/g, "")); });
      });
    }
    if (findings.length) {
      L.push(""); L.push("Findings:");
      findings.forEach(function (f) {
        L.push("- [" + CAT[cat(f.category)].one + ", " + SEV[sevIdx(f.severity)].toLowerCase() + "] " + str(f.id) + " " + str(f.title));
      });
    }
    L.push("");
    L.push("Generated offline by Faultline " + str(tool.version) + (redacted ? " (addresses redacted)" : "") + ".");
    return L.join("\n");
  }

  // ------------------------------------------------------------ top bar
  function topbar() {
    var modeBtns = [
      h("button", { type: "button", "aria-pressed": "true", "data-mode": "beginner" }, "Beginner"),
      h("button", { type: "button", "aria-pressed": "false", "data-mode": "expert" }, "Expert")
    ];
    modeBtns.forEach(function (b) {
      b.addEventListener("click", function () {
        var expert = b.getAttribute("data-mode") === "expert";
        doc.body.classList.toggle("expert", expert);
        modeBtns.forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      });
    });
    var tools = [
      h("div", { "class": "segmented", role: "group", "aria-label": "Explanation level" }, modeBtns),
      h("button", { type: "button", "class": "btn", onclick: function () { copyText(shareText(), "Summary copied to the clipboard"); } },
        icon(I_SHARE), h("span", { "class": "label" }, "Share summary"))
    ];
    if (EMBEDDED) {
      tools.push(h("button", { type: "button", "class": "btn", title: "Download the report as JSON",
        onclick: function () { download("faultline-" + safeFileStem(capture.name) + ".json", "application/json", JSON.stringify(R, null, 2)); } },
        icon(I_DOWN), h("span", { "class": "label" }, "JSON")));
      tools.push(h("button", { type: "button", "class": "btn", title: "Download this report as a single HTML file",
        onclick: function () { download("faultline-" + safeFileStem(capture.name) + ".html", "text/html", exportHtml()); } },
        icon(I_DOWN), h("span", { "class": "label" }, "HTML")));
      tools.push(h("a", { "class": "btn primary", href: "/" }, "Analyze another capture"));
    }
    var links = [["#verdict", "Verdict"], ["#fix-first", "Fix first"], ["#findings", "Findings"], ["#network", "Network"], ["#capture", "Capture"]];
    return h("header", { "class": "topbar" },
      h("div", { "class": "wrap" },
        h("a", { "class": "brand", href: "#verdict" }, brandMark(), "Faultline"),
        h("nav", { "class": "navlinks", "aria-label": "Report sections" },
          links.filter(function (l) { return l[0] !== "#fix-first" || hasFixFirst(); })
            .map(function (l) { return h("a", { href: l[0] }, l[1]); })),
        h("div", { "class": "tools" }, tools)));
  }

  // ------------------------------------------------------------- gauge
  function gauge(score) {
    var sc = clamp(num(score) === null ? 0 : num(score), 0, 100);
    var cx = 120, cy = 116, r = 92, a0 = 135, sweep = 270;
    function pt(deg, rr) { var a = deg * Math.PI / 180; return [cx + rr * Math.cos(a), cy + rr * Math.sin(a)]; }
    var p0 = pt(a0, r), p1 = pt(a0 + sweep, r);
    var d = "M" + p0[0].toFixed(2) + " " + p0[1].toFixed(2) + " A" + r + " " + r + " 0 1 1 " + p1[0].toFixed(2) + " " + p1[1].toFixed(2);
    var ticks = [];
    for (var i = 0; i <= 10; i++) {
      var deg = a0 + sweep * i / 10, q0 = pt(deg, r + 9), q1 = pt(deg, r + (i % 5 === 0 ? 17 : 13));
      ticks.push(s("line", { "class": "tick", x1: q0[0].toFixed(2), y1: q0[1].toFixed(2), x2: q1[0].toFixed(2), y2: q1[1].toFixed(2), "stroke-width": i % 5 === 0 ? 1.6 : 1 }));
    }
    var val = s("path", { "class": "value draw", d: d, fill: "none", "stroke-width": 12, "stroke-linecap": "round", pathLength: 100 });
    val.style.strokeDasharray = sc + " 100";
    val.style.setProperty("--arc", String(sc));
    if (sc === 0) { val.style.strokeOpacity = "0"; }
    var e0 = pt(a0, r + 26), e1 = pt(a0 + sweep, r + 26);
    return s("svg", { "class": "gauge", viewBox: "0 0 240 214", role: "img", "aria-label": "Health score " + Math.round(sc) + " out of 100" },
      ticks,
      s("path", { "class": "track", d: d, fill: "none", "stroke-width": 12, "stroke-linecap": "round" }),
      val,
      s("text", { "class": "num", x: cx, y: cy + 14, "text-anchor": "middle" }, String(Math.round(sc))),
      s("text", { "class": "lbl", x: cx, y: cy + 38, "text-anchor": "middle" }, "health score"),
      s("text", { "class": "end", x: e0[0].toFixed(1), y: (e0[1] + 4).toFixed(1), "text-anchor": "middle" }, "0"),
      s("text", { "class": "end", x: e1[0].toFixed(1), y: (e1[1] + 4).toFixed(1), "text-anchor": "middle" }, "100"));
  }

  // -------------------------------------------------------------- hero
  function headline() {
    // The big status word is already shown; drop a repeated "Under attack:" prefix.
    var t = str(verdict.headline).trim(), w = STATUS[status].word;
    if (t.toLowerCase().indexOf(w.toLowerCase() + ":") === 0) { t = t.slice(w.length + 1).trim(); }
    return t ? t.charAt(0).toUpperCase() + t.slice(1) : "Analysis complete.";
  }
  function hero() {
    var counts = obj(verdict.counts);
    var countEls = ["attack", "fault", "misconfig", "info"].map(function (k) {
      var n = num(counts[k]);
      if (n === null) { n = findings.filter(function (f) { return cat(f.category) === k; }).length; }
      if (k === "info" && n === 0) { return null; }
      var label = n === 1 ? CAT[k].one.toLowerCase() : CAT[k].many;
      if (k === "misconfig") { label = n === 1 ? "misconfig" : "misconfigs"; }
      return h("li", null, h("button", {
        type: "button", "class": "count c-" + k + (n === 0 ? " zero" : ""), disabled: n === 0 ? true : null,
        onclick: function () { setFilter(k); var el = doc.getElementById("findings"); if (el) { el.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth" }); } }
      }, h("b", null, String(n)), h("span", null, label)));
    });
    var meta = h("dl", { "class": "meta" },
      h("dt", null, "Capture"), h("dd", null, str(capture.name) || "unnamed"),
      h("dt", null, "Duration"), h("dd", null, fmtDur(capture.duration)),
      h("dt", null, "Packets"), h("dd", null, fmtInt(capture.packets)),
      h("dt", null, "Started"), h("dd", null, fmtDate(capture.first_ts)));
    var notices = [];
    var capWarn = arr(capture.warnings).concat(arr(R.warnings));
    if (capture.truncated === true || capture.limited === true) {
      notices.push(h("p", { "class": "notice" },
        h("span", null, capture.truncated === true ? "This capture file is incomplete, so the results cover only the part that could be read." :
          "This capture hit a safety limit, so only part of it was analysed."), " ",
        h("a", { href: "#capture" }, "Capture details")));
    } else if (capWarn.length) {
      notices.push(h("p", { "class": "notice" }, h("span", null, capWarn.length + " " + plural(capWarn.length, "note", "notes") + " from reading the file."), " ", h("a", { href: "#capture" }, "Capture details")));
    }
    if (redacted) {
      notices.push(h("p", { "class": "notice privacy" }, h("span", null, "Privacy mode: IP and MAC addresses are replaced with consistent pseudonyms, and evidence downloads are turned off, so this report is safe to share.")));
    }
    return h("section", { id: "verdict", "class": "hero", "aria-labelledby": "verdict-word" },
      h("div", { "class": "wrap" },
        h("div", { "class": "hero-grid" },
          h("div", { "class": "hero-text" },
            h("p", { "class": "status-word", id: "verdict-word" }, statusGlyph(), STATUS[status].word),
            h("h1", { "class": "headline" }, headline()),
            verdict.summary ? h("p", { "class": "summary" }, rich(verdict.summary)) : null,
            h("ul", { "class": "counts", "aria-label": "Findings by type" }, countEls)),
          h("div", { "class": "hero-side" }, gauge(verdict.score), meta)),
        notices,
        timeline()));
  }

  // ---------------------------------------------------------- timeline
  var chartRedraw = null;
  function niceStep(raw) {
    var steps = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400];
    for (var i = 0; i < steps.length; i++) { if (steps[i] >= raw) { return steps[i]; } }
    return Math.ceil(raw / 86400) * 86400;
  }
  function niceMax(v) {
    if (v <= 0) { return 1; }
    var p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p;
  }
  function timeline() {
    var series = arr(tl.series).filter(function (p) { return p && num(p.t) !== null; });
    var markers = arr(tl.markers).filter(function (m) { return m && num(m.t) !== null; });
    var bucket = num(tl.bucket_seconds) || 1;
    var box = h("div", { "class": "chart" });
    var tip = h("div", { "class": "tooltip", "aria-hidden": "true" });
    var fig = h("figure", { "class": "seismo", id: "timeline" },
      h("div", { "class": "seismo-head" },
        h("h2", null, "Timeline"),
        h("p", null, "Packets per second across the capture. Coloured bands show when each finding was happening.")),
      box,
      markers.length ? h("ul", { "class": "legend", "aria-label": "Jump to a finding" }, markers.map(function (m) {
        var k = cat(m.category), f = byId[m.finding];
        return h("li", null, h("button", { type: "button", "class": "c-" + k, onclick: function () { goto(m.finding); } },
          h("span", { "class": "fid" }, str(m.finding)),
          h("span", { "class": "ltxt" }, str(m.title || (f && f.title))),
          h("span", { "class": "sr-only" }, ", starts at " + fmtClock(rel(m.t)))));
      })) : null);
    if (!series.length) {
      box.appendChild(h("p", { "class": "more" }, "No timing data in this capture."));
      return fig;
    }
    var start = num(tl.start); if (start === null) { start = series[0].t; }
    var endT = series[series.length - 1].t + bucket;
    var span = Math.max(num(capture.duration) || 0, endT - start, 1e-6);
    var maxV = niceMax(Math.max.apply(null, series.map(function (p) { return (num(p.packets) || 0) / bucket; })));
    var firstDraw = true;

    function draw() {
      var W = Math.max(320, box.clientWidth || 900), H = 150 + (markers.length ? markers.length * 6 + 8 : 0);
      box.style.height = H + "px";
      var lanes = [], laneOf = [];
      var padL = 44, padR = 10, laneH = 6, lanesH = markers.length ? markers.length * laneH + 8 : 0, padB = 20 + lanesH;
      function xRaw(t) { return (t - start) / span; }
      markers.forEach(function (m, i) {
        var px = padL + xRaw(m.t) * (W - padL - padR), lane = 0;
        while (lane < lanes.length && px - lanes[lane] < 26) { lane++; }
        if (lane > 2) { lane = 2; }
        lanes[lane] = px; laneOf[i] = lane;
      });
      var padT = 12 + Math.min(lanes.length, 3) * 21;
      var w = W - padL - padR, hh = H - padT - padB;
      function x(t) { return padL + clamp(xRaw(t), 0, 1) * w; }
      function y(v) { return padT + hh - clamp(v / maxV, 0, 1) * hh; }
      while (box.firstChild) { box.removeChild(box.firstChild); }
      var svg = s("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, role: "img",
        "aria-label": "Packets per second over " + fmtDur(span) + ", with " + markers.length + " finding markers" });
      svg.appendChild(s("defs", null, s("linearGradient", { id: "fl-trace-fill", x1: 0, y1: 0, x2: 0, y2: 1 },
        s("stop", { "class": "s0", offset: "0" }), s("stop", { "class": "s1", offset: "1" }))));
      [0, 0.5, 1].forEach(function (f) {
        var yy = y(maxV * f);
        svg.appendChild(s("line", { "class": "grid", x1: padL, x2: W - padR, y1: yy, y2: yy }));
        svg.appendChild(s("text", { "class": "axis", x: padL - 8, y: yy + 4, "text-anchor": "end" }, fmtInt(maxV * f) + "/s"));
      });
      var step = niceStep(span / Math.max(2, Math.floor(w / 110)));
      for (var tk = 0; tk <= span + 1e-9; tk += step) {
        svg.appendChild(s("text", { "class": "axis", x: x(start + tk), y: padT + hh + lanesH + 16, "text-anchor": tk === 0 ? "start" : "middle" }, fmtClock(tk)));
      }
      // bands (behind the trace)
      markers.forEach(function (m, i) {
        var x0 = x(m.t), x1 = x(num(m.end) !== null ? m.end : m.t), k = cat(m.category);
        svg.appendChild(s("rect", { "class": "band k-" + k, "data-f": str(m.finding), x: x0, y: padT, width: Math.max(3, x1 - x0), height: hh }));
        svg.appendChild(s("rect", { "class": "lane k-" + k, "data-f": str(m.finding), x: x0, y: padT + hh + 6 + i * laneH, width: Math.max(4, x1 - x0), height: laneH - 2, rx: 2 }));
      });
      var pts = series.map(function (p) { return [x(p.t + bucket / 2), y((num(p.packets) || 0) / bucket)]; });
      var line = "M" + pts.map(function (p) { return p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" L");
      var area = line + " L" + pts[pts.length - 1][0].toFixed(1) + " " + (padT + hh) + " L" + pts[0][0].toFixed(1) + " " + (padT + hh) + " Z";
      var fill = s("path", { "class": "fill" + (firstDraw ? " draw" : ""), d: area });
      var trace = s("path", { "class": "trace" + (firstDraw ? " draw" : ""), d: line });
      svg.appendChild(fill); svg.appendChild(trace);
      // pins
      markers.forEach(function (m, i) {
        var px = x(m.t), py = 12 + laneOf[i] * 21, k = cat(m.category);
        var g = s("g", { "class": "pin k-" + k });
        g.appendChild(s("title", null, str(m.finding) + ": " + str(m.title)));
        g.appendChild(s("line", { "class": "stem", x1: px, x2: px, y1: py + 8, y2: padT + hh }));
        var lbl = str(m.finding).slice(0, 4), pw = 10 + lbl.length * 7;
        g.appendChild(s("rect", { x: px - pw / 2, y: py - 9, width: pw, height: 18, rx: 9 }));
        g.appendChild(s("text", { "class": "pin-label", x: px, y: py + 4, "text-anchor": "middle" }, lbl));
        g.addEventListener("click", function () { goto(m.finding); });
        svg.appendChild(g);
      });
      var cursor = s("line", { "class": "cursor", x1: 0, x2: 0, y1: padT, y2: padT + hh });
      svg.appendChild(cursor);
      var hit = s("rect", { x: padL, y: padT, width: w, height: hh + lanesH, fill: "transparent" });
      hit.style.cursor = "crosshair";
      svg.appendChild(hit);
      function at(ev) {
        var rect = svg.getBoundingClientRect();
        var px = (ev.clientX - rect.left) * (W / rect.width);
        var t = start + clamp((px - padL) / w, 0, 1) * span;
        var idx = clamp(Math.floor((t - start) / bucket), 0, series.length - 1);
        var active = markers.filter(function (m) {
          var e = num(m.end) !== null ? m.end : m.t;
          return t >= m.t - bucket / 2 && t <= e + bucket / 2;
        });
        return { px: px, t: t, p: series[idx], active: active };
      }
      hit.addEventListener("mousemove", function (ev) {
        var a = at(ev);
        box.classList.add("hovering");
        cursor.setAttribute("x1", a.px); cursor.setAttribute("x2", a.px);
        while (tip.firstChild) { tip.removeChild(tip.firstChild); }
        append(tip, [h("b", null, "+" + fmtClock(a.t - start)), h("div", null, fmtInt((num(a.p.packets) || 0) / bucket) + " packets/s")]);
        if (a.active.length) {
          tip.appendChild(h("ul", null, a.active.slice(0, 5).map(function (m) {
            return h("li", { "class": "c-" + cat(m.category) }, str(m.finding) + " " + str(m.title));
          })));
        }
        Array.prototype.forEach.call(svg.querySelectorAll(".band, .lane"), function (b) {
          b.classList.toggle("hot", a.active.some(function (m) { return str(m.finding) === b.getAttribute("data-f"); }));
        });
        box.appendChild(tip);
        var bw = box.clientWidth, tw = tip.offsetWidth || 200;
        var left = a.px * (bw / W) + 14;
        if (left + tw > bw) { left = a.px * (bw / W) - tw - 14; }
        tip.style.left = Math.max(0, left) + "px";
        tip.style.top = (padT - 4) + "px";
        hit.style.cursor = a.active.length ? "pointer" : "crosshair";
      });
      hit.addEventListener("mouseleave", function () {
        box.classList.remove("hovering");
        Array.prototype.forEach.call(svg.querySelectorAll(".hot"), function (b) { b.classList.remove("hot"); });
      });
      hit.addEventListener("click", function (ev) {
        var a = at(ev);
        if (a.active.length) { goto(a.active[a.active.length - 1].finding); }
      });
      box.appendChild(svg);
      box.appendChild(tip);
      if (firstDraw && !REDUCED && trace.getTotalLength) {
        try { trace.style.setProperty("--len", String(Math.ceil(trace.getTotalLength()))); } catch (e) { /* ignore */ }
      }
      firstDraw = false;
    }
    chartRedraw = draw;
    return fig;
  }

  // ------------------------------------------------------- severity bits
  function sevEl(v) {
    var n = sevIdx(v), pips = [];
    for (var i = 1; i <= 4; i++) { pips.push(h("i", { "class": i <= n ? "on" : null })); }
    return h("span", { "class": "sev" }, h("span", { "class": "pips", "aria-hidden": "true" }, pips), SEV[n]);
  }
  function pill(c) { c = cat(c); return h("span", { "class": "pill c-" + c }, CAT[c].one); }
  function confEl(v) {
    v = num(v); if (v === null) { return null; }
    return h("span", { "class": "conf" }, Math.round(clamp(v, 0, 1) * 100) + "% confident");
  }

  // ---------------------------------------------------------- fix first
  function hasFixFirst() {
    return incidents.length > 0 || findings.some(function (f) { return cat(f.category) !== "info"; });
  }
  function fixFirst() {
    if (!hasFixFirst()) { return null; }
    var items = incidents.slice();
    if (!items.length) {
      var top = findings.filter(function (f) { return cat(f.category) !== "info"; })[0];
      items = [{ title: top.title, category: top.category, severity: top.severity, story: top.summary,
        root_cause: top.id, findings: [top.id], first_fix: arr(top.fix).slice(0, 3) }];
    }
    return h("section", { id: "fix-first", "class": "section" },
      h("div", { "class": "wrap" },
        h("div", { "class": "section-head" },
          h("div", null,
            h("h2", null, "Fix this first"),
            h("p", null, "Related problems are grouped into one story. Fixing the root cause usually clears the symptoms that follow from it."))),
        h("div", { "class": "incidents" }, items.map(incidentEl))));
  }
  function incidentEl(inc) {
    var k = cat(inc.category);
    var ids = arr(inc.findings).filter(function (id) { return byId[id]; });
    var rootId = byId[inc.root_cause] ? inc.root_cause : ids[0];
    var order = [rootId].concat(ids.filter(function (id) { return id !== rootId; })).filter(Boolean);
    var steps = arr(inc.first_fix);
    if (!steps.length && byId[rootId]) { steps = arr(byId[rootId].fix).slice(0, 3); }
    return h("article", { "class": "incident c-" + k },
      h("div", { "class": "incident-main" },
        h("div", { "class": "row" }, pill(k), sevEl(inc.severity),
          ids.length > 1 ? h("span", { "class": "conf" }, ids.length + " linked findings") : null),
        h("h3", null, str(inc.title)),
        inc.story ? h("p", { "class": "story" }, rich(inc.story)) : null,
        order.length ? h("ol", { "class": "chain", "aria-label": "Root cause, then symptoms" }, order.map(function (id, i) {
          var f = byId[id], fk = cat(f.category);
          return h("li", { "class": "c-" + fk }, h("button", { type: "button", "class": "node" + (i === 0 ? " root" : ""), onclick: function () { goto(id); } },
            h("small", null, h("b", null, str(id)), i === 0 ? " root cause" : " symptom"),
            h("span", null, str(f.title))));
        })) : null),
      h("div", { "class": "incident-fix" },
        h("h4", null, "Do this first"),
        steps.length ? h("ol", { "class": "steps" }, steps.map(function (st) { return h("li", null, h("span", null, rich(st))); }))
          : h("p", null, "See the finding for details.")));
  }

  // ----------------------------------------------------------- findings
  var cards = [];
  var chipEls = {};
  var currentFilter = "all";
  function setFilter(k) {
    currentFilter = k;
    Object.keys(chipEls).forEach(function (c) { chipEls[c].setAttribute("aria-pressed", String(c === k)); });
    cards.forEach(function (c) { c.el.hidden = !(k === "all" || c.cat === k); });
  }
  function findingsSection() {
    var counts = { all: findings.length, attack: 0, fault: 0, misconfig: 0, info: 0 };
    findings.forEach(function (f) { counts[cat(f.category)]++; });
    var chipDefs = [["all", "All"], ["attack", CAT.attack.chip], ["fault", CAT.fault.chip], ["misconfig", CAT.misconfig.chip]];
    if (counts.info) { chipDefs.push(["info", CAT.info.chip]); }
    var chips = h("div", { "class": "chips", role: "group", "aria-label": "Filter findings" }, chipDefs.map(function (d) {
      var b = h("button", { type: "button", "class": "chip", "aria-pressed": String(d[0] === "all"), disabled: counts[d[0]] === 0 ? true : null,
        onclick: function () { setFilter(d[0]); } }, d[1], h("span", { "class": "n" }, String(counts[d[0]])));
      chipEls[d[0]] = b;
      return b;
    }));
    var list = h("div", { "class": "finding-list" });
    if (!findings.length) {
      list.appendChild(h("div", { "class": "empty" },
        h("h3", null, "Nothing looks wrong"),
        h("p", null, "Faultline checked TCP, DNS, DHCP, ARP, ICMP and TLS behaviour in this capture and found no faults, misconfigurations or attacks.")));
    }
    findings.forEach(function (f, i) {
      var c = card(f, i === 0);
      cards.push({ el: c.el, cat: cat(f.category), id: f.id, open: c.open });
      list.appendChild(c.el);
    });
    return h("section", { id: "findings", "class": "section" },
      h("div", { "class": "wrap" },
        h("div", { "class": "section-head" },
          h("div", null,
            h("h2", null, "What we found"),
            h("p", null, "Most important first. Open a finding to see what it means, how to fix it, and the exact packets behind it.")),
          findings.length ? chips : null),
        list));
  }

  function block(title, kids, extraClass) {
    return h("div", { "class": "block" + (extraClass ? " " + extraClass : "") }, h("h4", null, title), kids);
  }
  function dots(weight, k) {
    var w = clamp(num(weight) || 0, 0, 3), out = [];
    for (var i = 1; i <= 3; i++) {
      out.push(h("i", { "class": w >= i - 0.25 ? "on" : (w >= i - 0.75 ? "half" : null) }));
    }
    return h("span", { "class": "dots c-" + k, title: "weight " + w, "aria-label": "weight " + w + " of 3" }, out);
  }
  function reasoning(f) {
    var sc = obj(f.scores), win = cat(f.category);
    var hypKeys = ["attack", "fault", "misconfig"];
    var vals = {}, total = 0;
    hypKeys.forEach(function (k) { vals[k] = Math.max(0, num(sc[k]) || 0); total += vals[k]; });
    var inds = arr(f.indicators).filter(function (i) { return i && typeof i === "object"; });
    var alts = arr(f.alternatives).filter(function (a) { return a && typeof a === "object"; });
    if (!total && !inds.length && !alts.length) { return null; }
    var others = hypKeys.filter(function (k) { return k !== win && vals[k] > 0; })
      .map(function (k) { return vals[k].toFixed(1) + " for " + CAT[k].one.toLowerCase(); });
    var lead = win === "info" ? "This is informational. Here is the evidence we weighed." :
      CAT[win].one + " wins with " + (vals[win] || 0).toFixed(1) + " points of evidence" +
      (others.length ? ", against " + others.join(" and ") + "." : ". Nothing pointed anywhere else.");
    var bar = h("div", { "class": "scorebar", role: "img", "aria-label": hypKeys.map(function (k) { return CAT[k].one + " " + vals[k].toFixed(1); }).join(", ") });
    hypKeys.forEach(function (k) {
      if (!vals[k]) { return; }
      var seg = h("i", { "class": "c-" + k });
      seg.style.width = (100 * vals[k] / total).toFixed(2) + "%";
      bar.appendChild(seg);
    });
    var groups = hypKeys.concat(["info"]).map(function (k) {
      var mine = inds.filter(function (i) { return cat(i.supports) === k; });
      if (!mine.length) { return null; }
      mine.sort(function (a, b) { return (num(b.weight) || 0) - (num(a.weight) || 0); });
      return h("div", { "class": "hyp c-" + k },
        h("h5", null, CAT[k].hyp),
        h("ul", null, mine.map(function (i) { return h("li", null, dots(i.weight, k), h("span", null, str(i.text))); })));
    });
    return h("div", { "class": "reason" },
      h("h4", null, "Fault or attack? Why we think so"),
      h("p", { "class": "lead" }, lead),
      total ? bar : null,
      total ? h("ul", { "class": "scorekey" }, hypKeys.map(function (k) {
        return h("li", { "class": "c-" + k + (k === win ? " win" : "") }, CAT[k].one + " " + vals[k].toFixed(1));
      })) : null,
      h("div", { "class": "hyps" }, groups),
      alts.length ? h("ul", { "class": "whynot" }, alts.map(function (a) {
        return h("li", null, h("b", null, "Why not “" + str(a.title) + "”?"), " ", pill(a.category),
          a.why_not ? h("p", null, rich(a.why_not)) : null);
      })) : null);
  }
  function evidenceBlock(f) {
    var lines = arr(f.evidence_lines).filter(function (l) { return l && typeof l === "object"; });
    var pk = arr(f.packets).filter(function (n) { return num(n) !== null; }).map(function (n) { return Math.round(n); });
    if (!pk.length) { pk = lines.map(function (l) { return Math.round(num(l.no) || 0); }).filter(Boolean); }
    if (!lines.length && !pk.length) { return null; }
    var filter = pk.length ? "frame.number in {" + pk.join(" ") + "}" : "";
    var tools = [];
    if (!redacted && typeof evidence[f.id] === "string") {
      tools.push(h("button", { type: "button", "class": "btn", onclick: function () { downloadEvidence(f); } },
        icon(I_DOWN), "Download evidence .pcap (open in Wireshark)"));
    }
    if (filter) {
      tools.push(h("span", { "class": "filter" }, "In Wireshark:", h("code", { title: filter }, filter),
        h("button", { type: "button", "class": "btn", onclick: function () { copyText(filter, "Wireshark filter copied"); } }, icon(I_COPY), "Copy filter")));
    }
    var total = num(f.packet_total);
    var rows = lines.slice(0, 50).map(function (l) {
      var r = rel(l.ts);
      return h("tr", null,
        h("td", { "class": "num" }, fmtInt(l.no)),
        h("td", { "class": "num mono" }, r === null ? "" : "+" + fmtClock(r, true)),
        h("td", { "class": "mono" }, str(l.summary)));
    });
    var shown = rows.length;
    return h("div", { "class": "block evidence" },
      h("h4", null, "Evidence: the exact packets"),
      tools.length ? h("div", { "class": "evidence-tools" }, tools) : null,
      shown ? h("div", { "class": "table-scroll" }, h("table", null,
        h("thead", null, h("tr", null, h("th", { "class": "num", scope: "col" }, "No."), h("th", { "class": "num", scope: "col" }, "Time"), h("th", { scope: "col" }, "What happened"))),
        h("tbody", null, rows))) : null,
      total !== null && total > shown ? h("p", { "class": "more" }, "Showing " + shown + " of " + fmtInt(total) + " matching packets." +
        (pk.length > shown ? " The filter and the evidence file include " + fmtInt(pk.length) + "." : "")) : null);
  }
  function metricsEl(m) {
    m = obj(m);
    var keys = Object.keys(m).slice(0, 40);
    if (!keys.length) { return null; }
    return h("dl", { "class": "metrics" }, keys.map(function (k) {
      var v = m[k];
      var txt = Array.isArray(v) ? v.slice(0, 20).map(str).join(", ") : (v && typeof v === "object" ? JSON.stringify(v).slice(0, 300) : str(v));
      return h("div", null, h("dt", null, k.replace(/_/g, " ")), h("dd", null, txt));
    }));
  }
  function card(f, openByDefault) {
    var k = cat(f.category), id = str(f.id);
    var bodyId = "fb-" + id.replace(/[^A-Za-z0-9_-]/g, "");
    var causes = findings.filter(function (x) { return x.symptom_of === f.id; }).map(function (x) { return x.id; });
    var toggle = h("button", { type: "button", "class": "toggle", "aria-expanded": "false", "aria-controls": bodyId },
      h("span", null, "Details"), chevron());
    var body = h("div", { "class": "card-body", id: bodyId, hidden: true });
    var built = false;
    function build() {
      if (built) { return; }
      built = true;
      var mitre = str(f.mitre).trim();
      var mm = /^(T\d{4}(?:\.\d{3})?)\s*(.*)$/.exec(mitre);
      append(body, [
        h("div", { "class": "cols" },
          h("div", null,
            block("What's happening", [
              h("p", null, rich(f.explanation || f.summary)),
              f.analogy ? h("p", { "class": "analogy beginner-only" }, rich(f.analogy)) : null
            ])),
          h("div", { "class": "cols-right" },
            f.cause ? block("Likely cause", h("p", null, rich(f.cause))) : null,
            arr(f.fix).length ? h("div", { "class": "block", id: null }, h("h4", null, "How to fix"),
              h("ol", { "class": "ordered" }, arr(f.fix).map(function (st) { return h("li", null, h("span", null, rich(st))); }))) : null)),
        reasoning(f),
        mitre ? h("p", { "class": "mitre" }, "MITRE ATT&CK", mm ? h("b", null, mm[1]) : null, mm ? mm[2] : mitre) : null,
        evidenceBlock(f),
        arr(f.hosts).length ? block("Devices involved", h("ul", { "class": "hostlist" }, arr(f.hosts).slice(0, 60).map(function (x) { return h("li", null, str(x)); }))) : null,
        h("div", { "class": "block expert-only" },
          h("h4", null, "Technical details"),
          f.technical ? h("pre", { "class": "tech" }, str(f.technical)) : null,
          h("dl", { "class": "metrics" },
            h("div", null, h("dt", null, "detector"), h("dd", null, str(f.kind))),
            h("div", null, h("dt", null, "time"), h("dd", null, (rel(f.first_ts) === null ? "?" : "+" + fmtClock(rel(f.first_ts), true)) + " to " + (rel(f.last_ts) === null ? "?" : "+" + fmtClock(rel(f.last_ts), true))))),
          metricsEl(f.metrics))
      ]);
    }
    function open(state) {
      var isOpen = toggle.getAttribute("aria-expanded") === "true";
      var want = state === undefined ? !isOpen : state;
      if (want) { build(); }
      toggle.setAttribute("aria-expanded", String(want));
      toggle.firstChild.textContent = want ? "Hide details" : "Details";
      body.hidden = !want;
    }
    toggle.addEventListener("click", function () { open(); });
    var el = h("article", { "class": "card c-" + k, id: "finding-" + id.replace(/[^A-Za-z0-9_-]/g, ""), "aria-labelledby": bodyId + "-t" },
      h("div", { "class": "card-head" },
        h("div", null,
          h("div", { "class": "card-tags" }, pill(k), sevEl(f.severity), confEl(f.confidence), h("span", { "class": "fid-tag" }, id)),
          h("h3", { id: bodyId + "-t", tabindex: "-1" }, str(f.title)),
          h("p", null, rich(f.summary)),
          f.symptom_of && byId[f.symptom_of] ? h("p", { "class": "symlink" }, "Symptom of", jump(f.symptom_of, f.symptom_of + ": " + str(byId[f.symptom_of].title))) : null,
          causes.length ? h("p", { "class": "symlink" }, "Leads to", causes.map(function (c) { return jump(c, c); })) : null),
        toggle),
      body);
    if (openByDefault) { open(true); }
    return { el: el, open: open };
  }
  function goto(id) {
    var c = null;
    for (var i = 0; i < cards.length; i++) { if (cards[i].id === id) { c = cards[i]; } }
    if (!c) { return; }
    if (c.el.hidden) { setFilter("all"); }
    c.open(true);
    c.el.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
    c.el.classList.remove("flash");
    void c.el.offsetWidth;
    c.el.classList.add("flash");
    var t = c.el.querySelector("h3");
    if (t) { try { t.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  // ------------------------------------------------------------ network
  function barsList(rows, labelMono) {
    var max = Math.max.apply(null, rows.map(function (r) { return r.v; }).concat([1]));
    return h("ul", { "class": "bars" }, rows.map(function (r) {
      var fillEl = h("i");
      fillEl.style.width = (100 * r.v / max).toFixed(1) + "%";
      return h("li", null, h("span", { "class": "lbl" + (labelMono ? " mono" : ""), title: r.label }, r.label),
        h("span", { "class": "bar", "aria-hidden": "true" }, fillEl), h("span", { "class": "val" }, r.text));
    }));
  }
  function networkSection() {
    var attackHosts = {};
    findings.forEach(function (f) {
      if (cat(f.category) !== "attack") { return; }
      arr(f.hosts).slice(0, 1).forEach(function (x) { (attackHosts[x] = attackHosts[x] || []).push(f.id); });
    });
    var hs = hosts.slice().sort(function (a, b) {
      return ((num(b.packets_sent) || 0) + (num(b.packets_recv) || 0)) - ((num(a.packets_sent) || 0) + (num(a.packets_recv) || 0));
    });
    var shown = hs.slice(0, 60);
    var hostTable = h("div", { "class": "panel" },
      h("h3", null, "Devices"),
      shown.length ? h("div", { "class": "table-scroll" }, h("table", { "class": "hosts" },
        h("thead", null, h("tr", null, ["Address", "Name", "Hardware (MAC)", "Role", "Sent", "Received", "Data"].map(function (t, i) {
          return h("th", { scope: "col", "class": i >= 4 ? "num" : null }, t);
        }))),
        h("tbody", null, shown.map(function (x) {
          var ip = str(x.ip);
          var macs = arr(x.macs).map(str);
          return h("tr", null,
            h("td", { "class": "mono" }, ip, x.local === false ? h("div", { "class": "ext" }, "outside network") : null),
            h("td", null, arr(x.names).slice(0, 4).map(function (n, i) { return h("div", null, str(n)); })),
            h("td", { "class": "mono" }, macs.slice(0, 4).map(function (m) { return h("div", null, m); }),
              macs.length > 1 ? h("span", { "class": "badge flag" }, macs.length + " MACs for one IP") : null),
            h("td", null, arr(x.roles).map(function (r) {
              r = str(r);
              return h("span", { "class": "badge r-" + r.replace(/[^a-z-]/g, "") }, { "gateway": "Router", "dns-server": "DNS server", "dhcp-server": "DHCP server" }[r] || r);
            }), attackHosts[ip] ? h("span", { "class": "badge flag" }, "Suspect in " + attackHosts[ip].join(", ")) : null),
            h("td", { "class": "num" }, fmtInt(x.packets_sent)),
            h("td", { "class": "num" }, fmtInt(x.packets_recv)),
            h("td", { "class": "num" }, fmtBytes((num(x.bytes_sent) || 0) + (num(x.bytes_recv) || 0))));
        })))) : h("p", { "class": "more" }, "No devices were seen."),
      hs.length > shown.length ? h("p", { "class": "more" }, "Showing the " + shown.length + " busiest of " + fmtInt(hs.length) + " devices.") : null);

    var protos = obj(stats.protocols);
    var pkeys = Object.keys(protos).filter(function (k) { return num(protos[k]) !== null; });
    var ptotal = pkeys.reduce(function (a, k) { return a + protos[k]; }, 0) || 1;
    var prow = pkeys.sort(function (a, b) { return protos[b] - protos[a]; }).slice(0, 14).map(function (k) {
      return { label: k, v: protos[k], text: (100 * protos[k] / ptotal).toFixed(protos[k] / ptotal < 0.01 ? 2 : 1) + "%" };
    });
    var talk = arr(stats.top_talkers).filter(function (t) { return t && typeof t === "object"; }).slice(0, 10).map(function (t) {
      return { label: str(t.ip), v: num(t.bytes) || 0, text: fmtBytes(t.bytes) };
    });
    var convs = arr(stats.conversations).filter(function (c) { return c && typeof c === "object"; }).slice(0, 12);
    return h("section", { id: "network", "class": "section" },
      h("div", { "class": "wrap" },
        h("div", { "class": "section-head" }, h("div", null,
          h("h2", null, "Who was talking"),
          h("p", null, "Every device seen in the capture, what it does, and how much it sent."))),
        hostTable,
        h("div", { "class": "net-grid" },
          h("div", { "class": "panel" }, h("h3", null, "Protocols"), prow.length ? barsList(prow, false) : h("p", { "class": "more" }, "No protocol data.")),
          h("div", { "class": "panel" }, h("h3", null, "Busiest devices by data"), talk.length ? barsList(talk, true) : h("p", { "class": "more" }, "No traffic data."))),
        convs.length ? h("div", { "class": "panel", id: "conversations" },
          h("h3", null, "Busiest conversations"),
          h("div", { "class": "table-scroll" }, h("table", null,
            h("thead", null, h("tr", null, h("th", { scope: "col" }, "Between"), h("th", { scope: "col" }, "And"), h("th", { scope: "col" }, "Protocol"),
              h("th", { scope: "col", "class": "num" }, "Packets"), h("th", { scope: "col", "class": "num" }, "Data"))),
            h("tbody", null, convs.map(function (c) {
              return h("tr", null, h("td", { "class": "mono" }, str(c.a)), h("td", { "class": "mono" }, str(c.b)), h("td", null, str(c.proto)),
                h("td", { "class": "num" }, fmtInt(c.packets)), h("td", { "class": "num" }, fmtBytes(c.bytes)));
            }))))) : null));
  }

  // ------------------------------------------------------------ capture
  function captureSection() {
    var c = capture;
    var lt = arr(c.linktypes).map(function (x) { return ({ 0: "Null/loopback", 1: "Ethernet", 101: "Raw IP", 105: "802.11", 113: "Linux cooked", 127: "802.11 radiotap", 228: "Raw IPv4", 229: "Raw IPv6", 276: "Linux cooked v2" })[x] || ("type " + str(x)); });
    var rows = [
      ["File", str(c.name) || "unnamed"],
      ["Format", (str(c.format) || "?") + (c.compressed === true ? " (gzip compressed)" : "")],
      ["File size", fmtBytes(c.file_bytes)],
      ["Packets", fmtInt(c.packets) + (num(c.malformed_packets) ? " (" + fmtInt(c.malformed_packets) + " malformed)" : "")],
      ["Data captured", fmtBytes(c.bytes_captured)],
      ["Link type", lt.join(", ") || "?"],
      ["Started", fmtDate(c.first_ts)],
      ["Ended", fmtDate(c.last_ts)],
      ["Duration", fmtDur(c.duration)],
      ["SHA-256", str(c.sha256) || "?"],
      ["Report created", str(R.generated_at)]
    ];
    var warns = [];
    if (c.truncated === true) { warns.push("The file was truncated. Faultline analysed every complete packet before the cut."); }
    if (c.limited === true) { warns.push("A safety limit was reached, so only part of the file was analysed."); }
    warns = warns.concat(arr(c.warnings).map(str), arr(R.warnings).map(str));
    return h("section", { id: "capture", "class": "section" },
      h("div", { "class": "wrap" },
        h("div", { "class": "section-head" }, h("div", null,
          h("h2", null, "About this capture"),
          h("p", null, "The file Faultline read, and anything unusual about reading it."))),
        h("div", { "class": "capture-grid" },
          h("div", { "class": "panel" }, h("dl", { "class": "kv" }, rows.map(function (r) {
            return [h("dt", null, r[0]), h("dd", { "class": r[0] === "SHA-256" ? "mono" : null }, r[1])];
          }))),
          h("div", { "class": "panel" }, h("h3", null, "Reading notes"),
            warns.length ? h("ul", { "class": "warnlist" }, warns.slice(0, 50).map(function (w) { return h("li", null, w); }))
              : h("p", { "class": "more" }, "The file was read completely, with no problems.")))));
  }

  function footer() {
    return h("footer", { "class": "footer" },
      h("div", { "class": "wrap" },
        h("p", null, h("strong", null, "Generated offline by Faultline " + str(tool.version) + "."), " No data left this machine."),
        redacted ? h("p", null, "Privacy mode was on: addresses are pseudonymised and no raw packets are included.") :
          h("p", null, "This report contains addresses from your network. Re-run with redaction before sharing it publicly.")));
  }

  // -------------------------------------------------------------- mount
  var frag = doc.createDocumentFragment();
  append(frag, [topbar(), h("main", null, hero(), fixFirst(), findingsSection(), networkSection(), captureSection()), footer(), toastEl]);
  root.appendChild(frag);
  if (chartRedraw) {
    chartRedraw();
    var rt = null;
    window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(chartRedraw, 120); });
  }
  if (location.hash && /^#finding-[A-Za-z0-9_-]+$/.test(location.hash)) { goto(location.hash.slice(9)); }
})();
