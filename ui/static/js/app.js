"use strict";

/* ============================================================
   BlueLine UI — talks only to the real local API at /api/*.
   Nothing in this file fabricates scan state, progress, or findings.
   ============================================================ */

if (typeof fetch === "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    document.body.innerHTML = `<div style="padding:40px; font-family:sans-serif; color:#e7ecf6; background:#0a0e16; min-height:100vh;">
      <h2>Your browser engine is too old to run BlueLine</h2>
      <p>BlueLine's UI requires the Fetch API (supported by all browsers since ~2017, and by
      pywebview's native windows). Please open this page in an up-to-date browser.</p>
    </div>`;
  });
  throw new Error("BlueLine UI requires the Fetch API");
}

const state = {
  view: "home",
  targetPath: null,
  targetProfile: null,
  selectedProfile: "quick",
  liveScanId: null,
  livePollHandle: null,
  historyCache: [],
  seenStages: new Set(),      // stage names already rendered at least once this scan
  settledStages: new Set(),   // stage names whose completion/failure draw-in already played
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).error || ""; } catch (e) { /* ignore */ }
    throw new Error(`${path} -> HTTP ${res.status} ${detail}`);
  }
  return res.json();
}

/* ---------------- View routing ---------------- */

const VIEW_TITLES = {
  home: "Home", target: "Target Setup", config: "Scan Configuration",
  live: "Live Scan", findings: "Findings", reports: "Reports", settings: "Settings",
};

function goto(view) {
  state.view = view;
  $$(".view").forEach((v) => v.classList.remove("active"));
  $(`#view-${view}`).classList.add("active");
  $$(".nav-item").forEach((n) => {
    const active = n.dataset.view === view;
    n.classList.toggle("active", active);
    if (active) n.setAttribute("aria-current", "page"); else n.removeAttribute("aria-current");
  });
  $("#topbarTitle").textContent = VIEW_TITLES[view] || view;

  if (view === "home") loadRecentScans();
  if (view === "config") $("#configTargetPath").textContent = state.targetPath
    ? state.targetPath : "No target selected — go to Target Setup first.";
  if (view === "findings") loadScanSelectorOptions();
  if (view === "reports") loadReportsList();
}

$$(".nav-item").forEach((item) => item.addEventListener("click", () => goto(item.dataset.view)));
$$("[data-goto]").forEach((el) => el.addEventListener("click", () => goto(el.dataset.goto)));

/* ---------------- Theme ---------------- */

function applyTheme(theme) {
  document.body.setAttribute("data-theme", theme);
  try { localStorage.setItem("blueline_theme", theme); } catch (e) { /* non-fatal */ }
}
$("#themeToggle").addEventListener("click", () => {
  const current = document.body.getAttribute("data-theme");
  applyTheme(current === "dark" ? "light" : "dark");
});
(function initTheme() {
  let saved = "dark";
  try { saved = localStorage.getItem("blueline_theme") || "dark"; } catch (e) { /* ignore */ }
  applyTheme(saved);
})();

/* ---------------- Home: recent scans ---------------- */

function severityCountsHtml(row) {
  const parts = [];
  if (row.critical_count) parts.push(`<span class="badge badge-CRITICAL">${row.critical_count} CRIT</span>`);
  if (row.high_count) parts.push(`<span class="badge badge-HIGH">${row.high_count} HIGH</span>`);
  if (row.medium_count) parts.push(`<span class="badge badge-MEDIUM">${row.medium_count} MED</span>`);
  if (row.low_count) parts.push(`<span class="badge badge-LOW">${row.low_count} LOW</span>`);
  if (!parts.length) parts.push(`<span class="badge badge-INFORMATIONAL">CLEAN</span>`);
  return parts.join(" ");
}

async function loadRecentScans() {
  const container = $("#recentScansContainer");
  try {
    const rows = await api("/api/history");
    state.historyCache = rows;
    if (!rows.length) {
      container.innerHTML = `<div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M12 8v5l3 2"/></svg>
        No scans yet. Import a target to run your first scan.</div>`;
      return;
    }
    const tableRows = rows.slice(0, 10).map((r) => `
      <tr class="clickable" data-scan-id="${esc(r.scan_id)}">
        <td class="mono">${esc(r.scan_id)}</td>
        <td class="mono" style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(r.target_path)}</td>
        <td>${esc(r.profile)}</td>
        <td>${severityCountsHtml(r)}</td>
        <td>${r.overall_coverage != null ? r.overall_coverage + "%" : "—"}</td>
        <td class="text-muted">${esc((r.started_at || "").replace("T", " ").slice(0, 16))}</td>
      </tr>`).join("");
    container.innerHTML = `<table class="data-table">
      <tr><th>Scan ID</th><th>Target</th><th>Profile</th><th>Severity</th><th>Coverage</th><th>Started</th></tr>
      ${tableRows}
    </table>`;
    $$("#recentScansContainer tr.clickable").forEach((tr) => {
      tr.addEventListener("click", () => {
        selectScanForFindings(tr.dataset.scanId);
        goto("findings");
      });
    });
  } catch (e) {
    container.innerHTML = `<div class="empty-state">Could not load scan history: ${esc(e.message)}</div>`;
  }
}

/* ---------------- Target Setup ---------------- */

$("#discoverBtn").addEventListener("click", async () => {
  const path = $("#targetPathInput").value.trim();
  const statusEl = $("#discoverStatus");
  if (!path) { statusEl.textContent = "Enter a path first."; return; }
  statusEl.textContent = "Discovering…";
  try {
    const profile = await api("/api/target/discover", {
      method: "POST", body: JSON.stringify({ target_path: path }),
    });
    state.targetPath = profile.target_path;
    state.targetProfile = profile;
    statusEl.textContent = "";
    renderTargetProfile(profile);
  } catch (e) {
    statusEl.textContent = `Discovery failed: ${e.message}`;
  }
});

function renderTargetProfile(profile) {
  $("#targetProfileContainer").classList.remove("hidden");

  const summary = [
    ["Type", profile.target_type],
    ["Languages", (profile.languages || []).join(", ") || "none detected"],
    ["Interfaces", (profile.interfaces || []).join(", ") || "none detected"],
    ["Files", profile.file_count],
    ["Package managers", (profile.package_managers || []).join(", ") || "none"],
    ["Dependencies (approx.)", profile.dependencies_count],
  ];
  $("#profileSummary").innerHTML = summary.map(([label, value]) => `
    <div class="card metric-card">
      <div class="label">${esc(label)}</div>
      <div class="value" style="font-size:16px;">${esc(value)}</div>
    </div>`).join("");

  const caps = profile.capabilities || [];
  $("#capabilitiesList").innerHTML = caps.length ? caps.map((c) => `
    <div class="capability-row">
      <div>
        <div>${esc(c.name)}</div>
        ${c.notes ? `<div class="text-muted" style="font-size:11.5px; margin-top:2px;">${esc(c.notes)}</div>` : ""}
      </div>
      <span class="cap-level cap-${esc(c.level)}">${esc(c.level).replace(/_/g, " ")}</span>
    </div>`).join("") : `<div class="text-muted">No capabilities declared for this target.</div>`;

  if (profile.discovery_warnings && profile.discovery_warnings.length) {
    $("#capabilitiesList").innerHTML += `<div class="text-muted mt-16" style="font-size:12px;">
      ⚠ ${profile.discovery_warnings.map(esc).join("; ")}</div>`;
  }
}

/* ---------------- Scan Configuration ---------------- */

// Listen on the radio inputs' change event (not a click on the label) so
// this works correctly for keyboard users navigating with arrow keys
// between radios in the group, not just mouse clicks.
$$('input[name="scanProfile"]').forEach((input) => {
  input.addEventListener("change", () => {
    $$(".profile-option").forEach((o) => o.classList.remove("selected"));
    input.closest(".profile-option").classList.add("selected");
    state.selectedProfile = input.value;
  });
});

$("#startScanBtn").addEventListener("click", async () => {
  if (!state.targetPath) { alert("Select and discover a target first (Target Setup)."); goto("target"); return; }
  try {
    const resp = await api("/api/scan/start", {
      method: "POST",
      body: JSON.stringify({ target_path: state.targetPath, profile: state.selectedProfile }),
    });
    state.liveScanId = resp.scan_id;
    goto("live");
    startLivePolling();
  } catch (e) {
    alert(`Failed to start scan: ${e.message}`);
  }
});

/* ---------------- Live Scan ---------------- */

// pathLength="1" makes the dash math in CSS (.stage-check-path /
// .stage-fail-path) independent of the actual SVG path geometry.
const STAGE_ICONS = {
  running: `<div class="spinner"></div>`,
  completed: (animate) => `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--low)" stroke-width="2.5">
    <path pathLength="1" class="${animate ? "stage-check-path" : ""}" d="M4 12l5 5L20 6"/></svg>`,
  failed: (animate) => `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--crit)" stroke-width="2.5">
    <path pathLength="1" class="${animate ? "stage-fail-path" : ""}" d="M6 6l12 12M18 6L6 18"/></svg>`,
  skipped: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--text-muted)" stroke-width="2.5"><circle cx="12" cy="12" r="9"/></svg>`,
};

function stageDetailText(status, detail) {
  if (!detail) return "";
  if (status === "completed" && "findings" in detail) return `${detail.findings} finding(s)`;
  if (status === "failed" && detail.error) return detail.error;
  if (detail.reason) return detail.reason;
  return "";
}

function renderStageLog(log) {
  const seen = new Map(); // stage -> latest {status, detail}, preserving first-seen order
  for (const entry of log) {
    seen.set(entry.stage, { status: entry.status, detail: entry.detail });
  }
  if (!seen.size) {
    $("#stageLog").innerHTML = `<div class="empty-state">Starting…</div>`;
    return;
  }
  const rows = Array.from(seen.entries()).map(([stage, { status, detail }]) => {
    // Only animate a row's entrance the first time we've ever seen this
    // stage, and only play the checkmark/X draw-in once per stage — not
    // on every 1s poll tick re-render, which would otherwise replay both
    // animations continuously for rows that finished long ago.
    const isNewRow = !state.seenStages.has(stage);
    const shouldDrawIcon = (status === "completed" || status === "failed") && !state.settledStages.has(stage);
    state.seenStages.add(stage);
    if (status === "completed" || status === "failed") state.settledStages.add(stage);

    let icon;
    if (status === "completed" || status === "failed") {
      icon = STAGE_ICONS[status](shouldDrawIcon);
    } else {
      icon = STAGE_ICONS[status] || "";
    }

    return `<div class="stage-row" style="${isNewRow ? "" : "animation:none;"}">
      <div class="stage-icon">${icon}</div>
      <div class="stage-name">${esc(stage)}</div>
      <div class="stage-meta">${esc(stageDetailText(status, detail))}</div>
    </div>`;
  }).join("");
  $("#stageLog").innerHTML = rows;
}

function startLivePolling() {
  state.seenStages = new Set();
  state.settledStages = new Set();
  $("#liveScanId").textContent = state.liveScanId;
  $("#liveStatusBadge").textContent = "RUNNING";
  $("#liveStatusBadge").className = "badge badge-MEDIUM";
  if (state.livePollHandle) clearInterval(state.livePollHandle);

  const poll = async () => {
    try {
      const data = await api(`/api/scan/${state.liveScanId}/status`);
      renderStageLog(data.log || []);
      if (data.status === "completed" || data.status === "cancelled" || data.status === "failed") {
        clearInterval(state.livePollHandle);
        state.livePollHandle = null;
        const badge = $("#liveStatusBadge");
        badge.textContent = data.status.toUpperCase();
        badge.className = "badge status-just-changed " +
          (data.status === "completed" ? "badge-LOW" : data.status === "failed" ? "badge-CRITICAL" : "badge-INFORMATIONAL");
        loadRecentScans();
      }
    } catch (e) {
      clearInterval(state.livePollHandle);
      state.livePollHandle = null;
      $("#stageLog").innerHTML += `<div class="text-muted" style="margin-top:8px;">Polling stopped: ${esc(e.message)}</div>`;
    }
  };
  poll();
  state.livePollHandle = setInterval(poll, 1000);
}

$("#cancelScanBtn").addEventListener("click", async () => {
  if (!state.liveScanId) return;
  try {
    await api(`/api/scan/${state.liveScanId}/cancel`, { method: "POST" });
  } catch (e) { /* scan may have already finished */ }
});

/* ---------------- Findings ---------------- */


function loadScanSelectorOptions() {
  const sel = $("#scanSelector");
  const current = sel.value;
  sel.innerHTML = `<option value="">Select a scan…</option>` + state.historyCache.map((r) =>
    `<option value="${esc(r.scan_id)}">${esc(r.scan_id)} — ${esc(r.target_path)} (${esc(r.started_at || "").slice(0, 16)})</option>`
  ).join("");
  if (current) sel.value = current;
}

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };
const SEVERITY_COLORS = { CRITICAL: "#ef4444", HIGH: "#f2994a", MEDIUM: "#eab308", LOW: "#22c55e", INFORMATIONAL: "#7c8aa5" };

function severityDonutSvg(findings, size = 130) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
  findings.forEach((f) => { if (f.severity in counts) counts[f.severity]++; });
  const total = findings.length;
  const cx = size / 2, cy = size / 2;
  const rOuter = size / 2 - 8, rInner = rOuter * 0.6, strokeW = rOuter - rInner;
  const rMid = (rOuter + rInner) / 2;
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

  if (total === 0) {
    return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
      <circle cx="${cx}" cy="${cy}" r="${rMid}" fill="none" stroke="#2f4166" stroke-width="${strokeW}" stroke-dasharray="4 6"/>
    </svg>`;
  }
  const circumference = 2 * Math.PI * rMid;
  let offset = 0;
  const segments = order.filter((s) => counts[s] > 0).map((sev) => {
    const frac = counts[sev] / total;
    const length = frac * circumference;
    const seg = `<circle cx="${cx}" cy="${cy}" r="${rMid}" fill="none" stroke="${SEVERITY_COLORS[sev]}"
      stroke-width="${strokeW}" stroke-dasharray="${length.toFixed(2)} ${circumference.toFixed(2)}"
      stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
    offset += length;
    return seg;
  }).join("");
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
    ${segments}
    <text x="${cx}" y="${cy - 1}" text-anchor="middle" font-size="19" font-weight="700" fill="var(--text-primary)">${total}</text>
    <text x="${cx}" y="${cy + 15}" text-anchor="middle" font-size="9.5" fill="var(--text-muted)">FINDINGS</text>
  </svg>`;
}

function severityLegendHtml(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
  findings.forEach((f) => { if (f.severity in counts) counts[f.severity]++; });
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  // margin-right (not just flex gap) on the label so spacing is correct
  // even in engines with partial/buggy flexbox-gap support.
  return `<div style="display:flex; flex-direction:column; gap:6px;">` +
    order.map((sev) => `<div style="display:flex; align-items:center; gap:8px; font-size:12.5px;">
      <span style="width:10px; height:10px; border-radius:2px; background:${SEVERITY_COLORS[sev]}; display:inline-block; margin-right:2px;"></span>
      <span class="text-muted" style="margin-right:8px;">${sev}</span><b>${counts[sev]}</b>
    </div>`).join("") + `</div>`;
}

let currentFindings = [];

async function selectScanForFindings(scanId) {
  const container = $("#findingsContainer");
  container.innerHTML = `<div class="empty-state">Loading findings…</div>`;
  try {
    currentFindings = await api(`/api/scan/${scanId}/findings`);
    $("#scanSelector").value = scanId;
    const chartEl = $("#findingsSummaryChart");
    chartEl.classList.remove("hidden");
    chartEl.classList.remove("chart-enter");
    void chartEl.offsetWidth; // force reflow so the entrance animation replays for a new scan
    chartEl.classList.add("chart-enter");
    chartEl.innerHTML = severityDonutSvg(currentFindings) +
      `<div>${severityLegendHtml(currentFindings)}</div>`;
    renderFindings();
  } catch (e) {
    container.innerHTML = `<div class="empty-state">Could not load findings: ${esc(e.message)}</div>`;
  }
}

$("#scanSelector").addEventListener("change", (e) => {
  if (e.target.value) selectScanForFindings(e.target.value);
});
$("#severityFilter").addEventListener("change", renderFindings);
$("#findingSearch").addEventListener("input", renderFindings);

function renderFindings() {
  const container = $("#findingsContainer");
  const sevFilter = $("#severityFilter").value;
  const q = $("#findingSearch").value.trim().toLowerCase();

  let filtered = currentFindings.filter((f) => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (q) {
      const hay = `${f.title} ${f.category} ${f.subcategory} ${f.location || ""} ${f.affected_component}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  filtered = filtered.slice().sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-state">No findings match the current filters.</div>`;
    return;
  }

  container.innerHTML = filtered.map((f, i) => `
    <div class="card finding-card" style="margin-bottom:10px; padding:0; --enter-delay:${Math.min(i * 25, 300)}ms;">
      <button type="button" class="stage-row clickable-finding" data-idx="${i}"
              style="padding:13px 16px; cursor:pointer; border-bottom:none; animation:none; width:100%; background:none; border-left:none; border-right:none; border-top:none; text-align:left; font-family:inherit; color:inherit;"
              aria-expanded="false" aria-controls="detail-${i}">
        <span class="badge badge-${esc(f.severity)}">${esc(f.severity)}</span>
        <div class="stage-name" style="margin-left:4px;">${esc(f.title)}</div>
        <div class="stage-meta mono">${esc(f.location || f.affected_component)}</div>
        <div class="stage-meta">risk ${f.risk_score != null ? f.risk_score : "—"} · conf ${f.confidence}%</div>
      </button>
      <div class="finding-detail" id="detail-${i}">
        <div class="meta-row">
          <span><b>Category</b> ${esc(f.category)} / ${esc(f.subcategory)}</span>
          <span><b>Validation</b> ${esc(f.validation_status)}</span>
          <span><b>Detected by</b> ${esc((f.detector_sources || []).join(", "))}</span>
        </div>
        ${(f.evidence || []).map((e) => `
          ${e.snippet ? `<div class="snippet">${esc(e.snippet)}</div>` : ""}
          ${e.raw_output ? `<div class="snippet">${esc(e.raw_output.slice(0, 500))}</div>` : ""}
        `).join("")}
        ${f.impact ? `<p><b>Impact:</b> ${esc(f.impact)}</p>` : ""}
        ${f.remediation ? `<p><b>Remediation:</b> ${esc(f.remediation)}</p>` : ""}
        ${f.reproduction ? `<p><b>Reproduction:</b> ${esc(f.reproduction)}</p>` : ""}
      </div>
    </div>`).join("");

  container.classList.remove("content-refresh");
  void container.offsetWidth; // force reflow so this replays on every filter change
  container.classList.add("content-refresh");

  $$(".clickable-finding", container).forEach((row) => {
    row.addEventListener("click", () => {
      const detail = $(`#detail-${row.dataset.idx}`);
      const nowExpanded = detail.classList.toggle("expanded");
      row.setAttribute("aria-expanded", String(nowExpanded));
    });
  });
}

/* ---------------- Reports ---------------- */

async function loadReportsList() {
  const container = $("#reportsContainer");
  try {
    const rows = await api("/api/history");
    state.historyCache = rows;
    if (!rows.length) {
      container.innerHTML = `<div class="empty-state">No scans yet.</div>`;
      return;
    }
    container.innerHTML = rows.map((r) => `
      <div class="card" style="margin-bottom:10px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
        <div>
          <div class="mono" style="font-size:13px;">${esc(r.scan_id)}</div>
          <div class="text-muted" style="font-size:12px;">${esc(r.target_path)} · ${esc(r.profile)} · ${esc((r.started_at || "").slice(0, 16))}</div>
        </div>
        <div style="display:flex; gap:8px;">
          <a class="btn btn-sm" href="/api/scan/${esc(r.scan_id)}/report?format=html" target="_blank">HTML</a>
          <a class="btn btn-sm" href="/api/scan/${esc(r.scan_id)}/report?format=json" target="_blank">JSON</a>
          <a class="btn btn-sm" href="/api/scan/${esc(r.scan_id)}/report?format=sarif" target="_blank">SARIF</a>
          <a class="btn btn-sm" href="/api/scan/${esc(r.scan_id)}/report?format=csv" target="_blank">CSV</a>
          <a class="btn btn-sm" href="/api/scan/${esc(r.scan_id)}/report?format=pdf" target="_blank">PDF</a>
        </div>
      </div>`).join("");
  } catch (e) {
    container.innerHTML = `<div class="empty-state">Could not load reports: ${esc(e.message)}</div>`;
  }
}

/* ---------------- Init ---------------- */

loadRecentScans();

// Deep-linking: #findings/<scan_id> opens Findings with that scan
// pre-selected — bookmarkable/shareable, and also how this UI is
// verified with a headless renderer during development.
(function handleInitialHash() {
  const m = /^#findings\/(.+)$/.exec(location.hash);
  if (m) {
    goto("findings");
    selectScanForFindings(decodeURIComponent(m[1]));
  }
})();
