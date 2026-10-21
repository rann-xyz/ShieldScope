/*
 * ShieldScope frontend script
 * Vanilla JS — no external dependencies.
 * Respects fail-closed: without API key all scans return BLOCKED.
 */

"use strict";

// ---- State ----
let apiConfigured = false;

// ---- Init on load ----
document.addEventListener("DOMContentLoaded", () => {
  initNavToggle();
  initYear();
  initFooterYear();
  checkApiConfig();
  initForms();
  showInitialNotice();
});

// ---- Mobile nav toggle ----
function initNavToggle() {
  const toggle = document.getElementById("nav-toggle");
  const menu = document.getElementById("nav-menu");
  if (!toggle || !menu) return;
  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!expanded));
    menu.classList.toggle("open");
  });
  // Close on link click
  menu.querySelectorAll("a").forEach((a) => {
    a.addEventListener("click", () => {
      menu.classList.remove("open");
      toggle.setAttribute("aria-expanded", "false");
    });
  });
}

// ---- Years ----
function initYear() {
  const y = document.getElementById("year");
  if (y) y.textContent = String(new Date().getFullYear());
}
function initFooterYear() {
  const spans = document.querySelectorAll("#year");
  spans.forEach((el) => {
    if (el && !el.textContent || (el && el.textContent === "")) {
      el.textContent = String(new Date().getFullYear());
    }
  });
}

// ---- API config check ----
async function checkApiConfig() {
  const banner = document.getElementById("api-status");
  const text = document.getElementById("status-text");
  try {
    const resp = await fetch("/api/config");
    if (!resp.ok) throw new Error(resp.statusText);
    const cfg = await resp.json();
    apiConfigured = cfg.apiConfigured;
    updateApiStatus(cfg.apiConfigured, text, banner);
  } catch (err) {
    apiConfigured = false;
    if (text) text.textContent = "⚠️ API config unavailable — scans will return BLOCKED.";
    if (banner) banner.className = "status-banner";
  }
}

function updateApiStatus(online, textEl, bannerEl) {
  if (textEl) {
    textEl.textContent = online
      ? "✅ API key configured — live scanning enabled"
      : "⚠️ API key not configured — scans will return BLOCKED (no fake results).";
  }
  if (bannerEl) {
    bannerEl.className = online ? "status-banner ready" : "status-banner";
  }
}

// ---- Demo notice on load ----
function showInitialNotice() {
  const banner = document.querySelector(".demo-banner");
  const results = document.getElementById("results-section");
  if (banner) {
    banner.innerHTML = "⚠️ <strong>Demo Prototype</strong> — ShieldScope MVP. Results require valid API key. <a href=\"#about\" style=\"color:#78350f; text-decoration:underline;\">Learn how it works</a>";
  }
  // Hide results initially
  if (results) results.hidden = true;
}

// ---- Form handlers ----
function initForms() {
  bindForm("wallet-form", "/api/scan/wallet");
  bindForm("contract-form", "/api/scan/contract");
  bindForm("url-form", "/api/scan/url");
}

function bindForm(formId, endpoint) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    const resultsContainer = document.getElementById("results-container");
    const resultsSection = document.getElementById("results-section");

    if (!resultsContainer || !resultsSection) return;

    resultsContainer.innerHTML = '<p class="loading">Sedang memindai...</p>';
    resultsSection.hidden = false;

    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      resultsContainer.innerHTML = renderReport(data);
    } catch (err) {
      const errorText = err.message ? escapeHtml(err.message.toString()) : "Unknown error";
      resultsContainer.innerHTML =
        '<p class="error">❌ Gagal memindai: ' + errorText + "</p>";
    }
  });
}

// ---- Render report ----
function renderReport(data) {
  const level = (data.risk_level || "BLOCKED").toUpperCase();
  const score = data.risk_score;
  const badgeClass = `badge-${level.toLowerCase()}`;
  const scoreText = score !== null && score !== undefined
    ? `<div class="report-score">${score}/100</div>`
    : `<div class="report-score">N/A</div>`;

  const issuesHtml = (data.issues || []).length
    ? `<ul class="report-list">${data.issues.map((i) =>
        `<li><strong>${escapeHtml(i.title || "Issue")}</strong> — ${escapeHtml(i.severity || "")}</li>`).join("")}</ul>`
    : `<p style="color:#94a3b8;">Tidak ada masalah ditemukan.</p>`;

  const evidenceHtml = (data.evidence || []).length
    ? `<ul class="report-list">${data.evidence.map((e) =>
        `<li>${escapeHtml(e)}</li>`).join("")}</ul>`
    : `<p style="color:#94a3b8;">Tidak ada bukti tambahan.</p>`;

  const blockedNote = level === "BLOCKED"
    ? `<p style="color:#7f1d1d; font-weight:600; margin-top:0.5rem;">
        ℹ️ API key belum dikonfigurasi atau permintaan gagal.
        Atur WEBACITY_API_KEY di server untuk hasil langsung.
       </p>`
    : "";

  return `
    <div class="report-card">
      <div class="report-header">
        <div>
          <div class="report-target">${escapeHtml(data.target)}</div>
          <div class="report-summary">${escapeHtml(data.summary)}</div>
        </div>
        <div style="display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap;">
          ${scoreText}
          <span class="report-badge ${badgeClass}">${level}</span>
        </div>
      </div>
      ${issuesHtml}
      <p style="margin:0.5rem 0 0.25rem; font-size:0.85rem; color:#64748b;">Evidence:</p>
      ${evidenceHtml}
      ${blockedNote}
    </div>
  `;
}

// ---- Escape helper ----
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
