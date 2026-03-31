/**
 * SOC Analyst Dashboard — Client-Side Logic
 * Real-time fetching, Chart.js, tabs, add-log, block-ip, clear-logs,
 * total-logs tracking, analytics section.
 */

// ── Globals ──
let chartTraffic = null, chartThreats = null, chartLogins = null, chartTrend = null;
let chartHistory = null, chartSeverity = null;
const REFRESH_MS = 5000;
Chart.defaults.color = "#7a7a9a";
Chart.defaults.borderColor = "rgba(0,229,255,0.04)";
Chart.defaults.font.family = "'Inter',sans-serif";
Chart.defaults.font.size = 11;

// ── Helpers ──
async function apiFetch(url) {
  try {
    const r = await fetch(url);
    if (r.redirected) { window.location.href = r.url; return null; }
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { console.error("API:", url, e); return null; }
}

function sevBadge(s) {
  const v = (s || "low").toLowerCase();
  return `<span class="sev-badge sev-${v}">${v}</span>`;
}

function animNum(id, tgt) {
  const el = document.getElementById(id);
  if (!el) return;
  const cur = parseInt(el.textContent) || 0;
  if (cur === tgt) return;
  const d = tgt - cur, steps = 14;
  let s = 0;
  (function t() {
    s++;
    if (s >= steps) { el.textContent = tgt; return; }
    el.textContent = Math.round(cur + (d / steps) * s);
    requestAnimationFrame(t);
  })();
}

function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  const icons = { success: "fa-check-circle", error: "fa-times-circle", info: "fa-info-circle" };
  t.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${msg}`;
  container.appendChild(t);
  setTimeout(() => { t.classList.add("toast-out"); setTimeout(() => t.remove(), 300); }, 3000);
}

// ── Tab Nav ──
const TITLES = {
  dashboard: "Dashboard Overview",
  analytics: "Log Analytics",
  logs: "Live Security Logs",
  alerts: "Security Alerts",
  incidents: "Active Incidents",
  search: "IP Address Search",
  block: "Block Attacker IP"
};

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    const tab = item.dataset.tab;
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    item.classList.add("active");
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    const el = document.getElementById("tab-" + tab);
    if (el) el.classList.add("active");
    document.getElementById("page-title").textContent = TITLES[tab] || "Dashboard";
    document.getElementById("sidebar").classList.remove("open");
    if (tab === "logs") fetchLogs();
    if (tab === "alerts") fetchAlerts();
    if (tab === "incidents") fetchIncidents();
    if (tab === "analytics") fetchAnalytics();
  });
});

document.getElementById("menu-toggle").addEventListener("click", () =>
  document.getElementById("sidebar").classList.toggle("open"));

// ── Clock ──
function updateClock() {
  const el = document.getElementById("topbar-time");
  if (el) el.textContent = new Date().toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  });
}
setInterval(updateClock, 1000);
updateClock();

// ── Chart gradient helper ──
function grad(ctx, r, g, b) {
  const gr = ctx.createLinearGradient(0, 0, 0, 240);
  gr.addColorStop(0, `rgba(${r},${g},${b},.3)`);
  gr.addColorStop(1, `rgba(${r},${g},${b},.01)`);
  return gr;
}

// ── Stats (Dashboard) ──
async function fetchStats() {
  const s = await apiFetch("/api/stats");
  if (!s) return;
  animNum("val-logs", s.total_logs);
  animNum("val-alerts", s.total_alerts);
  animNum("val-incidents", s.total_incidents);
  animNum("val-blocked", s.blocked_ips);
  updateTrafficChart(s.traffic);
  updateThreatsChart(s.threats);
  updateLoginsChart(s.login_attempts);
  updateTrendChart(s.trend);
  fetchDashAlerts();
  // Update severity bars on analytics if data available
  updateSeverityBars(s.severity);
}

// ── Total Logs (Lifetime tracking) ──
async function fetchTotalLogs() {
  const s = await apiFetch("/api/total-logs");
  if (!s) return;
  animNum("val-total-processed", s.total_logs);
  animNum("val-today-logs", s.today_logs);
  animNum("val-critical-alerts", s.critical_alerts);
  // Also update analytics tab values
  animNum("analytics-total", s.total_logs);
  animNum("analytics-today", s.today_logs);
  animNum("analytics-critical", s.critical_alerts);
  return s;
}

// ── Analytics ──
async function fetchAnalytics() {
  const [totalData, statsData] = await Promise.all([
    apiFetch("/api/total-logs"),
    apiFetch("/api/stats")
  ]);

  if (totalData) {
    animNum("analytics-total", totalData.total_logs);
    animNum("analytics-today", totalData.today_logs);
    animNum("analytics-critical", totalData.critical_alerts);
    updateHistoryChart(totalData.history || []);
  }

  if (statsData) {
    updateSeverityChart(statsData.severity);
    updateSeverityBars(statsData.severity);
    updateTopAttackers(statsData);
  }
}

function updateHistoryChart(history) {
  const el = document.getElementById("chart-history");
  if (!el) return;
  const labels = history.map(h => h.date);
  const data = history.map(h => h.count);

  if (chartHistory) {
    chartHistory.data.labels = labels;
    chartHistory.data.datasets[0].data = data;
    chartHistory.update("none");
    return;
  }

  chartHistory = new Chart(el, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Logs",
        data: data,
        backgroundColor: "rgba(168,85,247,.4)",
        borderColor: "#a855f7",
        borderWidth: 1,
        borderRadius: 4,
        barPercentage: .7
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 45, font: { size: 9 } } },
        y: { beginAtZero: true, grid: { color: "rgba(168,85,247,.04)" } }
      }
    }
  });
}

function updateSeverityChart(sev) {
  const el = document.getElementById("chart-severity");
  if (!el || !sev) return;
  const colors = ["#00e5ff", "#ffaa00", "#ff00c8", "#ff2d55"];

  if (chartSeverity) {
    chartSeverity.data.labels = sev.labels;
    chartSeverity.data.datasets[0].data = sev.data;
    chartSeverity.update("none");
    return;
  }

  chartSeverity = new Chart(el, {
    type: "doughnut",
    data: {
      labels: sev.labels,
      datasets: [{
        data: sev.data,
        backgroundColor: colors,
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { padding: 12, usePointStyle: true, pointStyleWidth: 8 }
        }
      },
      cutout: "62%"
    }
  });
}

function updateSeverityBars(sev) {
  if (!sev || !sev.labels || !sev.data) return;
  const total = sev.data.reduce((a, b) => a + b, 0) || 1;
  const map = {};
  sev.labels.forEach((l, i) => map[l] = sev.data[i]);

  ["critical", "high", "medium", "low"].forEach(level => {
    const count = map[level] || 0;
    const pct = Math.round((count / total) * 100);
    const bar = document.getElementById("bar-" + level);
    const num = document.getElementById("bar-" + level + "-n");
    if (bar) bar.style.width = pct + "%";
    if (num) num.textContent = count;
  });
}

async function updateTopAttackers() {
  const logs = await apiFetch("/api/logs");
  if (!logs) return;
  const ipCount = {};
  const ipLast = {};
  logs.forEach(l => {
    const ip = l.source_ip;
    ipCount[ip] = (ipCount[ip] || 0) + 1;
    ipLast[ip] = l.timestamp;
  });
  const sorted = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const tb = document.getElementById("top-attackers-body");
  if (!tb) return;
  tb.innerHTML = sorted.map((item, i) =>
    `<tr>
      <td>${i + 1}</td>
      <td>${item[0]}</td>
      <td><span class="sev-badge ${item[1] >= 5 ? 'sev-critical' : item[1] >= 3 ? 'sev-high' : 'sev-medium'}">${item[1]}</span></td>
      <td>${ipLast[item[0]] || ""}</td>
      <td><button class="action-btn btn-red btn-sm" onclick="blockIP('${item[0]}')"><i class="fas fa-ban"></i> Block</button></td>
    </tr>`
  ).join("");
}

// ── Dashboard Charts ──
function updateTrafficChart(d) {
  const el = document.getElementById("chart-traffic");
  if (!el) return;
  if (chartTraffic) {
    chartTraffic.data.labels = d.labels;
    chartTraffic.data.datasets[0].data = d.data;
    chartTraffic.update("none");
    return;
  }
  chartTraffic = new Chart(el, {
    type: "line",
    data: {
      labels: d.labels,
      datasets: [{
        label: "Events", data: d.data,
        borderColor: "#00e5ff",
        backgroundColor: grad(el.getContext("2d"), 0, 229, 255),
        fill: true, tension: .4, borderWidth: 2,
        pointRadius: 3, pointBackgroundColor: "#00e5ff",
        pointHoverRadius: 5
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: "rgba(0,229,255,.03)" } }
      }
    }
  });
}

function updateThreatsChart(d) {
  const el = document.getElementById("chart-threats");
  if (!el) return;
  const c = ["#00e5ff", "#ff00c8", "#00ff95", "#ffaa00", "#ff2d55", "#a855f7"];
  if (chartThreats) {
    chartThreats.data.labels = d.labels;
    chartThreats.data.datasets[0].data = d.data;
    chartThreats.data.datasets[0].backgroundColor = c.slice(0, d.labels.length);
    chartThreats.update("none");
    return;
  }
  chartThreats = new Chart(el, {
    type: "doughnut",
    data: {
      labels: d.labels,
      datasets: [{ data: d.data, backgroundColor: c.slice(0, d.labels.length), borderWidth: 0, hoverOffset: 6 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { padding: 12, usePointStyle: true, pointStyleWidth: 8 } } },
      cutout: "62%"
    }
  });
}

function updateLoginsChart(d) {
  const el = document.getElementById("chart-logins");
  if (!el) return;
  if (chartLogins) {
    chartLogins.data.labels = d.labels;
    chartLogins.data.datasets[0].data = d.data;
    chartLogins.update("none");
    return;
  }
  chartLogins = new Chart(el, {
    type: "bar",
    data: {
      labels: d.labels,
      datasets: [{
        label: "Attempts", data: d.data,
        backgroundColor: "rgba(255,0,200,.4)",
        borderColor: "#ff00c8", borderWidth: 1,
        borderRadius: 4, barPercentage: .6
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { maxRotation: 45, font: { size: 9 } } },
        y: { beginAtZero: true, grid: { color: "rgba(255,0,200,.03)" } }
      }
    }
  });
}

function updateTrendChart(d) {
  const el = document.getElementById("chart-trend");
  if (!el) return;
  if (chartTrend) {
    chartTrend.data.labels = d.labels;
    chartTrend.data.datasets[0].data = d.data;
    chartTrend.update("none");
    return;
  }
  chartTrend = new Chart(el, {
    type: "line",
    data: {
      labels: d.labels,
      datasets: [{
        label: "Incidents", data: d.data,
        borderColor: "#00ff95",
        backgroundColor: grad(el.getContext("2d"), 0, 255, 149),
        fill: true, tension: .4, borderWidth: 2,
        pointRadius: 4, pointBackgroundColor: "#00ff95",
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: "rgba(0,255,149,.03)" } }
      }
    }
  });
}

// ── Dashboard Alerts ──
async function fetchDashAlerts() {
  const a = await apiFetch("/api/alerts");
  if (!a) return;
  const tb = document.getElementById("dashboard-alerts-body");
  if (!tb) return;
  tb.innerHTML = a.slice(-8).reverse().map(a =>
    `<tr><td>${a.timestamp || ""}</td><td>${a.source_ip || ""}</td><td>${a.event_type || ""}</td><td>${sevBadge(a.severity)}</td><td style="white-space:normal;max-width:300px;font-family:'Inter',sans-serif;font-size:12px">${a.message || ""}</td></tr>`
  ).join("");
}

// ── Logs ──
async function fetchLogs() {
  const l = await apiFetch("/api/logs");
  if (!l) return;
  const tb = document.getElementById("logs-body");
  if (!tb) return;
  tb.innerHTML = l.slice(-80).reverse().map(l =>
    `<tr><td>${l.id}</td><td>${l.timestamp || ""}</td><td>${l.source_ip || ""}</td><td>${l.destination_ip || ""}</td><td>${l.event_type || ""}</td><td>${sevBadge(l.severity)}</td><td>${l.tool || ""}</td><td>${l.port || ""}</td><td>${l.status || ""}</td></tr>`
  ).join("");
}

// ── Alerts ──
async function fetchAlerts() {
  const a = await apiFetch("/api/alerts");
  if (!a) return;
  const tb = document.getElementById("alerts-body");
  if (!tb) return;
  tb.innerHTML = a.slice(-80).reverse().map(a =>
    `<tr><td>${a.id}</td><td>${a.timestamp || ""}</td><td>${a.source_ip || ""}</td><td>${a.event_type || ""}</td><td>${sevBadge(a.severity)}</td><td style="white-space:normal;max-width:280px;font-family:'Inter',sans-serif;font-size:12px">${a.message || ""}</td><td><button class="action-btn btn-red btn-sm" onclick="blockIP('${a.source_ip}')"><i class="fas fa-ban"></i> Block</button></td></tr>`
  ).join("");
}

// ── Incidents ──
async function fetchIncidents() {
  const inc = await apiFetch("/api/incidents");
  if (!inc) return;
  const tb = document.getElementById("incidents-body");
  if (!tb) return;
  tb.innerHTML = inc.map(i =>
    `<tr><td>${i.incident_id}</td><td>${i.source_ip}</td><td>${i.event_type}</td><td>${sevBadge(i.severity)}</td><td>${i.count}</td><td>${i.first_seen}</td><td>${i.last_seen}</td><td>${i.blocked ? '<span class="sev-badge sev-critical">BLOCKED</span>' : '<span class="sev-badge sev-low">ACTIVE</span>'}</td></tr>`
  ).join("");
}

// ── Search ──
document.getElementById("search-ip-btn").addEventListener("click", searchIP);
document.getElementById("search-ip-input").addEventListener("keydown", e => { if (e.key === "Enter") searchIP(); });

async function searchIP() {
  const ip = document.getElementById("search-ip-input").value.trim();
  if (!ip) { showToast("Please enter an IP address to search.", "error"); return; }
  const l = await apiFetch("/api/search?ip=" + encodeURIComponent(ip));
  if (!l) return;
  const tb = document.getElementById("search-body");
  if (!tb) return;
  if (!l.length) {
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:24px">No logs found for IP: ${ip}</td></tr>`;
    showToast(`No results for ${ip}`, "info");
    return;
  }
  tb.innerHTML = l.reverse().map(l =>
    `<tr><td>${l.id}</td><td>${l.timestamp || ""}</td><td>${l.source_ip || ""}</td><td>${l.destination_ip || ""}</td><td>${l.event_type || ""}</td><td>${sevBadge(l.severity)}</td><td style="white-space:normal;max-width:280px;font-family:'Inter',sans-serif;font-size:12px">${l.message || ""}</td></tr>`
  ).join("");
  showToast(`Found ${l.length} logs for ${ip}`, "success");
}

// ── Block IP ──
document.getElementById("block-ip-btn").addEventListener("click", () => {
  const ip = document.getElementById("block-ip-input").value.trim();
  if (ip) blockIP(ip);
});
document.getElementById("block-ip-input").addEventListener("keydown", e => {
  if (e.key === "Enter") {
    const ip = document.getElementById("block-ip-input").value.trim();
    if (ip) blockIP(ip);
  }
});

async function blockIP(ip) {
  try {
    const r = await fetch("/api/block-ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    const d = await r.json();
    const el = document.getElementById("block-result");
    if (d.success) {
      if (el) { el.className = "result-msg success"; el.innerHTML = `<i class="fas fa-check-circle"></i> ${d.message} (Total blocked: ${d.blocked.length})`; }
      showToast(`IP ${ip} blocked successfully`, "success");
      fetchStats();
    } else {
      if (el) { el.className = "result-msg error"; el.innerHTML = `<i class="fas fa-times-circle"></i> ${d.error || "Failed."}`; }
      showToast(d.error || "Failed to block IP", "error");
    }
  } catch (e) {
    console.error("Block:", e);
    showToast("Network error blocking IP", "error");
  }
}

// ── Add Log Modal ──
const modal = document.getElementById("modal-overlay");
document.getElementById("btn-add-log").addEventListener("click", () => modal.classList.add("open"));
document.getElementById("modal-close").addEventListener("click", () => modal.classList.remove("open"));
document.getElementById("modal-cancel").addEventListener("click", () => modal.classList.remove("open"));
modal.addEventListener("click", e => { if (e.target === modal) modal.classList.remove("open"); });

document.getElementById("add-log-form").addEventListener("submit", async e => {
  e.preventDefault();
  const p = {
    source_ip: document.getElementById("log-source-ip").value.trim(),
    destination_ip: document.getElementById("log-dest-ip").value.trim(),
    event_type: document.getElementById("log-event-type").value,
    severity: document.getElementById("log-severity").value,
    port: parseInt(document.getElementById("log-port").value) || 0,
    status: document.getElementById("log-status").value,
    message: document.getElementById("log-message").value.trim()
  };
  const res = document.getElementById("add-log-result");

  if (!p.source_ip) {
    if (res) { res.className = "result-msg error"; res.textContent = "Source IP is required."; }
    return;
  }
  if (!p.event_type) {
    if (res) { res.className = "result-msg error"; res.textContent = "Event type is required."; }
    return;
  }

  try {
    const r = await fetch("/api/add-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(p)
    });
    const d = await r.json();
    if (d.success) {
      if (res) {
        res.className = "result-msg success";
        res.innerHTML = `<i class="fas fa-check-circle"></i> Log #${d.log.id} added successfully.`;
      }
      showToast(`Log #${d.log.id} inserted`, "success");
      refreshAll();
      setTimeout(() => {
        document.getElementById("add-log-form").reset();
        if (res) { res.className = "result-msg"; res.textContent = ""; }
        modal.classList.remove("open");
      }, 1200);
    } else {
      if (res) { res.className = "result-msg error"; res.textContent = d.error || "Failed to add log."; }
      showToast(d.error || "Failed to add log", "error");
    }
  } catch (err) {
    if (res) { res.className = "result-msg error"; res.textContent = "Network error."; }
    showToast("Network error adding log", "error");
  }
});

// ── Clear Logs ──
const confirmModal = document.getElementById("confirm-overlay");
document.getElementById("btn-clear-logs").addEventListener("click", () => confirmModal.classList.add("open"));
document.getElementById("confirm-no").addEventListener("click", () => confirmModal.classList.remove("open"));
confirmModal.addEventListener("click", e => { if (e.target === confirmModal) confirmModal.classList.remove("open"); });
document.getElementById("confirm-yes").addEventListener("click", async () => {
  try {
    await fetch("/api/clear-logs", { method: "POST" });
    confirmModal.classList.remove("open");
    showToast("All logs cleared", "info");
    refreshAll();
  } catch (e) { console.error(e); }
});

// ── Load Logs Button ──
document.getElementById("btn-load-logs").addEventListener("click", () => {
  // Switch to logs tab
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const logsNav = document.querySelector('.nav-item[data-tab="logs"]');
  if (logsNav) logsNav.classList.add("active");
  document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
  const logsTab = document.getElementById("tab-logs");
  if (logsTab) logsTab.classList.add("active");
  document.getElementById("page-title").textContent = TITLES.logs;
  fetchLogs();
  showToast("Logs loaded", "info");
});

// ── Refresh ──
document.getElementById("btn-refresh").addEventListener("click", () => {
  refreshAll();
  showToast("Dashboard refreshed", "info");
});

function refreshAll() {
  fetchStats();
  fetchTotalLogs();
  const at = document.querySelector(".nav-item.active");
  if (at) {
    const t = at.dataset.tab;
    if (t === "logs") fetchLogs();
    if (t === "alerts") fetchAlerts();
    if (t === "incidents") fetchIncidents();
    if (t === "analytics") fetchAnalytics();
  }
}

// ── Initial Load & Auto-Refresh ──
fetchStats();
fetchTotalLogs();

setInterval(() => {
  fetchStats();
  fetchTotalLogs();
  const at = document.querySelector(".nav-item.active");
  if (at) {
    const t = at.dataset.tab;
    if (t === "logs") fetchLogs();
    if (t === "alerts") fetchAlerts();
    if (t === "incidents") fetchIncidents();
    if (t === "analytics") fetchAnalytics();
  }
}, REFRESH_MS);
