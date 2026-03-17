const state = {
  loggedIn: false,
  csrf: "",
  username: "",
  theme: "dark",
  mode: "cells",
  filter: "all",
  refreshSeconds: 4,
  system: null,
  cells: [],
  storage: [],
  backups: [],
  selectedCellName: "",
  selectedStorage: 0,
  selectedBackup: 0,
  lastStatus: "Ready.",
  statusLines: ["Ready."],
  statusOpen: false,
  cpuUserSeries: [],
  cpuSystemSeries: [],
  memoryUsedSeries: [],
  lastCPUTicks: null,
  actionModalDepth: 0,
  confirmResolver: null,
  confirmRestoreFocus: null,
  pollTimer: null,
};

const els = {
  loginCard: document.getElementById("loginCard"),
  app: document.getElementById("app"),
  loginForm: document.getElementById("loginForm"),
  loginStatus: document.getElementById("loginStatus"),
  sessionInfo: document.getElementById("sessionInfo"),
  modeSystem: document.getElementById("modeSystem"),
  modeCells: document.getElementById("modeCells"),
  modeStorage: document.getElementById("modeStorage"),
  cellFilterGroup: document.getElementById("cellFilterGroup"),
  refreshBtn: document.getElementById("refreshBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  metaPanel: document.getElementById("metaPanel"),
  systemView: document.getElementById("systemView"),
  cellsView: document.getElementById("cellsView"),
  storageView: document.getElementById("storageView"),
  systemSummary: document.getElementById("systemSummary"),
  cpuTrendUserPath: document.getElementById("cpuTrendUserPath"),
  cpuTrendSystemPath: document.getElementById("cpuTrendSystemPath"),
  cpuTrendLegend: document.getElementById("cpuTrendLegend"),
  memoryTrendAreaPath: document.getElementById("memoryTrendAreaPath"),
  memoryTrendLinePath: document.getElementById("memoryTrendLinePath"),
  memoryTrendLegend: document.getElementById("memoryTrendLegend"),
  fsBody: document.getElementById("fsBody"),
  ifaceBody: document.getElementById("ifaceBody"),
  ioHead: document.getElementById("ioHead"),
  ioBody: document.getElementById("ioBody"),
  cellsBody: document.getElementById("cellsBody"),
  storageBody: document.getElementById("storageBody"),
  backupsBody: document.getElementById("backupsBody"),
  cellDetails: document.getElementById("cellDetails"),
  storageDetails: document.getElementById("storageDetails"),
  statusPane: document.querySelector(".status-pane"),
  statusBox: document.getElementById("statusBox"),
  statusToggleBtn: document.getElementById("statusToggleBtn"),
  actionModal: document.getElementById("actionModal"),
  actionModalText: document.getElementById("actionModalText"),
  confirmModal: document.getElementById("confirmModal"),
  confirmModalTitle: document.getElementById("confirmModalTitle"),
  confirmModalMessage: document.getElementById("confirmModalMessage"),
  confirmModalMeta: document.getElementById("confirmModalMeta"),
  confirmModalCancelBtn: document.getElementById("confirmModalCancelBtn"),
  confirmModalConfirmBtn: document.getElementById("confirmModalConfirmBtn"),
  startBtn: document.getElementById("startBtn"),
  stopBtn: document.getElementById("stopBtn"),
  restartBtn: document.getElementById("restartBtn"),
  startAllBtn: document.getElementById("startAllBtn"),
  stopAllBtn: document.getElementById("stopAllBtn"),
  restartAllBtn: document.getElementById("restartAllBtn"),
  applyAllBtn: document.getElementById("applyAllBtn"),
  backupCreateBtn: document.getElementById("backupCreateBtn"),
  backupRestoreBtn: document.getElementById("backupRestoreBtn"),
  backupRestoreManifestBtn: document.getElementById("backupRestoreManifestBtn"),
  backupDeleteBtn: document.getElementById("backupDeleteBtn"),
  themeToggles: Array.from(document.querySelectorAll("[data-theme-toggle]")),
};

const themeStorageKey = "cellweb.theme";
const statusPanelStorageKey = "cellweb.status.open";
const chartHistorySize = 72;
const supportedThemes = ["dark", "light", "retro"];

function normalizeTheme(theme) {
  return supportedThemes.includes(theme) ? theme : "dark";
}

function nextTheme(theme) {
  const active = normalizeTheme(theme);
  const idx = supportedThemes.indexOf(active);
  return supportedThemes[(idx + 1) % supportedThemes.length];
}

function themeToggleConfig(theme) {
  if (theme === "light") {
    return { label: "Light mode", iconRef: "#i-sun" };
  }
  if (theme === "retro") {
    return { label: "Retro mode", iconRef: "#i-retro" };
  }
  return { label: "Dark mode", iconRef: "#i-moon" };
}

function ensureSystemTrendElements() {
  const hasAllTrendEls = Boolean(
    els.cpuTrendUserPath
    && els.cpuTrendSystemPath
    && els.cpuTrendLegend
    && els.memoryTrendAreaPath
    && els.memoryTrendLinePath
    && els.memoryTrendLegend,
  );
  if (hasAllTrendEls) {
    return;
  }

  const summary = document.getElementById("systemSummary");
  if (!summary) {
    return;
  }

  let trendGrid = document.getElementById("systemTrendGrid");
  if (!trendGrid) {
    trendGrid = document.createElement("div");
    trendGrid.id = "systemTrendGrid";
    trendGrid.className = "trend-grid";
    trendGrid.setAttribute("aria-label", "System trends");
    trendGrid.innerHTML = `<section class="trend-card" aria-live="polite">
      <div class="trend-head">
        <div class="trend-title">CPU user/system</div>
        <div id="cpuTrendLegend" class="trend-legend">Waiting for samples ...</div>
      </div>
      <div class="trend-canvas">
        <svg class="trend-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <path id="cpuTrendUserPath" class="trend-line trend-line-user" d=""></path>
          <path id="cpuTrendSystemPath" class="trend-line trend-line-system" d=""></path>
        </svg>
      </div>
    </section>
    <section class="trend-card" aria-live="polite">
      <div class="trend-head">
        <div class="trend-title">Memory used</div>
        <div id="memoryTrendLegend" class="trend-legend">Waiting for samples ...</div>
      </div>
      <div class="trend-canvas">
        <svg class="trend-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <path id="memoryTrendAreaPath" class="trend-area" d=""></path>
          <path id="memoryTrendLinePath" class="trend-line trend-line-memory" d=""></path>
        </svg>
      </div>
    </section>`;
    summary.insertAdjacentElement("afterend", trendGrid);
  }

  els.cpuTrendUserPath = document.getElementById("cpuTrendUserPath");
  els.cpuTrendSystemPath = document.getElementById("cpuTrendSystemPath");
  els.cpuTrendLegend = document.getElementById("cpuTrendLegend");
  els.memoryTrendAreaPath = document.getElementById("memoryTrendAreaPath");
  els.memoryTrendLinePath = document.getElementById("memoryTrendLinePath");
  els.memoryTrendLegend = document.getElementById("memoryTrendLegend");
}

function setStatus(text, level = "") {
  const ts = new Date().toLocaleTimeString();
  const prefix = level ? `[${level.toUpperCase()}] ` : "";
  const line = `${ts} ${prefix}${text}`;
  state.lastStatus = line;
  state.statusLines.push(line);
  if (state.statusLines.length > 80) {
    state.statusLines.shift();
  }
  els.statusBox.textContent = state.statusLines.join("\n");
  els.statusBox.scrollTop = els.statusBox.scrollHeight;
}

function setLoginStatus(text, level = "") {
  els.loginStatus.textContent = text;
  els.loginStatus.className = "status";
  if (level) {
    els.loginStatus.classList.add(level);
  }
}

function showActionModal(text) {
  if (!els.actionModal) return;
  state.actionModalDepth += 1;
  if (text && els.actionModalText) {
    els.actionModalText.textContent = text;
  }
  els.actionModal.classList.add("open");
  els.actionModal.setAttribute("aria-hidden", "false");
}

function hideActionModal() {
  if (!els.actionModal) return;
  state.actionModalDepth = Math.max(0, state.actionModalDepth - 1);
  if (state.actionModalDepth > 0) return;
  els.actionModal.classList.remove("open");
  els.actionModal.setAttribute("aria-hidden", "true");
}

async function withActionModal(text, fn) {
  showActionModal(text || "Action in progress ...");
  try {
    return await fn();
  } finally {
    hideActionModal();
  }
}

function isConfirmModalOpen() {
  return Boolean(els.confirmModal && els.confirmModal.classList.contains("open"));
}

function closeConfirmModal(answer) {
  if (!isConfirmModalOpen() || !els.confirmModal) return;

  els.confirmModal.classList.remove("open");
  els.confirmModal.setAttribute("aria-hidden", "true");

  if (state.confirmRestoreFocus && typeof state.confirmRestoreFocus.focus === "function") {
    state.confirmRestoreFocus.focus();
  }
  state.confirmRestoreFocus = null;

  const resolve = state.confirmResolver;
  state.confirmResolver = null;
  if (resolve) {
    resolve(Boolean(answer));
  }
}

async function confirmAction(options = {}) {
  const title = options.title || "Confirm action";
  const message = options.message || "Are you sure?";
  const detail = options.detail || "";
  const confirmLabel = options.confirmLabel || "Confirm";
  const danger = options.danger !== false;

  if (
    !els.confirmModal
    || !els.confirmModalTitle
    || !els.confirmModalMessage
    || !els.confirmModalMeta
    || !els.confirmModalCancelBtn
    || !els.confirmModalConfirmBtn
  ) {
    const fallbackText = [title, message, detail].filter(Boolean).join("\n");
    return confirm(fallbackText);
  }

  if (state.confirmResolver) {
    closeConfirmModal(false);
  }

  els.confirmModalTitle.textContent = title;
  els.confirmModalMessage.textContent = message;
  els.confirmModalMeta.textContent = detail;
  els.confirmModalMeta.classList.toggle("hidden", !detail);
  els.confirmModalConfirmBtn.textContent = confirmLabel;
  els.confirmModalConfirmBtn.classList.toggle("danger", danger);

  state.confirmRestoreFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  els.confirmModal.classList.add("open");
  els.confirmModal.setAttribute("aria-hidden", "false");
  els.confirmModalCancelBtn.focus();

  return new Promise((resolve) => {
    state.confirmResolver = resolve;
  });
}

async function api(path, options = {}) {
  const init = {
    method: options.method || "GET",
    headers: {
      "Accept": "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(state.csrf && initMethodNeedsCSRF(options.method || "GET")
        ? { "X-CSRF-Token": state.csrf }
        : {}),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  };

  const res = await fetch(path, init);
  const payload = await res.json().catch(() => ({}));

  if (!res.ok || payload.ok === false) {
    const err = new Error(payload.error || `HTTP ${res.status}`);
    err.details = payload.details || "";
    err.status = res.status;
    throw err;
  }

  return payload;
}

function initMethodNeedsCSRF(method) {
  const m = method.toUpperCase();
  return m !== "GET" && m !== "HEAD" && m !== "OPTIONS";
}

function showApp(loggedIn) {
  state.loggedIn = loggedIn;
  els.loginCard.hidden = loggedIn;
  els.app.hidden = !loggedIn;
  els.loginCard.classList.toggle("hidden", loggedIn);
  els.app.classList.toggle("hidden", !loggedIn);
  if (els.statusPane) {
    els.statusPane.hidden = !loggedIn;
  }
  if (els.statusToggleBtn) {
    els.statusToggleBtn.hidden = !loggedIn;
  }
  if (!loggedIn) {
    state.lastCPUTicks = null;
  }
  applyStatusPanel(state.statusOpen, false);
}

function detectInitialStatusPanel() {
  try {
    return localStorage.getItem(statusPanelStorageKey) === "1";
  } catch {
    return false;
  }
}

function applyStatusPanel(open, persist = false) {
  state.statusOpen = Boolean(open);
  const active = state.loggedIn && state.statusOpen;

  if (els.statusPane) {
    els.statusPane.classList.toggle("open", active);
  }
  els.app.classList.toggle("status-open", active);

  const label = active ? "Hide console" : "Show console";
  if (els.statusToggleBtn) {
    els.statusToggleBtn.classList.toggle("active", active);
    els.statusToggleBtn.setAttribute("aria-pressed", active ? "true" : "false");
    els.statusToggleBtn.setAttribute("aria-label", label);
    els.statusToggleBtn.title = label;
  }

  if (active) {
    els.statusBox.scrollTop = els.statusBox.scrollHeight;
  }

  if (persist) {
    try {
      localStorage.setItem(statusPanelStorageKey, state.statusOpen ? "1" : "0");
    } catch {
      // ignore localStorage access errors
    }
  }
}

function toggleStatusPanel() {
  applyStatusPanel(!state.statusOpen, true);
}

function detectInitialTheme() {
  try {
    const stored = localStorage.getItem(themeStorageKey);
    if (supportedThemes.includes(stored)) {
      return stored;
    }
  } catch {
    // ignore localStorage access errors
  }
  if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    return "light";
  }
  return "dark";
}

function applyTheme(theme, persist = false) {
  state.theme = normalizeTheme(theme);
  document.documentElement.setAttribute("data-theme", state.theme);

  const targetTheme = nextTheme(state.theme);
  const target = themeToggleConfig(targetTheme);

  els.themeToggles.forEach((btn) => {
    const labelEl = btn.querySelector(".theme-toggle-label");
    if (labelEl) {
      labelEl.textContent = target.label;
    }
    const iconUse = btn.querySelector("svg use");
    if (iconUse) {
      iconUse.setAttribute("href", target.iconRef);
    }
    btn.setAttribute("aria-label", `Enable ${target.label.toLowerCase()}`);
    btn.title = `Enable ${target.label.toLowerCase()}`;
  });

  if (persist) {
    try {
      localStorage.setItem(themeStorageKey, state.theme);
    } catch {
      // ignore localStorage access errors
    }
  }
}

function toggleTheme() {
  applyTheme(nextTheme(state.theme), true);
}

function selectedCell() {
  if (state.selectedCellName) {
    const found = state.cells.find((row) => row.name === state.selectedCellName);
    if (found) {
      return found;
    }
  }
  return state.cells[0] || null;
}

function selectedStorage() {
  return state.storage[state.selectedStorage] || null;
}

function selectedBackup() {
  return state.backups[state.selectedBackup] || null;
}

function clampPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

function pushTrendPoint(series, value) {
  if (value === null) return;
  series.push(value);
  if (series.length > chartHistorySize) {
    series.shift();
  }
}

function normalizeTrendSeries(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return values
    .map((v) => clampPercent(v))
    .filter((v) => v !== null)
    .slice(-chartHistorySize);
}

function parseCPUTicks(raw) {
  if (!raw || typeof raw !== "object") {
    return null;
  }

  const user = Number(raw.user);
  const nice = Number(raw.nice);
  const system = Number(raw.system);
  const intr = Number(raw.intr);
  const idle = Number(raw.idle);

  if (![user, nice, system, intr, idle].every((v) => Number.isFinite(v) && v >= 0)) {
    return null;
  }

  return { user, nice, system, intr, idle };
}

function buildTrendPoints(series) {
  const values = series.slice(-chartHistorySize);
  if (values.length === 0) {
    return [];
  }

  const startSlot = chartHistorySize - values.length;
  const denom = Math.max(1, chartHistorySize - 1);
  return values.map((value, idx) => {
    const slot = startSlot + idx;
    const x = (slot / denom) * 100;
    const y = 100 - ((clampPercent(value) || 0) / 100) * 100;
    return { x, y };
  });
}

function buildTrendLinePath(points) {
  if (!points.length) return "";
  return points.map((p, idx) => `${idx === 0 ? "M" : "L"} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(" ");
}

function buildTrendAreaPath(points) {
  if (!points.length) return "";
  const line = buildTrendLinePath(points);
  const first = points[0];
  const last = points[points.length - 1];
  return `${line} L ${last.x.toFixed(2)} 100 L ${first.x.toFixed(2)} 100 Z`;
}

function formatPercentCompact(value) {
  const n = clampPercent(value);
  if (n === null) return "-";
  return `${n.toFixed(1)}%`;
}

function renderSystemTrends() {
  ensureSystemTrendElements();

  const cpuUserPoints = buildTrendPoints(state.cpuUserSeries);
  const cpuSystemPoints = buildTrendPoints(state.cpuSystemSeries);
  const memoryPoints = buildTrendPoints(state.memoryUsedSeries);

  if (els.cpuTrendUserPath) {
    els.cpuTrendUserPath.setAttribute("d", buildTrendLinePath(cpuUserPoints));
  }
  if (els.cpuTrendSystemPath) {
    els.cpuTrendSystemPath.setAttribute("d", buildTrendLinePath(cpuSystemPoints));
  }
  if (els.memoryTrendAreaPath) {
    els.memoryTrendAreaPath.setAttribute("d", buildTrendAreaPath(memoryPoints));
  }
  if (els.memoryTrendLinePath) {
    els.memoryTrendLinePath.setAttribute("d", buildTrendLinePath(memoryPoints));
  }

  const latestCPUUser = state.cpuUserSeries.length ? state.cpuUserSeries[state.cpuUserSeries.length - 1] : null;
  const latestCPUSystem = state.cpuSystemSeries.length ? state.cpuSystemSeries[state.cpuSystemSeries.length - 1] : null;
  if (els.cpuTrendLegend) {
    if (latestCPUUser === null || latestCPUSystem === null) {
      els.cpuTrendLegend.textContent = "Waiting for samples ...";
    } else {
      els.cpuTrendLegend.textContent = `U ${formatPercentCompact(latestCPUUser)} | S ${formatPercentCompact(latestCPUSystem)}`;
    }
  }

  const latestMem = state.memoryUsedSeries.length ? state.memoryUsedSeries[state.memoryUsedSeries.length - 1] : null;
  if (els.memoryTrendLegend) {
    els.memoryTrendLegend.textContent = latestMem === null
      ? "Waiting for samples ..."
      : `Used ${formatPercentCompact(latestMem)}`;
  }
}

function updateSystemTrends(snapshot) {
  if (!snapshot || typeof snapshot !== "object") {
    return;
  }

  if (snapshot.trends && typeof snapshot.trends === "object") {
    if (state.cpuUserSeries.length === 0) {
      state.cpuUserSeries = normalizeTrendSeries(snapshot.trends.cpu_user_percent);
    }
    if (state.cpuSystemSeries.length === 0) {
      state.cpuSystemSeries = normalizeTrendSeries(snapshot.trends.cpu_system_percent);
    }
    if (state.memoryUsedSeries.length === 0) {
      state.memoryUsedSeries = normalizeTrendSeries(snapshot.trends.memory_used_percent);
    }
  }

  const memUsed = clampPercent(snapshot.memory && snapshot.memory.used_percent);
  pushTrendPoint(state.memoryUsedSeries, memUsed);

  const ticks = parseCPUTicks(snapshot.cpu_ticks);
  if (ticks) {
    if (state.lastCPUTicks) {
      const dUser = Math.max(0, ticks.user - state.lastCPUTicks.user);
      const dNice = Math.max(0, ticks.nice - state.lastCPUTicks.nice);
      const dSystem = Math.max(0, ticks.system - state.lastCPUTicks.system);
      const dIntr = Math.max(0, ticks.intr - state.lastCPUTicks.intr);
      const dIdle = Math.max(0, ticks.idle - state.lastCPUTicks.idle);
      const total = dUser + dNice + dSystem + dIntr + dIdle;

      if (total > 0) {
        pushTrendPoint(state.cpuUserSeries, ((dUser + dNice) * 100) / total);
        pushTrendPoint(state.cpuSystemSeries, ((dSystem + dIntr) * 100) / total);
      }
    }
    state.lastCPUTicks = ticks;
  }

  renderSystemTrends();
}

function applyModeUI() {
  const isSystem = state.mode === "system";
  const isCells = state.mode === "cells";
  const isStorage = state.mode === "storage";

  els.modeSystem.classList.toggle("active", isSystem);
  els.modeCells.classList.toggle("active", isCells);
  els.modeStorage.classList.toggle("active", isStorage);

  els.systemView.classList.toggle("hidden", !isSystem);
  els.cellsView.classList.toggle("hidden", !isCells);
  els.storageView.classList.toggle("hidden", !isStorage);
  els.cellFilterGroup.classList.toggle("hidden", !isCells);
}

function renderMetrics(meta) {
  const blocks = [];
  if (state.mode === "system") {
    blocks.push(metric("FFS", meta.filesystems || 0));
    blocks.push(metric("IF", meta.interfaces || 0));
    blocks.push(metric("I/O", meta.io_devices || 0));
    blocks.push(metric("Warn", meta.warnings || 0));
  } else if (state.mode === "cells") {
    blocks.push(metric("Cells", meta.total || 0));
    blocks.push(metric("Running", meta.running || 0));
    blocks.push(metric("Orphans", meta.missing_manifest || 0));
    blocks.push(metric("Filter", state.filter));
  } else {
    blocks.push(metric("Targets", meta.total || 0));
    blocks.push(metric("Volumes", meta.volumes || 0));
    blocks.push(metric("Overlays", meta.overlays || 0));
    blocks.push(metric("Ready", meta.backup_ready || 0));
  }
  els.metaPanel.innerHTML = blocks.join("");
}

function metric(label, value) {
  return `<div class="metric"><span class="label">${escapeHtml(label)}</span><span class="value">${escapeHtml(String(value))}</span></div>`;
}

function renderCells() {
  const filtered = state.cells.filter((row) => {
    if (state.filter === "running") return row.running;
    if (state.filter === "stopped") return !row.running;
    return true;
  });

  if (!state.selectedCellName && filtered.length > 0) {
    state.selectedCellName = filtered[0].name;
  }
  if (state.selectedCellName && !filtered.some((row) => row.name === state.selectedCellName)) {
    state.selectedCellName = filtered.length > 0 ? filtered[0].name : "";
  }

  els.cellsBody.innerHTML = filtered.map((row, idx) => {
    const rowClass = row.name === state.selectedCellName ? "selected" : "";
    const stateClass = row.running ? "state-running" : "state-stopped";
    const name = row.manifest_present ? row.name : `!${row.name}`;
    return `<tr class="${rowClass}" data-row="${idx}">
      <td>${escapeHtml(name)}</td>
      <td class="${stateClass}">${row.running ? "running" : "stopped"}</td>
      <td>${escapeHtml(row.cid || "-")}</td>
      <td>${escapeHtml(row.cpu10s || "-")}</td>
      <td>${escapeHtml(humanAge(row.age))}</td>
    </tr>`;
  }).join("");

  els.cellsBody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => {
      const idx = Number(tr.dataset.row);
      const picked = filtered[idx];
      state.selectedCellName = picked ? picked.name : "";
      renderCells();
    });
  });

  const row = state.selectedCellName ? filtered.find((c) => c.name === state.selectedCellName) || null : null;
  renderCellDetails(row);
}

function renderCellDetails(row) {
  if (!row) {
    els.cellDetails.innerHTML = detail("Info", "No cell selected.", "span-3");
    setCellActionButtons(false);
    return;
  }

  els.cellDetails.innerHTML = [
    detail("Name", row.name),
    detail("State", row.running ? "running" : "stopped"),
    detail("CID", row.cid || "-"),
    detail("Procs", row.procs || "0"),
    detail("Refs", row.refs || "-"),
    detail("Age", humanAge(row.age)),
    detail("CPU 1s", row.cpu1s || "-"),
    detail("CPU 10s", row.cpu10s || "-"),
    detail("Memory", formatMaybeBytes(row.memory)),
    detail("Manifest", row.manifest_present ? "present" : "missing (ORPHAN)"),
    detail("Profile", row.create_profile || "-"),
    detail("Reserved Ports", row.create_reserved_ports || "-"),
    detail("Rlimit nofile", row.create_rlimit_nofile || "-"),
    detail("Rlimit as", formatMaybeBytes(row.create_rlimit_as)),
    detail("Rlimit core", row.create_rlimit_core || "-"),
    detail("Autostart", row.autostart || "NO"),
    detail("Root", row.root || "-", "span-2"),
    detail("Supervise Cmd", row.supervise_cmd || "-", "span-3"),
  ].join("");

  setCellActionButtons(true, row);
}

function setCellActionButtons(enabled, row = null) {
  [els.startBtn, els.stopBtn, els.restartBtn].forEach((btn) => {
    btn.disabled = !enabled;
  });
  if (!enabled || !row) {
    return;
  }
  els.startBtn.disabled = row.running;
  els.stopBtn.disabled = !row.running;
}

function renderStorage() {
  if (state.selectedStorage >= state.storage.length) {
    state.selectedStorage = Math.max(0, state.storage.length - 1);
  }

  els.storageBody.innerHTML = state.storage.map((row, idx) => {
    const selected = idx === state.selectedStorage ? "selected" : "";
    const runtime = row.runtime_present ? "yes" : "no";
    const mountedClass = row.mounted ? "state-warn" : "";
    return `<tr class="${selected}" data-row="${idx}">
      <td>${escapeHtml(row.kind)}</td>
      <td>${escapeHtml(row.name)}</td>
      <td>${escapeHtml(runtime)}</td>
      <td class="${mountedClass}">${row.mounted ? "yes" : "no"}</td>
      <td>${escapeHtml(row.refs || "-")}</td>
      <td>${escapeHtml(row.mode || "-")}</td>
    </tr>`;
  }).join("");

  els.storageBody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", async () => {
      state.selectedStorage = Number(tr.dataset.row);
      state.selectedBackup = 0;
      renderStorage();
      await refreshBackups();
    });
  });

  renderStorageDetails(selectedStorage());
}

function renderStorageDetails(row) {
  if (!row) {
    els.storageDetails.innerHTML = "<div class='detail-item'><div class='k'>Info</div><div class='v'>No storage target selected.</div></div>";
    setStorageActionButtons(false);
    return;
  }

  els.storageDetails.innerHTML = [
    detail("Kind", row.kind),
    detail("Name", row.name),
    detail("Runtime", row.runtime_present ? "present" : "missing"),
    detail("Mounted", row.mounted ? "yes" : "no"),
    detail("Path", row.path || "-"),
    detail("Used By", row.used_by || "-"),
  ].join("");

  setStorageActionButtons(true, row);
}

function setStorageActionButtons(enabled, row = null) {
  [
    els.backupCreateBtn,
    els.backupRestoreBtn,
    els.backupRestoreManifestBtn,
    els.backupDeleteBtn,
  ].forEach((btn) => {
    btn.disabled = !enabled;
  });

  if (!enabled || !row) {
    return;
  }

  const backup = selectedBackup();
  const hasBackup = Boolean(backup && backup.archive);
  els.backupRestoreBtn.disabled = row.mounted || !hasBackup;
  els.backupRestoreManifestBtn.disabled = row.mounted || !hasBackup;
  els.backupDeleteBtn.disabled = !hasBackup;
}

function renderBackups() {
  if (state.selectedBackup >= state.backups.length) {
    state.selectedBackup = Math.max(0, state.backups.length - 1);
  }

  els.backupsBody.innerHTML = state.backups.map((row, idx) => {
    const selected = idx === state.selectedBackup ? "selected" : "";
    return `<tr class="${selected}" data-row="${idx}">
      <td>${escapeHtml(formatBackupTimestamp(row.timestamp))}</td>
      <td>${escapeHtml(formatMaybeBytes(row.size))}</td>
      <td>${escapeHtml(row.archive || "-")}</td>
    </tr>`;
  }).join("");

  els.backupsBody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => {
      state.selectedBackup = Number(tr.dataset.row);
      renderBackups();
      setStorageActionButtons(Boolean(selectedStorage()), selectedStorage());
    });
  });

  setStorageActionButtons(Boolean(selectedStorage()), selectedStorage());
}

function renderSystem() {
  const data = state.system;
  if (!data) {
    els.systemSummary.innerHTML = "<div class='detail-item'><div class='k'>Info</div><div class='v'>No data.</div></div>";
    els.fsBody.innerHTML = "";
    els.ifaceBody.innerHTML = "";
    els.ioHead.innerHTML = "";
    els.ioBody.innerHTML = "";
    renderSystemTrends();
    return;
  }

  els.systemSummary.innerHTML = [
    detail("Host", data.hostname || "-"),
    detail("Uptime", data.uptime || "-"),
    detail("Load", data.load_average || "-"),
    detail("RAM", formatMemory(data.memory)),
    detail("Swap", formatSwap(data.swap)),
    detail("Warnings", (data.warnings || []).length ? data.warnings.join(" | ") : "none"),
  ].join("");

  const filesystems = data.filesystems || [];
  els.fsBody.innerHTML = filesystems.map((row) => `<tr>
    <td>${escapeHtml(row.filesystem || "-")}</td>
    <td>${escapeHtml(row.mountpoint || "-")}</td>
    <td>${escapeHtml(formatKB(row.size_kb))}</td>
    <td>${escapeHtml(formatKB(row.used_kb))}</td>
    <td>${escapeHtml(formatKB(row.avail_kb))}</td>
    <td>${escapeHtml(String(row.capacity_percent ?? 0))}%</td>
  </tr>`).join("");

  const interfaces = data.interfaces || [];
  els.ifaceBody.innerHTML = interfaces.map((row) => `<tr>
    <td>${escapeHtml(row.name || "-")}</td>
    <td>${escapeHtml(row.status || "-")}</td>
    <td>${escapeHtml(row.mtu >= 0 ? String(row.mtu) : "-")}</td>
    <td>${escapeHtml((row.addresses || []).join(", ") || "-")}</td>
    <td>${escapeHtml(formatBytes(row.in_bytes || 0))}</td>
    <td>${escapeHtml(formatBytes(row.out_bytes || 0))}</td>
  </tr>`).join("");

  const ioRows = data.io || [];
  const metricKeys = new Set();
  ioRows.forEach((row) => Object.keys(row.metrics || {}).forEach((k) => metricKeys.add(k)));
  const columns = ["device", ...Array.from(metricKeys).sort()];
  els.ioHead.innerHTML = columns.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
  els.ioBody.innerHTML = ioRows.map((row) => {
    const cols = [`<td>${escapeHtml(row.device || "-")}</td>`];
    columns.slice(1).forEach((k) => cols.push(`<td>${escapeHtml((row.metrics && row.metrics[k]) || "-")}</td>`));
    return `<tr>${cols.join("")}</tr>`;
  }).join("");

  renderSystemTrends();
}

function detail(key, value, className = "") {
  const classes = className ? `detail-item ${className}` : "detail-item";
  return `<div class="${classes}"><div class="k">${escapeHtml(key)}</div><div class="v">${escapeHtml(value || "-")}</div></div>`;
}

async function refreshCells() {
  const payload = await api("/api/cells");
  state.cells = payload.rows || [];
  renderMetrics(payload.meta || {});
  renderCells();
}

async function refreshSystem() {
  const payload = await api("/api/system");
  state.system = payload.data || null;
  updateSystemTrends(state.system);
  renderMetrics(payload.meta || {});
  renderSystem();
}

async function refreshStorage() {
  const payload = await api("/api/storage");
  state.storage = payload.rows || [];
  renderMetrics(payload.meta || {});
  renderStorage();
}

async function refreshBackups() {
  const row = selectedStorage();
  if (!row) {
    state.backups = [];
    renderBackups();
    return;
  }
  const payload = await api(`/api/backups?kind=${encodeURIComponent(row.kind)}&name=${encodeURIComponent(row.name)}`);
  state.backups = payload.rows || [];
  renderBackups();
}

async function refreshCurrentMode() {
  if (!state.loggedIn) return;

  if (state.mode === "system") {
    await refreshSystem();
  } else if (state.mode === "cells") {
    await refreshCells();
  } else {
    await refreshStorage();
    await refreshBackups();
  }
}

async function runCellAction(action, all = false) {
  const row = selectedCell();
  const body = { action, all };
  if (!all && row) {
    body.name = row.name;
  }
  const payload = await api("/api/cells/action", { method: "POST", body });
  setStatus(payload.message || "Cell action executed.", "success");
  if (payload.output) {
    setStatus(payload.output, "success");
  }
  await refreshCells();
}

async function runStorageAction(action, withManifest = false) {
  const row = selectedStorage();
  if (!row) {
    throw new Error("No storage target selected.");
  }

  const body = {
    action,
    kind: row.kind,
    name: row.name,
    with_manifest: withManifest,
  };

  if (action === "restore" || action === "delete") {
    const backup = selectedBackup();
    if (!backup || !backup.archive) {
      throw new Error("No backup selected.");
    }
    body.archive = backup.archive;
  }

  const payload = await api("/api/storage/action", { method: "POST", body });
  setStatus(payload.message || "Storage action executed.", "success");
  if (payload.output) {
    setStatus(payload.output, "success");
  }
  await refreshStorage();
  await refreshBackups();
}

function bindEvents() {
  els.themeToggles.forEach((btn) => {
    btn.addEventListener("click", toggleTheme);
  });

  if (els.statusToggleBtn) {
    els.statusToggleBtn.addEventListener("click", toggleStatusPanel);
  }

  if (els.confirmModalCancelBtn) {
    els.confirmModalCancelBtn.addEventListener("click", () => {
      closeConfirmModal(false);
    });
  }

  if (els.confirmModalConfirmBtn) {
    els.confirmModalConfirmBtn.addEventListener("click", () => {
      closeConfirmModal(true);
    });
  }

  if (els.confirmModal) {
    els.confirmModal.addEventListener("click", (ev) => {
      if (ev.target === els.confirmModal) {
        closeConfirmModal(false);
      }
    });
  }

  document.addEventListener("keydown", (ev) => {
    if (!isConfirmModalOpen()) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeConfirmModal(false);
    }
  });

  els.loginForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const data = new FormData(els.loginForm);
    const username = String(data.get("username") || "").trim();
    const password = String(data.get("password") || "");

    setLoginStatus("Authenticating ...");
    try {
      await withActionModal("Checking credentials ...", async () => {
        const payload = await api("/api/login", {
          method: "POST",
          body: { username, password },
        });
        state.csrf = payload.csrf_token;
        state.username = payload.username;
        state.refreshSeconds = payload.refresh_seconds || 4;
        state.mode = "cells";
        showApp(true);
        applyModeUI();
        schedulePolling();
        els.sessionInfo.textContent = `${state.username} on netbsd`;
        setStatus("Login successful.", "success");
        setLoginStatus("", "");
        await refreshCurrentMode();
      });
    } catch (err) {
      setLoginStatus(err.details || err.message || "Login failed.", "error");
    }
  });

  els.logoutBtn.addEventListener("click", () => guarded(async () => {
    try {
      await api("/api/logout", { method: "POST" });
    } catch {
      // ignore logout errors
    }
    clearPolling();
    state.csrf = "";
    state.username = "";
    state.mode = "cells";
    applyModeUI();
    showApp(false);
    setStatus("Signed out.");
  }, { progressText: "Signing out ..." }));

  els.modeCells.addEventListener("click", async () => {
    state.mode = "cells";
    applyModeUI();
    await refreshCells();
  });

  els.modeSystem.addEventListener("click", async () => {
    state.mode = "system";
    applyModeUI();
    await refreshSystem();
  });

  els.modeStorage.addEventListener("click", async () => {
    state.mode = "storage";
    applyModeUI();
    await refreshStorage();
    await refreshBackups();
  });

  els.cellFilterGroup.querySelectorAll(".filter").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.filter = btn.dataset.filter;
      els.cellFilterGroup.querySelectorAll(".filter").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderCells();
    });
  });

  els.refreshBtn.addEventListener("click", () => guarded(async () => {
      setStatus("Refreshing ...");
      await refreshCurrentMode();
      setStatus("Refreshed.", "success");
  }, { progressText: "Refreshing view ..." }));

  els.startBtn.addEventListener("click", async () => {
    const row = selectedCell();
    if (!row) {
      setStatus("No cell selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm start",
      message: "The selected cell will be started.",
      detail: row.name,
      confirmLabel: "Start",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("start"), { progressText: "Starting cell ..." });
  });

  els.stopBtn.addEventListener("click", async () => {
    const row = selectedCell();
    if (!row) {
      setStatus("No cell selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm stop",
      message: "The selected cell will be stopped.",
      detail: row.name,
      confirmLabel: "Stop",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("stop"), { progressText: "Stopping cell ..." });
  });

  els.restartBtn.addEventListener("click", async () => {
    const row = selectedCell();
    if (!row) {
      setStatus("No cell selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm restart",
      message: "The selected cell will be restarted.",
      detail: row.name,
      confirmLabel: "Restart",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("restart"), { progressText: "Restarting cell ..." });
  });

  els.startAllBtn.addEventListener("click", async () => {
    const approved = await confirmAction({
      title: "Confirm start all",
      message: "All cells will be started.",
      detail: `${state.cells.length} Targets`,
      confirmLabel: "Start all",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("start", true), { progressText: "Starting all cells ..." });
  });

  els.stopAllBtn.addEventListener("click", async () => {
    const approved = await confirmAction({
      title: "Confirm stop all",
      message: "All cells will be stopped.",
      detail: `${state.cells.length} Targets`,
      confirmLabel: "Stop all",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("stop", true), { progressText: "Stopping all cells ..." });
  });

  els.restartAllBtn.addEventListener("click", async () => {
    const approved = await confirmAction({
      title: "Confirm restart all",
      message: "All cells will be restarted.",
      detail: `${state.cells.length} Targets`,
      confirmLabel: "Restart all",
      danger: false,
    });
    if (!approved) return;
    guarded(() => runCellAction("restart", true), { progressText: "Restarting all cells ..." });
  });

  els.applyAllBtn.addEventListener("click", () => guarded(() => runCellAction("apply", true), { progressText: "Applying changes to all cells ..." }));

  els.backupCreateBtn.addEventListener("click", () => guarded(() => runStorageAction("create"), { progressText: "Creating backup ..." }));
  els.backupRestoreBtn.addEventListener("click", async () => {
    const row = selectedStorage();
    const backup = selectedBackup();
    if (!row || !backup) {
      setStatus("No target/backup selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm restore",
      message: "The selected backup will be restored.",
      detail: `${row.kind}:${row.name}\n${backup.archive}`,
      confirmLabel: "Restore",
      danger: true,
    });
    if (!approved) return;
    guarded(() => runStorageAction("restore", false), { progressText: "Restoring backup ..." });
  });

  els.backupRestoreManifestBtn.addEventListener("click", async () => {
    const row = selectedStorage();
    const backup = selectedBackup();
    if (!row || !backup) {
      setStatus("No target/backup selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm restore + manifest",
      message: "Backup and manifest will be restored.",
      detail: `${row.kind}:${row.name}\n${backup.archive}`,
      confirmLabel: "Restore + manifest",
      danger: true,
    });
    if (!approved) return;
    guarded(() => runStorageAction("restore", true), { progressText: "Restoring backup and manifest ..." });
  });

  els.backupDeleteBtn.addEventListener("click", async () => {
    const row = selectedStorage();
    const backup = selectedBackup();
    if (!row || !backup) {
      setStatus("No target/backup selected.", "error");
      return;
    }
    const approved = await confirmAction({
      title: "Confirm backup deletion",
      message: "The selected backup will be permanently deleted.",
      detail: `${row.kind}:${row.name}\n${backup.archive}`,
      confirmLabel: "Delete",
      danger: true,
    });
    if (!approved) return;
    guarded(() => runStorageAction("delete", false), { progressText: "Deleting backup ..." });
  });
}

async function guarded(fn, options = {}) {
  const progressText = options.progressText || "";
  try {
    if (progressText) {
      await withActionModal(progressText, fn);
    } else {
      await fn();
    }
  } catch (err) {
    if (err.status === 401) {
      clearPolling();
      showApp(false);
      setLoginStatus("Session expired. Please sign in again.", "error");
      return;
    }
    setStatus(err.details || err.message || "Action failed", "error");
  }
}

function schedulePolling() {
  clearPolling();
  state.pollTimer = setInterval(() => {
    guarded(async () => {
      await refreshCurrentMode();
    });
  }, Math.max(2, state.refreshSeconds) * 1000);
}

function clearPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  if (n < 1024 ** 4) return `${(n / 1024 ** 3).toFixed(1)} GiB`;
  return `${(n / 1024 ** 4).toFixed(1)} TiB`;
}

function parseLooseBytes(value) {
  if (value === null || value === undefined) return null;
  const raw = String(value).trim();
  if (raw === "" || raw === "-") return null;

  const compact = raw.replaceAll(",", "");
  if (/^\d+$/.test(compact)) {
    const bytes = Number(compact);
    return Number.isFinite(bytes) && bytes >= 0 ? bytes : null;
  }

  const m = compact.match(/^(\d+(?:\.\d+)?)\s*(b|bytes?|k|kb|kib|m|mb|mib|g|gb|gib|t|tb|tib)$/i);
  if (!m) return null;

  const amount = Number(m[1]);
  if (!Number.isFinite(amount) || amount < 0) return null;

  const unit = m[2].toLowerCase();
  const factor = {
    b: 1,
    byte: 1,
    bytes: 1,
    k: 1024,
    kb: 1024,
    kib: 1024,
    m: 1024 ** 2,
    mb: 1024 ** 2,
    mib: 1024 ** 2,
    g: 1024 ** 3,
    gb: 1024 ** 3,
    gib: 1024 ** 3,
    t: 1024 ** 4,
    tb: 1024 ** 4,
    tib: 1024 ** 4,
  }[unit];

  if (!factor) return null;
  return amount * factor;
}

function formatMaybeBytes(value) {
  const bytes = parseLooseBytes(value);
  if (bytes === null) {
    const raw = String(value ?? "").trim();
    return raw === "" ? "-" : raw;
  }
  return formatBytes(bytes);
}

function formatBackupTimestamp(value) {
  const raw = String(value ?? "").trim();
  if (raw === "" || raw === "-") return "-";
  const m = raw.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (!m) return raw;
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}`;
}

function formatKB(kb) {
  const n = Number(kb);
  if (!Number.isFinite(n) || n < 0) return "-";
  return formatBytes(n * 1024);
}

function formatMemory(mem) {
  if (!mem || !Number.isFinite(Number(mem.total_bytes))) return "-";
  return `${formatBytes(mem.used_bytes || 0)} / ${formatBytes(mem.total_bytes || 0)} (${mem.used_percent || 0}%)`;
}

function formatSwap(swap) {
  if (!swap || !swap.readable) return "n/a";
  if (!swap.has_swap) return "no swap";
  return `${formatKB(swap.used_kb || 0)} / ${formatKB(swap.total_kb || 0)} (${swap.used_percent || 0}%)`;
}

function humanAge(raw) {
  const value = String(raw ?? "").trim();
  if (value === "") return "-";
  if (!/^\d+$/.test(value)) return value;
  const n = Number(value);
  if (!Number.isFinite(n)) return value;
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m${n % 60}s`;
  if (n < 86400) return `${Math.floor(n / 3600)}h${Math.floor((n % 3600) / 60)}m`;
  if (n < 604800) return `${Math.floor(n / 86400)}d${Math.floor((n % 86400) / 3600)}h`;
  return `${Math.floor(n / 604800)}w${Math.floor((n % 604800) / 86400)}d`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function bootstrap() {
  ensureSystemTrendElements();
  applyTheme(detectInitialTheme());
  state.statusOpen = detectInitialStatusPanel();
  bindEvents();
  applyModeUI();
  applyStatusPanel(state.statusOpen, false);
  setStatus("Checking session ...");
  try {
    const me = await api("/api/me");
    state.csrf = me.csrf_token;
    state.username = me.username;
    state.refreshSeconds = me.refresh_seconds || 4;
    state.mode = "cells";
    showApp(true);
    applyModeUI();
    els.sessionInfo.textContent = `${state.username} on netbsd`;
    schedulePolling();
    await refreshCurrentMode();
    setStatus("Connected.", "success");
  } catch {
    showApp(false);
    setStatus("Please sign in.");
  }
}

bootstrap();
