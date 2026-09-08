const loginView = document.getElementById("login-view");
const appView = document.getElementById("app-view");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const urlForm = document.getElementById("url-form");
const torrentForm = document.getElementById("torrent-form");
const addError = document.getElementById("add-error");
const jobsList = document.getElementById("jobs-list");
const jobsEmpty = document.getElementById("jobs-empty");
const filesList = document.getElementById("files-list");
const filesEmpty = document.getElementById("files-empty");
const ntfyPill = document.getElementById("ntfy-pill");
const routeValue = document.getElementById("route-value");
const egressValue = document.getElementById("egress-value");
const liveValue = document.getElementById("live-value");
const liveDot = document.getElementById("live-dot");
const ntfyTestBtn = document.getElementById("ntfy-test-btn");
const logoutBtn = document.getElementById("logout-btn");
const addOpenBtn = document.getElementById("add-open-btn");
const addCloseBtn = document.getElementById("add-close-btn");
const addBackdrop = document.getElementById("add-backdrop");
const addDialog = document.getElementById("add-dialog");
const urlInput = document.getElementById("url-input");
const confirmDialog = document.getElementById("confirm-dialog");
const confirmBackdrop = document.getElementById("confirm-backdrop");
const confirmCancelBtn = document.getElementById("confirm-cancel-btn");
const confirmOkBtn = document.getElementById("confirm-ok-btn");
const confirmFileId = document.getElementById("confirm-file-id");
const confirmError = document.getElementById("confirm-error");

let pollTimer = null;
let socket = null;
let socketRetry = null;
let useWebsocket = true;
let pendingDeleteId = null;
let deleteInFlight = false;
const expandedJobs = new Set();
const cardEls = new Map(); // id → root element (preserve expand + canvas across polls)
const fileEls = new Map(); // id → completed file row

function show(el) {
  el.classList.remove("hidden");
}

function hide(el) {
  el.classList.add("hidden");
}

function setError(node, message) {
  if (!message) {
    hide(node);
    node.textContent = "";
    return;
  }
  node.textContent = message;
  show(node);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(options.headers || {}),
    },
  });
  if (res.status === 401 && !path.startsWith("/api/auth/login")) {
    enterLogin();
    throw new Error("Unauthorized");
  }
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const detail = data && data.detail ? data.detail : res.statusText;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function enterLogin() {
  closeAddDialog();
  closeConfirmDialog();
  stopLive();
  hide(appView);
  show(loginView);
}

function enterApp() {
  hide(loginView);
  show(appView);
  refreshAll();
  startLive();
}

function openAddDialog() {
  setError(addError, "");
  show(addDialog);
  requestAnimationFrame(() => urlInput.focus());
}

function closeAddDialog() {
  hide(addDialog);
  setError(addError, "");
}

function openConfirmDelete(fileId) {
  pendingDeleteId = fileId;
  deleteInFlight = false;
  confirmFileId.textContent = fileId;
  confirmOkBtn.disabled = false;
  confirmOkBtn.textContent = "Delete";
  setError(confirmError, "");
  show(confirmDialog);
  requestAnimationFrame(() => confirmCancelBtn.focus());
}

function closeConfirmDialog() {
  if (deleteInFlight) return;
  hide(confirmDialog);
  pendingDeleteId = null;
  setError(confirmError, "");
  confirmOkBtn.disabled = false;
  confirmOkBtn.textContent = "Delete";
}

async function confirmDeleteFile() {
  if (!pendingDeleteId || deleteInFlight) return;
  const fileId = pendingDeleteId;
  deleteInFlight = true;
  confirmOkBtn.disabled = true;
  confirmOkBtn.textContent = "Deleting…";
  setError(confirmError, "");
  try {
    await api(`/api/files/${encodeURIComponent(fileId)}`, { method: "DELETE" });
    deleteInFlight = false;
    closeConfirmDialog();
    requestLiveRefresh();
  } catch (err) {
    deleteInFlight = false;
    confirmOkBtn.disabled = false;
    confirmOkBtn.textContent = "Delete";
    setError(confirmError, err.message);
  }
}

addOpenBtn.addEventListener("click", openAddDialog);
addCloseBtn.addEventListener("click", closeAddDialog);
addBackdrop.addEventListener("click", closeAddDialog);
confirmBackdrop.addEventListener("click", closeConfirmDialog);
confirmCancelBtn.addEventListener("click", closeConfirmDialog);
confirmOkBtn.addEventListener("click", confirmDeleteFile);

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!confirmDialog.classList.contains("hidden")) {
    closeConfirmDialog();
    return;
  }
  if (!addDialog.classList.contains("hidden")) {
    closeAddDialog();
  }
});

function formatBytes(n) {
  if (n == null || Number.isNaN(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatRate(bps) {
  if (!bps) return "0 B/s";
  return `${formatBytes(bps)}/s`;
}

function pct(progress) {
  return `${Math.min(100, Math.round((progress || 0) * 1000) / 10)}%`;
}

function formatEta(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds <= 0) return "done";
  const s = Math.round(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${r}s`;
  return `${r}s`;
}

function formatDuration(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds <= 0) return "0s";
  return formatEta(seconds);
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function checkSession() {
  try {
    await api("/api/auth/me");
    enterApp();
  } catch {
    enterLogin();
  }
}

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setError(loginError, "");
  const password = document.getElementById("password").value;
  try {
    await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    enterApp();
  } catch (err) {
    setError(loginError, err.message || "Login failed");
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } finally {
    enterLogin();
  }
});

urlForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setError(addError, "");
  const url = document.getElementById("url-input").value.trim();
  const name = document.getElementById("name-input").value.trim();
  try {
    await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({ url, name: name || null }),
    });
    urlForm.reset();
    closeAddDialog();
    requestLiveRefresh();
  } catch (err) {
    setError(addError, err.message || "Failed to add");
  }
});

torrentForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setError(addError, "");
  const fileInput = document.getElementById("torrent-input");
  if (!fileInput.files.length) return;
  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  try {
    const res = await fetch("/api/jobs/torrent", {
      method: "POST",
      body: fd,
      credentials: "same-origin",
    });
    if (res.status === 401) {
      enterLogin();
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || res.statusText);
    torrentForm.reset();
    closeAddDialog();
    requestLiveRefresh();
  } catch (err) {
    setError(addError, err.message || "Upload failed");
  }
});

function applySnapshot(payload) {
  if (!payload) return;
  if (payload.status) renderStatus(payload.status);
  if (payload.jobs) renderJobs(payload.jobs);
  if (payload.files) renderFiles(payload.files);
}

async function refreshAll() {
  try {
    const [status, jobs, files] = await Promise.all([
      api("/api/status"),
      api("/api/jobs"),
      api("/api/files"),
    ]);
    applySnapshot({ status, jobs, files });
  } catch (err) {
    if (err.message !== "Unauthorized") {
      console.error(err);
    }
  }
}

function setLiveState(label, tone) {
  liveValue.textContent = label;
  liveValue.className = `status-value ${tone}`;
  liveDot.className = `status-dot ${tone}`;
}

function renderStatus(status) {
  if (status.dev_mode) {
    routeValue.textContent = "dev · clearnet";
    routeValue.className = "status-value warn";
  } else {
    routeValue.textContent = "gluetun";
    routeValue.className = "status-value ok";
  }

  egressValue.textContent = status.public_ip || "—";
  egressValue.title = status.public_ip ? "Current egress public IP" : "Public IP not yet known";

  if (status.ntfy_enabled) {
    ntfyPill.textContent = "ntfy on";
    ntfyPill.className = "pill ok";
    show(ntfyPill);
    show(ntfyTestBtn);
  } else {
    hide(ntfyPill);
    hide(ntfyTestBtn);
  }
}

ntfyTestBtn.addEventListener("click", async () => {
  try {
    await api("/api/ntfy/test", { method: "POST", body: "{}" });
    ntfyTestBtn.textContent = "Sent";
    setTimeout(() => {
      ntfyTestBtn.textContent = "Test ntfy";
    }, 2000);
  } catch (err) {
    setError(addError, err.message || "ntfy test failed");
  }
});

function statusClass(status) {
  if (status === "downloading" || status === "encrypting") return "ok";
  if (status === "paused" || status === "queued") return "warn";
  if (status === "failed") return "danger";
  return "";
}

function kindIcon(kind) {
  if (kind === "magnet") return "🧲";
  if (kind === "torrent") return "📦";
  if (kind === "http") return "🔗";
  return "•";
}

function flagEmoji(country) {
  if (!country || country.length !== 2) return "🌐";
  const A = 0x1f1e6;
  return String.fromCodePoint(
    ...[...country.toUpperCase()].map((c) => A + c.charCodeAt(0) - 65)
  );
}

function setFlagEl(el, country) {
  const cc = (country || "").toUpperCase();
  if (el.dataset.country === cc) return;
  el.dataset.country = cc;
  el.title = cc || "unknown";
  el.textContent = flagEmoji(cc || null);
  // CSS flag image as decoration (cached by browser; no <img> load churn)
  if (cc.length === 2) {
    el.style.backgroundImage = `url("https://flagcdn.com/w40/${cc.toLowerCase()}.png")`;
    el.classList.add("has-img");
  } else {
    el.style.backgroundImage = "";
    el.classList.remove("has-img");
  }
}

function peerMetaFlags(p) {
  return [p.seed ? "seed" : "", p.encrypted ? "enc" : "", p.connection || ""]
    .filter(Boolean)
    .join(" ");
}

function setTextIfChanged(el, value) {
  if (!el) return;
  const next = value == null ? "" : String(value);
  if (el.textContent !== next) el.textContent = next;
}

function createPeerRow(p) {
  const key = `${p.ip}:${p.port || 0}`;
  const tr = document.createElement("tr");
  tr.dataset.peer = key;

  const tdIp = document.createElement("td");
  tdIp.className = "mono";
  const inner = document.createElement("span");
  inner.className = "peer-ip-inner";

  const flag = document.createElement("span");
  flag.className = "flag";
  setFlagEl(flag, p.country);

  const addr = document.createElement("span");
  addr.className = "peer-addr";
  addr.textContent = `${p.ip}${p.port ? ":" + p.port : ""}`;

  inner.append(flag, addr);
  tdIp.appendChild(inner);

  const tdClient = document.createElement("td");
  tdClient.className = "peer-client";
  tdClient.textContent = p.client || "—";

  const tdDown = document.createElement("td");
  tdDown.className = "peer-down";
  tdDown.textContent = formatRate(p.down_speed);

  const tdUp = document.createElement("td");
  tdUp.className = "peer-up";
  tdUp.textContent = formatRate(p.up_speed);

  const tdProg = document.createElement("td");
  tdProg.className = "peer-prog";
  tdProg.textContent = pct(p.progress);

  const tdFlags = document.createElement("td");
  tdFlags.className = "peer-flags";
  tdFlags.textContent = peerMetaFlags(p) || "—";

  tr.append(tdIp, tdClient, tdDown, tdUp, tdProg, tdFlags);
  return tr;
}

function patchPeerRow(tr, p) {
  setFlagEl(tr.querySelector(".flag"), p.country);
  setTextIfChanged(tr.querySelector(".peer-addr"), `${p.ip}${p.port ? ":" + p.port : ""}`);
  setTextIfChanged(tr.querySelector(".peer-client"), p.client || "—");
  setTextIfChanged(tr.querySelector(".peer-down"), formatRate(p.down_speed));
  setTextIfChanged(tr.querySelector(".peer-up"), formatRate(p.up_speed));
  setTextIfChanged(tr.querySelector(".peer-prog"), pct(p.progress));
  setTextIfChanged(tr.querySelector(".peer-flags"), peerMetaFlags(p) || "—");
}

function syncPeersTable(body, wrap, peers) {
  const scrollTop = wrap.scrollTop;
  if (!body._peerRows) body._peerRows = new Map();
  const map = body._peerRows;

  // Stable order by IP so rows don't jump every tick
  const list = [...peers].sort((a, b) => {
    const ka = `${a.ip}:${a.port || 0}`;
    const kb = `${b.ip}:${b.port || 0}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  if (!list.length) {
    if (body.dataset.empty !== "1") {
      map.clear();
      body.replaceChildren();
      const empty = document.createElement("tr");
      empty.dataset.empty = "1";
      empty.innerHTML = `<td colspan="6" class="muted">No peers yet</td>`;
      body.appendChild(empty);
      body.dataset.empty = "1";
    }
    wrap.scrollTop = scrollTop;
    return;
  }

  if (body.dataset.empty === "1") {
    body.replaceChildren();
    delete body.dataset.empty;
    map.clear();
  }

  const seen = new Set();
  let orderChanged = false;
  const desiredOrder = [];

  for (const p of list) {
    const key = `${p.ip}:${p.port || 0}`;
    seen.add(key);
    let tr = map.get(key);
    if (!tr) {
      tr = createPeerRow(p);
      map.set(key, tr);
      orderChanged = true;
    } else {
      patchPeerRow(tr, p);
    }
    desiredOrder.push(tr);
  }

  for (const [key, tr] of [...map.entries()]) {
    if (!seen.has(key)) {
      tr.remove();
      map.delete(key);
      orderChanged = true;
    }
  }

  // Only touch DOM structure when the peer set changes — never shuffle existing rows
  if (orderChanged) {
    const current = [...body.children];
    const same =
      current.length === desiredOrder.length &&
      current.every((node, i) => node === desiredOrder[i]);
    if (!same) {
      body.replaceChildren(...desiredOrder);
    }
  }

  wrap.scrollTop = scrollTop;
}

function drawSpeedGraph(canvas, history) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 320;
  const cssH = canvas.clientHeight || 96;
  if (canvas.width !== Math.floor(cssW * dpr) || canvas.height !== Math.floor(cssH * dpr)) {
    canvas.width = Math.floor(cssW * dpr);
    canvas.height = Math.floor(cssH * dpr);
  }
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const samples = history || [];
  if (samples.length < 2) {
    ctx.fillStyle = "rgba(138, 163, 148, 0.55)";
    ctx.font = `${12 * dpr}px DM Sans, sans-serif`;
    ctx.fillText("Waiting for speed samples…", 12 * dpr, h / 2);
    return;
  }

  const downs = samples.map((s) => s.down || 0);
  const ups = samples.map((s) => s.up || 0);
  const maxV = Math.max(1, ...downs, ...ups);
  const pad = 8 * dpr;

  function path(values, color, fill) {
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = pad + (i / (values.length - 1)) * (w - pad * 2);
      const y = h - pad - (v / maxV) * (h - pad * 2);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2 * dpr;
    ctx.stroke();
    if (fill) {
      const lastX = pad + (w - pad * 2);
      ctx.lineTo(lastX, h - pad);
      ctx.lineTo(pad, h - pad);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
    }
  }

  ctx.strokeStyle = "rgba(232, 240, 234, 0.08)";
  ctx.lineWidth = 1;
  for (let i = 0; i < 4; i++) {
    const y = pad + ((h - pad * 2) * i) / 3;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(w - pad, y);
    ctx.stroke();
  }

  path(downs, "#3dcf8e", "rgba(61, 207, 142, 0.12)");
  path(ups, "#6aa8e8", null);

  ctx.fillStyle = "rgba(138, 163, 148, 0.85)";
  ctx.font = `${10 * dpr}px JetBrains Mono, monospace`;
  ctx.fillText(`peak ↓ ${formatRate(maxV)}`, pad, pad + 10 * dpr);
}

function renderJobs(jobs) {
  const active = jobs.filter((j) =>
    ["queued", "downloading", "paused", "encrypting"].includes(j.status)
  );
  const recent = jobs.filter((j) => ["failed"].includes(j.status)).slice(0, 8);
  const showList = [...active, ...recent];
  const seen = new Set(showList.map((j) => j.id));

  for (const [id, el] of [...cardEls.entries()]) {
    if (!seen.has(id)) {
      el.remove();
      cardEls.delete(id);
      expandedJobs.delete(id);
    }
  }

  if (!showList.length) {
    jobsList.innerHTML = "";
    cardEls.clear();
    show(jobsEmpty);
    return;
  }
  hide(jobsEmpty);

  for (const job of showList) {
    let card = cardEls.get(job.id);
    if (!card || !card.querySelector('[data-f="pct"]')) {
      const fresh = buildJobCardShell(job.id);
      if (card) card.replaceWith(fresh);
      else jobsList.appendChild(fresh);
      card = fresh;
      cardEls.set(job.id, card);
    }
    patchJobCard(card, job);
  }

  const desired = showList.map((job) => cardEls.get(job.id)).filter(Boolean);
  const current = [...jobsList.children].filter((el) => el.classList?.contains("job-card"));
  const sameOrder =
    current.length === desired.length && current.every((node, i) => node === desired[i]);
  if (!sameOrder) {
    // Avoid appendChild reshuffles every tick — they repaint the whole expanded table
    for (const el of desired) jobsList.appendChild(el);
  }
}

function buildJobCardShell(jobId) {
  const card = document.createElement("article");
  card.className = "job-card";
  card.dataset.id = jobId;
  card.innerHTML = `
    <header class="job-summary">
      <button type="button" class="job-toggle" aria-expanded="false">
        <span class="chevron" aria-hidden="true"></span>
        <span class="job-summary-main">
          <span class="job-title-row">
            <span class="kind-badge" data-f="kind-badge"></span>
            <span class="row-title" data-f="name"></span>
            <span class="pill" data-f="status-pill"></span>
          </span>
          <span class="job-chips" data-f="chips"></span>
          <span class="progress-row">
            <span class="bar"><span data-f="bar"></span></span>
            <span class="progress-pct" data-f="pct">0%</span>
          </span>
        </span>
      </button>
      <div class="row-actions job-actions" data-f="actions"></div>
    </header>
    <div class="job-detail hidden" data-f="detail">
      <div class="detail-grid" data-f="stats"></div>
      <div class="graph-block">
        <div class="graph-head">
          <strong>Speed</strong>
          <span class="legend"><i class="lg down"></i> download <i class="lg up"></i> upload</span>
        </div>
        <canvas class="speed-canvas" height="96" data-f="canvas"></canvas>
      </div>
      <div class="peers-block">
        <div class="graph-head">
          <strong>Peers</strong>
          <span data-f="peer-count">0 connected</span>
        </div>
        <div class="peers-table-wrap" data-f="peers-wrap">
          <table class="peers-table">
            <thead>
              <tr>
                <th>IP</th><th>Client</th><th>↓</th><th>↑</th><th>Prog</th><th>Flags</th>
              </tr>
            </thead>
            <tbody data-f="peers-body"></tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  const toggle = card.querySelector(".job-toggle");
  toggle.addEventListener("click", () => {
    if (expandedJobs.has(jobId)) expandedJobs.delete(jobId);
    else expandedJobs.add(jobId);
    const job = card._job;
    if (job) patchJobCard(card, job);
  });

  return card;
}

function chip(icon, label, title) {
  return `<span class="chip" title="${escapeHtml(title || label)}"><span class="chip-ico" aria-hidden="true">${icon}</span><span class="chip-txt">${escapeHtml(label)}</span></span>`;
}

function syncActionButton(container, key, visible, label, className, onClick) {
  let btn = container.querySelector(`[data-action="${key}"]`);
  if (!visible) {
    if (btn) btn.remove();
    return;
  }
  if (!btn) {
    btn = document.createElement("button");
    btn.type = "button";
    btn.dataset.action = key;
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      try {
        await onClick();
      } catch (err) {
        setError(addError, err.message);
      }
    });
    container.appendChild(btn);
  }
  btn.className = className;
  btn.textContent = label;
}

function patchJobCard(card, job) {
  card._job = job;
  const expanded = expandedJobs.has(job.id);
  const canCancel = ["queued", "downloading", "paused"].includes(job.status);
  const canPause = ["queued", "downloading"].includes(job.status);
  const canResume = job.status === "paused";
  card.classList.toggle("expanded", expanded);

  const f = (name) => card.querySelector(`[data-f="${name}"]`);
  const toggle = card.querySelector(".job-toggle");
  toggle.setAttribute("aria-expanded", expanded ? "true" : "false");

  f("kind-badge").textContent = kindIcon(job.kind);
  f("kind-badge").title = job.kind;
  f("name").textContent = job.name;

  const statusPill = f("status-pill");
  statusPill.textContent = job.status.replaceAll("_", " ");
  statusPill.className = `pill ${statusClass(job.status)}`;

  const sizeLabel =
    job.total_bytes != null
      ? `${formatBytes(job.downloaded_bytes)} / ${formatBytes(job.total_bytes)}`
      : formatBytes(job.downloaded_bytes);

  let chips;
  if (job.status === "encrypting") {
    chips = [chip("Σ", sizeLabel, "Encryption progress")];
  } else {
    chips = [
      chip("↓", formatRate(job.download_rate), "Download speed"),
      chip("↑", formatRate(job.upload_rate), "Upload speed"),
      chip("Σ", sizeLabel, "Transferred"),
      chip("⏱", formatEta(job.eta_seconds), "ETA"),
    ];
    if (job.kind !== "http") {
      chips.push(chip("👥", `${job.num_seeds}s · ${job.num_peers}p`, "Seeds / peers"));
    }
  }
  const chipsHtml = chips.join("");
  if (card._chipsHtml !== chipsHtml) {
    card._chipsHtml = chipsHtml;
    f("chips").innerHTML = chipsHtml;
  }

  const barEl = f("bar");
  const pctLabel = pct(job.progress);
  if (barEl.style.width !== pctLabel) barEl.style.width = pctLabel;
  setTextIfChanged(f("pct"), pctLabel);

  // Action buttons
  const actions = f("actions");
  syncActionButton(actions, "pause", canPause, "Pause", "btn ghost small", async () => {
    await api(`/api/jobs/${card.dataset.id}/pause`, { method: "POST", body: "{}" });
    requestLiveRefresh();
  });
  syncActionButton(actions, "resume", canResume, "Resume", "btn secondary small", async () => {
    await api(`/api/jobs/${card.dataset.id}/resume`, { method: "POST", body: "{}" });
    requestLiveRefresh();
  });
  syncActionButton(actions, "cancel", canCancel, "Cancel", "btn danger small", async () => {
    const id = card.dataset.id;
    await api(`/api/jobs/${id}`, { method: "DELETE" });
    expandedJobs.delete(id);
    cardEls.delete(id);
    card.remove();
    requestLiveRefresh();
  });

  const detail = f("detail");
  detail.classList.toggle("hidden", !expanded);
  if (!expanded) return;

  // Stats
  const stats = [
    ["State", job.state || "—"],
    ["Active", formatDuration(job.active_duration_seconds)],
    ["Payload ↓", formatRate(job.payload_download_rate)],
    ["Payload ↑", formatRate(job.payload_upload_rate)],
    ["Uploaded", formatBytes(job.uploaded_bytes)],
    ["Availability", (job.distributed_copies || 0).toFixed(2)],
    ["Pieces", `${job.pieces_done}/${job.num_pieces || "—"}`],
    ["Swarm", `list ${job.list_seeds}s / ${job.list_peers}p`],
    ["Tracker", job.current_tracker || "—", true, true],
    ["Info hash", job.info_hash || "—", true, true],
    ["Source", job.source_preview || "—", true, true],
  ];
  if (job.error) stats.push(["Error", job.error, true, false, true]);

  const statsHtml = stats
    .map(([label, value, wide, mono, danger]) => {
      const cls = ["stat", wide ? "wide" : "", danger ? "danger-text" : ""].filter(Boolean).join(" ");
      const vcls = ["stat-value", mono ? "mono" : ""].filter(Boolean).join(" ");
      return `<div class="${cls}"><span class="stat-label">${escapeHtml(label)}</span><span class="${vcls}">${escapeHtml(String(value))}</span></div>`;
    })
    .join("");
  if (card._statsHtml !== statsHtml) {
    card._statsHtml = statsHtml;
    f("stats").innerHTML = statsHtml;
  }

  const hist = job.speed_history || [];
  const graphKey = hist.length
    ? `${hist.length}:${hist[hist.length - 1].t}:${hist[hist.length - 1].down}`
    : "0";
  if (card._graphKey !== graphKey) {
    card._graphKey = graphKey;
    requestAnimationFrame(() => drawSpeedGraph(f("canvas"), hist));
  }

  // Peers — reuse rows; stable IP order; no DOM shuffle unless peer set changes
  const wrap = f("peers-wrap");
  setTextIfChanged(f("peer-count"), `${(job.peers || []).length} connected`);
  syncPeersTable(f("peers-body"), wrap, job.peers || []);
}

function renderFiles(files) {
  const list = files || [];
  const seen = new Set(list.map((f) => f.id));

  for (const [id, el] of [...fileEls.entries()]) {
    if (!seen.has(id)) {
      el.remove();
      fileEls.delete(id);
    }
  }

  if (!list.length) {
    filesList.innerHTML = "";
    fileEls.clear();
    show(filesEmpty);
    return;
  }
  hide(filesEmpty);

  for (const file of list) {
    let row = fileEls.get(file.id);
    if (!row) {
      row = document.createElement("div");
      row.className = "row";
      row.dataset.id = file.id;
      row.innerHTML = `
        <div class="row-main">
          <div class="row-title"><code data-f="id"></code></div>
          <div class="row-meta">
            <span data-f="size"></span>
            <span data-f="duration"></span>
          </div>
        </div>
        <div class="row-actions">
          <button type="button" class="btn danger small" data-f="delete">Delete</button>
        </div>
      `;
      row.querySelector('[data-f="delete"]').addEventListener("click", () => {
        openConfirmDelete(row.dataset.id);
      });
      fileEls.set(file.id, row);
    }
    setTextIfChanged(row.querySelector('[data-f="id"]'), file.id);
    setTextIfChanged(row.querySelector('[data-f="size"]'), formatBytes(file.encrypted_size_bytes));
    const durEl = row.querySelector('[data-f="duration"]');
    if (file.duration_seconds != null) {
      durEl.hidden = false;
      setTextIfChanged(durEl, formatDuration(file.duration_seconds));
    } else {
      durEl.hidden = true;
      setTextIfChanged(durEl, "");
    }
  }

  const desired = list.map((file) => fileEls.get(file.id)).filter(Boolean);
  const current = [...filesList.children].filter((el) => el.classList?.contains("row"));
  const sameOrder =
    current.length === desired.length && current.every((node, i) => node === desired[i]);
  if (!sameOrder) {
    for (const el of desired) filesList.appendChild(el);
  }
}

function wsUrl() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/api/ws`;
}

function requestLiveRefresh() {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "refresh" }));
    return;
  }
  refreshAll();
}

function startLive() {
  stopLive();
  if (!useWebsocket || !window.WebSocket) {
    startPollingFallback();
    return;
  }
  connectSocket();
}

function stopLive() {
  if (socketRetry) {
    clearTimeout(socketRetry);
    socketRetry = null;
  }
  if (socket) {
    try {
      socket.close();
    } catch (_) {
      /* ignore */
    }
    socket = null;
  }
  stopPollingFallback();
}

function connectSocket() {
  try {
    socket = new WebSocket(wsUrl());
  } catch (err) {
    console.warn("websocket failed, falling back to poll", err);
    startPollingFallback();
    return;
  }

  socket.addEventListener("open", () => {
    stopPollingFallback();
    setLiveState("live", "ok");
  });

  socket.addEventListener("message", (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data.type === "snapshot") {
        applySnapshot(data);
      }
    } catch (err) {
      console.error("bad live message", err);
    }
  });

  socket.addEventListener("close", (ev) => {
    socket = null;
    setLiveState("reconnecting", "warn");
    if (ev.code === 4401) {
      enterLogin();
      return;
    }
    startPollingFallback();
    socketRetry = setTimeout(connectSocket, 1200);
  });

  socket.addEventListener("error", () => {
    // close handler will reconnect / fallback
  });
}

function startPollingFallback() {
  stopPollingFallback();
  setLiveState("polling", "warn");
  pollTimer = setInterval(refreshAll, 2000);
}

function stopPollingFallback() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

checkSession();
