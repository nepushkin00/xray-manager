"use strict";

const state = {
  csrf: null,
  profiles: [],
  activeProfileId: null,
  activeProfileKey: null,
  settings: null,
  subscriptions: [],
  selectedIds: new Set(),
  testingIds: new Set(),
  bulkProgress: "",
  bulkTesting: false
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    el.hidden = true;
  }, 4200);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) {
    headers["content-type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (state.csrf && !["GET", "HEAD"].includes(options.method || "GET")) {
    headers["x-csrf-token"] = state.csrf;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showLogin();
    const error = new Error(data.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function showLogin() {
  const dialog = $("#loginDialog");
  if (!dialog.open) dialog.showModal();
}

function hideLogin() {
  const dialog = $("#loginDialog");
  if (dialog.open) dialog.close();
}

function showView(name) {
  $$(".view").forEach((view) => view.classList.toggle("is-active", view.id === `${name}View`));
  $$(".tab").forEach((tab) => tab.classList.toggle("is-active", tab.dataset.view === name));
  if (name === "logs") loadLogs();
}

function profileDelay(profile) {
  if (state.testingIds.has(profile.id)) return '<span class="delay-pending">проверка...</span>';
  if (profile.lastTestError) return `<span class="delay-bad" title="${escapeHtml(profile.lastTestError)}">ошибка</span>`;
  if (profile.delayMs == null) return "";
  const cls = profile.delayMs < 900 ? "delay-ok" : "delay-bad";
  return `<span class="${cls}">${profile.delayMs} ms</span>`;
}

function updateProfile(profile) {
  if (!profile?.id) return;
  const index = state.profiles.findIndex((item) => item.id === profile.id);
  if (index !== -1) state.profiles[index] = profile;
}

function normalizeActiveProfileClient() {
  const activeById = state.activeProfileId
    ? state.profiles.find((profile) => profile.id === state.activeProfileId)
    : null;
  if (activeById) {
    state.activeProfileKey = activeById.key || state.activeProfileKey;
    return activeById;
  }
  const activeByKey = state.activeProfileKey
    ? state.profiles.find((profile) => profile.key === state.activeProfileKey)
    : null;
  if (activeByKey) {
    state.activeProfileId = activeByKey.id;
    return activeByKey;
  }
  state.activeProfileId = null;
  state.activeProfileKey = null;
  return null;
}

function decodePunycodeLabel(label) {
  if (!label.toLowerCase().startsWith("xn--")) return label;
  const input = label.slice(4).toLowerCase();
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = input.lastIndexOf("-");
  const output = delimiter >= 0 ? input.slice(0, delimiter).split("").map((char) => char.codePointAt(0)) : [];
  let index = delimiter >= 0 ? delimiter + 1 : 0;
  let n = initialN;
  let i = 0;
  let bias = initialBias;

  const digit = (codePoint) => {
    if (codePoint >= 48 && codePoint <= 57) return codePoint - 22;
    if (codePoint >= 65 && codePoint <= 90) return codePoint - 65;
    if (codePoint >= 97 && codePoint <= 122) return codePoint - 97;
    return base;
  };

  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > Math.floor(((base - tMin) * tMax) / 2)) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };

  try {
    while (index < input.length) {
      const oldI = i;
      let w = 1;
      for (let k = base; ; k += base) {
        const codePoint = input.codePointAt(index);
        index += 1;
        const d = digit(codePoint);
        if (d >= base) return label;
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldI, outLen, oldI === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i, 0, n);
      i += 1;
    }
    return String.fromCodePoint(...output);
  } catch {
    return label;
  }
}

function displayDirectDomainRule(rule) {
  const raw = String(rule || "");
  if (/^(domain|regexp|full|geosite):/i.test(raw)) return raw;
  const prefix = raw.startsWith("*.") ? "*." : "";
  const domain = prefix ? raw.slice(2) : raw;
  const display = domain.split(".").map(decodePunycodeLabel).join(".");
  return `${prefix}${display}`;
}

function normalizeDirectDomainInput(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";
  if (/^(domain|regexp|full|geosite):/i.test(raw)) return raw;
  let value = raw.toLowerCase();
  if (/^https?:\/\//i.test(value)) {
    try {
      value = new URL(value).hostname;
    } catch {
      return "";
    }
  } else {
    value = value.split(/[/?#]/)[0];
  }
  let wildcard = false;
  if (value.startsWith("*.")) {
    wildcard = true;
    value = value.slice(2);
  } else if (value.startsWith(".")) {
    wildcard = true;
    value = value.slice(1);
  }
  value = value.replace(/\.$/, "");
  if (value.includes(":")) value = value.split(":")[0];
  if (!value || value === "*") return "";
  return wildcard ? `*.${value}` : value;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function visibleProfiles() {
  const filter = $("#filterInput").value.trim().toLowerCase();
  return state.profiles.filter((profile) => {
    if (!filter) return true;
    return [profile.name, profile.address, profile.group, profile.source].some((value) => String(value || "").toLowerCase().includes(filter));
  });
}

function updateSelectionUi(rows = visibleProfiles()) {
  const visibleIds = rows.map((profile) => profile.id);
  const visibleSelected = visibleIds.filter((id) => state.selectedIds.has(id)).length;
  const totalSelected = state.selectedIds.size;
  const toggle = $("#toggleVisibleCheckbox");
  if (toggle) {
    toggle.checked = rows.length > 0 && visibleSelected === rows.length;
    toggle.indeterminate = visibleSelected > 0 && visibleSelected < rows.length;
  }
  $("#selectionHint").textContent = totalSelected ? `Выбрано: ${totalSelected}` : "";
  $("#deleteSelectedBtn").disabled = totalSelected === 0;
  $("#clearSelectionBtn").disabled = totalSelected === 0;
  $("#testAllBtn").disabled = state.bulkTesting || state.profiles.length === 0;
  $("#testAllBtn").textContent = state.bulkTesting ? "Проверка..." : "Проверить все";
  $("#bulkHint").textContent = state.bulkProgress;
}

function renderProfiles() {
  const rows = visibleProfiles();
  normalizeActiveProfileClient();

  $("#profilesBody").innerHTML = rows.map((profile, index) => {
    const active = profile.id === state.activeProfileId;
    const checked = state.selectedIds.has(profile.id) ? "checked" : "";
    return `
      <tr class="${active ? "is-active" : ""}">
        <td class="col-check"><input class="profile-check" type="checkbox" data-id="${profile.id}" ${checked}></td>
        <td class="col-num">${index + 1}</td>
        <td>${escapeHtml((profile.protocol || "vless").toUpperCase())}</td>
        <td>${active ? '<span class="badge">Активный</span> ' : ""}${escapeHtml(profile.name)}</td>
        <td title="${escapeHtml(profile.address)}">${escapeHtml(profile.address)}</td>
        <td>${escapeHtml(profile.port)}</td>
        <td>${escapeHtml(profile.network || "tcp")}</td>
        <td>${escapeHtml(profile.security || "none")}</td>
        <td>${escapeHtml(profile.group || "")}</td>
        <td>${profileDelay(profile)}</td>
        <td class="actions">
          <button data-action="activate" data-id="${profile.id}" title="Сделать активным">✓</button>
          <button data-action="test" data-id="${profile.id}" title="Проверить задержку">↯</button>
          <button data-action="edit" data-id="${profile.id}" title="Редактировать">✎</button>
          <button data-action="delete" data-id="${profile.id}" class="danger" title="Удалить">×</button>
        </td>
      </tr>
    `;
  }).join("");

  const active = normalizeActiveProfileClient();
  $("#activeHint").textContent = active ? `Активный: ${active.name} · ${active.address}:${active.port}` : "Активный профиль не выбран";
  updateSelectionUi(rows);
}

function renderSubscriptions() {
  const list = $("#subscriptionsList");
  if (!state.subscriptions.length) {
    list.innerHTML = '<div class="panel">Подписок пока нет.</div>';
    return;
  }
  list.innerHTML = state.subscriptions.map((sub) => `
    <div class="sub-row">
      <div>
        <strong>${escapeHtml(sub.name)}</strong>
        <small>${escapeHtml(sub.group)} · ${escapeHtml(sub.url)}</small>
        <small>${escapeHtml(sub.lastUpdateStatus || "ещё не обновлялась")}${sub.lastUpdateError ? ` · ${escapeHtml(sub.lastUpdateError)}` : ""}</small>
      </div>
      <div class="actions">
        <button data-sub-action="refresh" data-id="${sub.id}">Обновить</button>
        <button data-sub-action="delete" data-id="${sub.id}" class="danger">Удалить</button>
      </div>
    </div>
  `).join("");
}

function renderDirectDomains() {
  const body = $("#directDomainsBody");
  if (!body) return;
  const rules = state.settings?.routingDirectDomains || [];
  if (!rules.length) {
    body.innerHTML = '<tr><td colspan="2" class="muted-cell">Список пуст</td></tr>';
    return;
  }
  body.innerHTML = rules.map((rule, index) => `
    <tr>
      <td title="${escapeHtml(rule)}">${escapeHtml(displayDirectDomainRule(rule))}</td>
      <td class="mini-actions"><button type="button" class="danger" data-direct-domain-index="${index}">×</button></td>
    </tr>
  `).join("");
}

function fillSettingsForm() {
  const form = $("#settingsForm");
  const settings = state.settings;
  if (!settings) return;
  form.listen.value = settings.mixed.listen;
  form.port.value = settings.mixed.port;
  form.udp.checked = Boolean(settings.mixed.udp);
  form.sniffing.checked = Boolean(settings.mixed.sniffing);
  form.auth.checked = Boolean(settings.mixed.auth);
  form.user.value = settings.mixed.user || "";
  form.pass.value = "";
  form.routingMode.value = settings.routingMode || "global";
  form.domainStrategy.value = settings.domainStrategy || "AsIs";
  form.loglevel.value = settings.loglevel || "warning";
  form.muxEnabled.checked = Boolean(settings.mux?.enabled);
  form.muxConcurrency.value = settings.mux?.concurrency ?? -1;
  state.settings.routingDirectDomains = Array.isArray(settings.routingDirectDomains) ? settings.routingDirectDomains : [];
  renderDirectDomains();
}

async function loadAll() {
  const [status, profiles, settings, subscriptions] = await Promise.all([
    api("/api/status"),
    api("/api/profiles"),
    api("/api/settings"),
    api("/api/subscriptions")
  ]);
  state.profiles = profiles.profiles;
  state.activeProfileId = profiles.activeProfileId;
  state.activeProfileKey = profiles.activeProfileKey || null;
  state.settings = settings.settings;
  state.subscriptions = subscriptions.subscriptions;
  const liveIds = new Set(state.profiles.map((profile) => profile.id));
  state.selectedIds = new Set([...state.selectedIds].filter((id) => liveIds.has(id)));
  $("#statusLine").textContent = `${status.service.active} · ${status.service.version || "Xray"}`;
  renderProfiles();
  renderSubscriptions();
  fillSettingsForm();
}

async function loadLogs() {
  try {
    const logs = await api("/api/logs");
    $("#errorLog").textContent = logs.error || "";
    $("#accessLog").textContent = logs.access || "";
  } catch (error) {
    toast(error.message);
  }
}

function openEdit(profile) {
  const form = $("#editForm");
  for (const key of ["id", "name", "group", "address", "port", "uuid", "flow", "network", "security", "serverName", "fingerprint", "publicKey", "shortId"]) {
    form[key].value = profile[key] ?? "";
  }
  $("#editDialog").showModal();
}

function settingsPayloadFromForm() {
  const form = $("#settingsForm");
  return {
    routingMode: form.routingMode.value,
    domainStrategy: form.domainStrategy.value,
    loglevel: form.loglevel.value,
    routingDirectDomains: state.settings?.routingDirectDomains || [],
    mux: {
      enabled: form.muxEnabled.checked,
      concurrency: Number(form.muxConcurrency.value)
    },
    mixed: {
      listen: form.listen.value,
      port: Number(form.port.value),
      udp: form.udp.checked,
      sniffing: form.sniffing.checked,
      auth: form.auth.checked,
      user: form.user.value,
      pass: form.pass.value
    }
  };
}

async function saveSettingsAndApply(message = "Настройки применены") {
  const patched = await api("/api/settings", { method: "PATCH", body: settingsPayloadFromForm() });
  state.settings = patched.settings;
  await api("/api/apply", { method: "POST" });
  toast(message);
  await loadAll();
}

async function main() {
  try {
    const me = await api("/api/auth/me");
    state.csrf = me.csrf;
    hideLogin();
    await loadAll();
  } catch {
    showLogin();
  }

  $$(".tab").forEach((tab) => tab.addEventListener("click", () => showView(tab.dataset.view)));
  $("#filterInput").addEventListener("input", renderProfiles);
  $("#refreshBtn").addEventListener("click", () => loadAll().catch((error) => toast(error.message)));
  $("#selectAllBtn").addEventListener("click", () => {
    for (const profile of visibleProfiles()) state.selectedIds.add(profile.id);
    renderProfiles();
  });
  $("#clearSelectionBtn").addEventListener("click", () => {
    state.selectedIds.clear();
    renderProfiles();
  });
  $("#toggleVisibleCheckbox").addEventListener("change", (event) => {
    const rows = visibleProfiles();
    if (event.currentTarget.checked) {
      for (const profile of rows) state.selectedIds.add(profile.id);
    } else {
      for (const profile of rows) state.selectedIds.delete(profile.id);
    }
    renderProfiles();
  });
  $("#deleteSelectedBtn").addEventListener("click", async () => {
    const ids = [...state.selectedIds];
    if (!ids.length) return;
    if (!confirm(`Удалить выбранные профили: ${ids.length}?`)) return;
    try {
      $("#deleteSelectedBtn").disabled = true;
      const result = await api("/api/profiles/bulk-delete", { method: "POST", body: { ids } });
      state.selectedIds.clear();
      toast(`Удалено профилей: ${result.removed}`);
      await loadAll();
    } catch (error) {
      toast(error.message);
      await loadAll().catch(() => {});
    }
  });
  $("#testAllBtn").addEventListener("click", async () => {
    if (!state.profiles.length || state.bulkTesting) return;
    if (!confirm(`Проверить задержку у всех профилей: ${state.profiles.length}?`)) return;
    const profiles = [...state.profiles];
    state.bulkTesting = true;
    state.testingIds = new Set(profiles.map((profile) => profile.id));
    state.bulkProgress = `Проверка: 0/${profiles.length} · параллельно`;
    renderProfiles();
    try {
      const result = await api("/api/test-all", { method: "POST", body: { ids: profiles.map((profile) => profile.id) } });
      state.profiles = Array.isArray(result.profiles) ? result.profiles : state.profiles;
      state.bulkProgress = "";
      toast(`Проверка завершена: ${result.success} ok, ${result.failed} ошибок · потоков: ${result.concurrency}`);
    } catch (error) {
      if (error.status === 409) toast("Проверка задержек уже запущена");
      else toast(error.message);
      await loadAll().catch(() => {});
    } finally {
      state.bulkTesting = false;
      state.testingIds.clear();
      state.bulkProgress = "";
      renderProfiles();
    }
  });
  $("#reloadLogsBtn").addEventListener("click", loadLogs);
  $("#importBtn").addEventListener("click", () => $("#importDialog").showModal());
  $$("[data-close]").forEach((btn) => btn.addEventListener("click", () => btn.closest("dialog").close()));

  $("#loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#loginError").textContent = "";
    const form = event.currentTarget;
    try {
      const result = await api("/api/auth/login", {
        method: "POST",
        body: { username: form.username.value, password: form.password.value, remember: form.remember.checked }
      });
      state.csrf = result.csrf;
      form.reset();
      hideLogin();
      await loadAll();
    } catch (error) {
      $("#loginError").textContent = error.message;
    }
  });

  $("#logoutBtn").addEventListener("click", async () => {
    await api("/api/auth/logout", { method: "POST" }).catch(() => {});
    state.csrf = null;
    showLogin();
  });

  $("#importForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const result = await api("/api/import", {
        method: "POST",
        body: { text: form.text.value, group: form.group.value }
      });
      $("#importDialog").close();
      form.reset();
      toast(`Импорт: ${result.added} новых, ${result.updated} обновлено`);
      await loadAll();
    } catch (error) {
      toast(error.message);
    }
  });

  $("#profilesBody").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const profile = state.profiles.find((item) => item.id === button.dataset.id);
    if (!profile) return;
    try {
      if (button.dataset.action === "activate") {
        const result = await api(`/api/profiles/${profile.id}/activate`, { method: "POST" });
        state.activeProfileId = result.activeProfileId || profile.id;
        state.activeProfileKey = result.activeProfileKey || profile.key || null;
        renderProfiles();
        toast("Активный сервер переключён");
        await loadAll();
      }
      if (button.dataset.action === "test") {
        button.disabled = true;
        button.textContent = "...";
        state.testingIds.add(profile.id);
        renderProfiles();
        try {
          const result = await api(`/api/test/${profile.id}`, { method: "POST" });
          updateProfile(result.profile);
        } catch (error) {
          if (error.data?.profile) updateProfile(error.data.profile);
          else throw error;
        } finally {
          state.testingIds.delete(profile.id);
          renderProfiles();
        }
      }
      if (button.dataset.action === "edit") openEdit(profile);
      if (button.dataset.action === "delete") {
        if (!confirm(`Удалить ${profile.name}?`)) return;
        await api(`/api/profiles/${profile.id}`, { method: "DELETE" });
        await loadAll();
      }
    } catch (error) {
      toast(error.message);
      await loadAll().catch(() => {});
    } finally {
      button.disabled = false;
    }
  });

  $("#profilesBody").addEventListener("change", (event) => {
    const checkbox = event.target.closest(".profile-check");
    if (!checkbox) return;
    if (checkbox.checked) state.selectedIds.add(checkbox.dataset.id);
    else state.selectedIds.delete(checkbox.dataset.id);
    updateSelectionUi();
  });

  $("#editForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form).entries());
    const id = body.id;
    delete body.id;
    body.port = Number(body.port);
    try {
      await api(`/api/profiles/${id}`, { method: "PATCH", body });
      $("#editDialog").close();
      await loadAll();
    } catch (error) {
      toast(error.message);
    }
  });

  $("#subscriptionForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const body = Object.fromEntries(new FormData(form).entries());
    try {
      await api("/api/subscriptions", { method: "POST", body });
      form.reset();
      await loadAll();
    } catch (error) {
      toast(error.message);
    }
  });

  $("#subscriptionsList").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-sub-action]");
    if (!button) return;
    try {
      if (button.dataset.subAction === "refresh") {
        button.disabled = true;
        const result = await api(`/api/subscriptions/${button.dataset.id}/refresh`, { method: "POST" });
        toast(`Подписка: ${result.added} новых, ${result.updated} обновлено`);
      }
      if (button.dataset.subAction === "delete") {
        await api(`/api/subscriptions/${button.dataset.id}`, { method: "DELETE" });
      }
      await loadAll();
    } catch (error) {
      toast(error.message);
    } finally {
      button.disabled = false;
    }
  });

  $("#addDirectDomainBtn").addEventListener("click", async () => {
    const input = $("#directDomainInput");
    const rule = normalizeDirectDomainInput(input.value);
    if (!rule) {
      toast("Введите домен или Xray matcher");
      return;
    }
    const current = state.settings.routingDirectDomains || [];
    if (!current.some((item) => item.toLowerCase() === rule.toLowerCase())) {
      state.settings.routingDirectDomains = [...current, rule];
    }
    input.value = "";
    renderDirectDomains();
    try {
      await saveSettingsAndApply("Direct-правило добавлено");
    } catch (error) {
      toast(error.message);
      await loadAll().catch(() => {});
    }
  });

  $("#directDomainInput").addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    $("#addDirectDomainBtn").click();
  });

  $("#directDomainsBody").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-direct-domain-index]");
    if (!button) return;
    const index = Number(button.dataset.directDomainIndex);
    const current = state.settings.routingDirectDomains || [];
    state.settings.routingDirectDomains = current.filter((_, itemIndex) => itemIndex !== index);
    renderDirectDomains();
    try {
      await saveSettingsAndApply("Direct-правило удалено");
    } catch (error) {
      toast(error.message);
      await loadAll().catch(() => {});
    }
  });

  $("#settingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await saveSettingsAndApply("Настройки применены");
    } catch (error) {
      toast(error.message);
    }
  });
}

main();
