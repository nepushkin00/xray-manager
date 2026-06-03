"use strict";

const fs = require("fs");
const fsp = fs.promises;
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const path = require("path");
const { domainToASCII } = require("url");
const { execFile, execFileSync, spawn } = require("child_process");
const net = require("net");

const APP_VERSION = "1.0.0";
const PUBLIC_IP = process.env.PUBLIC_IP || "85.155.96.187";
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, "public");
const STATE_PATH = process.env.STATE_PATH || "/var/lib/xray-manager/state.json";
const SECRETS_PATH = process.env.SECRETS_PATH || "/etc/xray-manager/secrets.json";
const CREDENTIALS_PATH = process.env.CREDENTIALS_PATH || "/etc/xray-manager/credentials.txt";
const SESSION_PATH = process.env.SESSION_PATH || "/var/lib/xray-manager/sessions.json";
const CERT_DIR = process.env.CERT_DIR || "/etc/xray-manager/tls";
const ACME_WEBROOT = process.env.ACME_WEBROOT || "/var/lib/xray-manager/acme-challenge";
const XRAY_BIN = process.env.XRAY_BIN || "/opt/xray-codex/xray";
const XRAY_CONFIG = process.env.XRAY_CONFIG || "/etc/xray-codex/config.json";
const XRAY_SERVICE = process.env.XRAY_SERVICE || "xray-codex.service";
const MANAGER_MODE = process.env.MANAGER_MODE || (process.env.DOCKER_MODE === "1" ? "docker" : "systemd");
const IS_DOCKER_MODE = MANAGER_MODE === "docker";
const XRAY_CONFIG_DIR = path.dirname(XRAY_CONFIG);
const XRAY_LOG_DIR = process.env.XRAY_LOG_DIR || "/var/log/xray-codex";
const XRAY_BACKUP_DIR = process.env.XRAY_BACKUP_DIR || "/var/backups/xray-codex";
const OLD_CONFIG_PATH = process.env.OLD_CONFIG_PATH || "/home/ihelpit/.config/xray-codex/config.json";
const NODE_BIN = process.execPath;

const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 443);
const LISTEN_HOST = process.env.LISTEN_HOST || "0.0.0.0";
const DEFAULT_LATENCY_TEST_CONCURRENCY = clampNumber(process.env.LATENCY_TEST_CONCURRENCY || 6, 1, 12);
let managedXrayProcess = null;
let managedXrayStopping = false;
let bulkLatencyTestRunning = false;
let autoSwitchTaskRunning = false;

const JSON_TYPE = { "content-type": "application/json; charset=utf-8" };
const TEXT_TYPE = { "content-type": "text/plain; charset=utf-8" };
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon"
};

function nowIso() {
  return new Date().toISOString();
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function profileKey(profile) {
  const parts = [
    profile.protocol || "vless",
    profile.uuid || "",
    profile.address || "",
    profile.port || "",
    profile.network || "",
    profile.security || "",
    profile.serverName || "",
    profile.publicKey || "",
    profile.shortId || "",
    profile.path || "",
    profile.serviceName || ""
  ];
  return parts.join("|").toLowerCase();
}

function stableId(seed) {
  return `p_${sha256(seed).slice(0, 16)}`;
}

function sanitizeName(name, fallback) {
  const trimmed = String(name || "").trim();
  return trimmed.slice(0, 100) || fallback;
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function toIntPort(value, fallback = 443) {
  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return fallback;
  }
  return port;
}

function clampNumber(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, Math.round(number)));
}

function normalizeNetwork(network) {
  const raw = String(network || "tcp").toLowerCase();
  if (raw === "raw") return "tcp";
  if (["tcp", "ws", "grpc", "kcp", "httpupgrade", "xhttp"].includes(raw)) return raw;
  return "tcp";
}

function normalizeSecurity(security) {
  const raw = String(security || "none").toLowerCase();
  if (["tls", "reality", "none"].includes(raw)) return raw;
  return "none";
}

function parseVlessLink(link, defaults = {}) {
  const rawLink = String(link || "").trim();
  if (!rawLink.toLowerCase().startsWith("vless://")) {
    throw new Error("Поддерживаются только VLESS-ссылки.");
  }

  let parsed;
  try {
    parsed = new URL(rawLink);
  } catch (error) {
    throw new Error(`Некорректная VLESS-ссылка: ${error.message}`);
  }

  const params = parsed.searchParams;
  const uuid = parsed.username ? safeDecodeURIComponent(parsed.username) : "";
  if (!uuid) throw new Error("В VLESS-ссылке не найден UUID.");

  const address = parsed.hostname.replace(/^\[/, "").replace(/\]$/, "");
  if (!address) throw new Error("В VLESS-ссылке не найден адрес сервера.");

  const port = toIntPort(parsed.port || params.get("port"), 443);
  const network = normalizeNetwork(params.get("type") || params.get("network") || "tcp");
  const security = normalizeSecurity(params.get("security") || "none");
  const hashName = parsed.hash ? safeDecodeURIComponent(parsed.hash.slice(1)) : "";
  const name = sanitizeName(hashName, `${address}:${port}`);

  const profile = {
    id: stableId(`${uuid}@${address}:${port}|${rawLink}`),
    protocol: "vless",
    name,
    group: sanitizeName(defaults.group, "MAIN"),
    source: defaults.source || "manual",
    sourceId: defaults.sourceId || null,
    address,
    port,
    uuid,
    encryption: params.get("encryption") || "none",
    flow: params.get("flow") || "",
    network,
    security,
    serverName: params.get("sni") || params.get("servername") || params.get("serverName") || params.get("peer") || "",
    fingerprint: params.get("fp") || params.get("fingerprint") || "chrome",
    publicKey: params.get("pbk") || params.get("publicKey") || "",
    shortId: params.get("sid") || params.get("shortId") || "",
    spiderX: params.get("spx") || params.get("spiderX") || "",
    mldsa65Verify: params.get("mldsa65Verify") || "",
    alpn: params.get("alpn") || "",
    allowInsecure: ["1", "true", "yes"].includes(String(params.get("allowInsecure") || "").toLowerCase()),
    host: params.get("host") || "",
    path: params.get("path") || "",
    serviceName: params.get("serviceName") || "",
    mode: params.get("mode") || "",
    rawLink,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    delayMs: null,
    lastTestAt: null,
    lastTestError: null,
    autoSwitchExcluded: false
  };

  profile.key = profileKey(profile);
  return profile;
}

function isLikelyBase64(text) {
  const compact = String(text || "").replace(/\s+/g, "");
  if (!compact || compact.includes("://")) return false;
  return /^[A-Za-z0-9+/=_-]+$/.test(compact) && compact.length % 4 !== 1;
}

function decodeSubscriptionText(text) {
  const raw = String(text || "").trim();
  if (!raw) return "";
  if (!isLikelyBase64(raw)) return raw;
  const compact = raw.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = compact.padEnd(compact.length + ((4 - compact.length % 4) % 4), "=");
  try {
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    return decoded.includes("://") ? decoded : raw;
  } catch {
    return raw;
  }
}

function extractLinks(text) {
  const decoded = decodeSubscriptionText(text);
  return decoded
    .split(/[\r\n\t ]+/)
    .map((item) => item.trim())
    .filter((item) => item.toLowerCase().startsWith("vless://"));
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeDirectDomainRule(input) {
  const raw = String(input || "").trim();
  if (!raw) return null;
  const lower = raw.toLowerCase();
  if (/^(domain|regexp|full|geosite):/i.test(raw)) return raw;

  let value = lower;
  if (/^https?:\/\//i.test(value)) {
    try {
      value = new URL(value).hostname;
    } catch {
      return null;
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
  const ascii = domainToASCII(value);
  if (!ascii || ascii === "*" || !/^[a-z0-9.-]+$/.test(ascii) || ascii.includes("..")) return null;
  return wildcard ? `*.${ascii}` : ascii;
}

function normalizeDirectDomainRules(values) {
  const seen = new Set();
  const rules = [];
  for (const value of Array.isArray(values) ? values : []) {
    const rule = normalizeDirectDomainRule(value);
    if (!rule) continue;
    const key = rule.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    rules.push(rule);
  }
  return rules.slice(0, 500);
}

function directDomainMatchers(values) {
  const matchers = [];
  for (const rule of normalizeDirectDomainRules(values)) {
    if (/^(domain|regexp|full|geosite):/i.test(rule)) {
      matchers.push(rule);
      continue;
    }
    const suffix = rule.startsWith("*.") ? rule.slice(2) : rule;
    matchers.push(`regexp:(^|.*\\.)${escapeRegex(suffix)}$`);
  }
  return matchers;
}

function defaultState() {
  return {
    version: 1,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    activeProfileId: null,
    activeProfileKey: null,
    profiles: [],
    subscriptions: [],
    settings: {
      publicIp: PUBLIC_IP,
      loglevel: "warning",
      routingMode: "global",
      domainStrategy: "AsIs",
      routingDirectDomains: [],
      mux: { enabled: false, concurrency: -1 },
      mixed: {
        tag: "mixed",
        listen: "127.0.0.1",
        port: 10808,
        udp: true,
        auth: false,
        user: "",
        pass: "",
        sniffing: true,
        destOverride: ["http", "tls"],
        routeOnly: false,
        externalAllowedCidrs: []
      },
      speedTest: {
        url: "https://www.gstatic.com/generate_204",
        timeoutSeconds: 15
      },
      autoSwitch: {
        enabled: false,
        intervalMinutes: 60,
        refreshSubscriptions: true,
        testProfiles: true,
        failoverEnabled: true,
        failoverIntervalSeconds: 60,
        failoverFailures: 2,
        failoverConsecutiveFailures: 0,
        maxDelayMs: 0,
        lastRunAt: null,
        lastRunStatus: null,
        lastRunError: null,
        lastFailoverAt: null,
        lastFailoverStatus: null,
        lastFailoverError: null,
        lastSelectedProfileId: null
      },
      security: {
        clientAllowCidrs: [],
        cookieTtlHours: 12
      }
    }
  };
}

async function ensureDir(dir, mode = 0o755) {
  await fsp.mkdir(dir, { recursive: true, mode });
}

async function readJson(file, fallback = null) {
  try {
    return JSON.parse(await fsp.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJsonAtomic(file, value, mode = 0o600) {
  await ensureDir(path.dirname(file), 0o755);
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fsp.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await fsp.rename(tmp, file);
  await fsp.chmod(file, mode);
}

async function writeTextAtomic(file, value, mode = 0o600) {
  await ensureDir(path.dirname(file), 0o755);
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fsp.writeFile(tmp, value, { mode });
  await fsp.rename(tmp, file);
  await fsp.chmod(file, mode);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

function verifyPassword(password, encoded) {
  const parts = String(encoded || "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nRaw, rRaw, pRaw, saltRaw, keyRaw] = parts;
  const salt = Buffer.from(saltRaw, "base64url");
  const expected = Buffer.from(keyRaw, "base64url");
  const actual = crypto.scryptSync(String(password), salt, expected.length, {
    N: Number(nRaw),
    r: Number(rRaw),
    p: Number(pRaw)
  });
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

async function ensureSecrets() {
  const existing = await readJson(SECRETS_PATH, null);
  if (existing?.admin?.passwordHash && existing?.sessionSecret) {
    return existing;
  }

  const adminPassword = randomToken(18);
  const proxyPassword = randomToken(18);
  const secrets = {
    createdAt: nowIso(),
    admin: {
      username: "admin",
      passwordHash: hashPassword(adminPassword)
    },
    proxy: {
      username: "xproxy",
      password: proxyPassword
    },
    sessionSecret: randomToken(48)
  };

  await writeJsonAtomic(SECRETS_PATH, secrets, 0o600);
  await writeTextAtomic(
    CREDENTIALS_PATH,
    [
      "Xray Manager credentials",
      `URL: https://${PUBLIC_IP}/`,
      `UI username: ${secrets.admin.username}`,
      `UI password: ${adminPassword}`,
      `Mixed proxy username: ${secrets.proxy.username}`,
      `Mixed proxy password: ${proxyPassword}`,
      "",
      "The UI password is stored as a hash in secrets.json. Keep this file private."
    ].join("\n"),
    0o600
  );

  return secrets;
}

function profileToLink(profile) {
  const params = new URLSearchParams();
  params.set("encryption", profile.encryption || "none");
  if (profile.flow) params.set("flow", profile.flow);
  params.set("type", profile.network || "tcp");
  if (profile.security && profile.security !== "none") params.set("security", profile.security);
  if (profile.serverName) params.set("sni", profile.serverName);
  if (profile.fingerprint) params.set("fp", profile.fingerprint);
  if (profile.publicKey) params.set("pbk", profile.publicKey);
  if (profile.shortId) params.set("sid", profile.shortId);
  if (profile.spiderX) params.set("spx", profile.spiderX);
  if (profile.alpn) params.set("alpn", profile.alpn);
  if (profile.host) params.set("host", profile.host);
  if (profile.path) params.set("path", profile.path);
  if (profile.serviceName) params.set("serviceName", profile.serviceName);
  if (profile.allowInsecure) params.set("allowInsecure", "true");
  return `vless://${profile.uuid}@${profile.address}:${profile.port}?${params.toString()}#${encodeURIComponent(profile.name || profile.address)}`;
}

function importProfilesFromXrayConfig(config) {
  const profiles = [];
  let activeTag = null;
  const rules = config?.routing?.rules || [];
  for (const rule of rules) {
    if (Array.isArray(rule.inboundTag) && rule.outboundTag) {
      activeTag = rule.outboundTag;
    }
  }

  for (const outbound of config?.outbounds || []) {
    if (outbound?.protocol !== "vless") continue;
    const vnext = outbound.settings?.vnext?.[0];
    const user = vnext?.users?.[0];
    if (!vnext || !user) continue;
    const stream = outbound.streamSettings || {};
    const reality = stream.realitySettings || {};
    const tls = stream.tlsSettings || {};
    const name = outbound.tag ? outbound.tag.replace(/^proxy-/, "") : vnext.address;
    const profile = {
      id: stableId(outbound.tag || `${user.id}@${vnext.address}:${vnext.port}`),
      protocol: "vless",
      name: sanitizeName(name, `${vnext.address}:${vnext.port}`),
      group: "MAIN",
      source: "imported",
      sourceId: null,
      address: vnext.address,
      port: toIntPort(vnext.port, 443),
      uuid: user.id,
      encryption: user.encryption || "none",
      flow: user.flow || "",
      network: normalizeNetwork(stream.network || "tcp"),
      security: normalizeSecurity(stream.security || "none"),
      serverName: reality.serverName || tls.serverName || "",
      fingerprint: reality.fingerprint || tls.fingerprint || "chrome",
      publicKey: reality.publicKey || "",
      shortId: reality.shortId || "",
      spiderX: reality.spiderX || "",
      mldsa65Verify: reality.mldsa65Verify || "",
      alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : "",
      allowInsecure: Boolean(tls.allowInsecure),
      host: stream.wsSettings?.headers?.Host || "",
      path: stream.wsSettings?.path || stream.httpupgradeSettings?.path || "",
      serviceName: stream.grpcSettings?.serviceName || "",
      mode: "",
      rawLink: "",
      createdAt: nowIso(),
      updatedAt: nowIso(),
      delayMs: null,
      lastTestAt: null,
      lastTestError: null,
      autoSwitchExcluded: false
    };
    profile.rawLink = profileToLink(profile);
    profile.key = profileKey(profile);
    profile.originalTag = outbound.tag || null;
    profiles.push(profile);
  }

  const active = profiles.find((profile) => profile.originalTag === activeTag) || profiles[0] || null;
  for (const profile of profiles) delete profile.originalTag;
  return { profiles, activeProfileId: active?.id || null };
}

async function loadState() {
  const state = await readJson(STATE_PATH, null);
  if (state) {
    const merged = mergeState(defaultState(), state);
    normalizeActiveProfile(merged);
    return merged;
  }

  const fresh = defaultState();
  const oldConfig = await readJson(OLD_CONFIG_PATH, null);
  if (oldConfig) {
    const imported = importProfilesFromXrayConfig(oldConfig);
    fresh.profiles = imported.profiles;
    fresh.activeProfileId = imported.activeProfileId;
  }
  await saveState(fresh);
  return fresh;
}

function mergeState(base, override) {
  const merged = { ...base, ...override };
  merged.settings = {
    ...base.settings,
    ...(override.settings || {}),
    mixed: { ...base.settings.mixed, ...(override.settings?.mixed || {}) },
    mux: { ...base.settings.mux, ...(override.settings?.mux || {}) },
    speedTest: { ...base.settings.speedTest, ...(override.settings?.speedTest || {}) },
    autoSwitch: { ...base.settings.autoSwitch, ...(override.settings?.autoSwitch || {}) },
    security: { ...base.settings.security, ...(override.settings?.security || {}) }
  };
  merged.profiles = Array.isArray(override.profiles) ? override.profiles : [];
  merged.subscriptions = Array.isArray(override.subscriptions) ? override.subscriptions : [];
  return merged;
}

function normalizeActiveProfile(state) {
  for (const profile of state.profiles) {
    profile.key = profileKey(profile);
  }

  const activeById = state.activeProfileId
    ? state.profiles.find((profile) => profile.id === state.activeProfileId)
    : null;
  if (activeById) {
    state.activeProfileKey = activeById.key;
    return activeById;
  }

  const activeByKey = state.activeProfileKey
    ? state.profiles.find((profile) => profile.key === state.activeProfileKey)
    : null;
  if (activeByKey) {
    state.activeProfileId = activeByKey.id;
    state.activeProfileKey = activeByKey.key;
    return activeByKey;
  }

  state.activeProfileId = null;
  state.activeProfileKey = null;
  return null;
}

function setActiveProfile(state, profile) {
  if (!profile) {
    state.activeProfileId = null;
    state.activeProfileKey = null;
    return null;
  }
  profile.key = profileKey(profile);
  state.activeProfileId = profile.id;
  state.activeProfileKey = profile.key;
  return profile;
}

function fastestProfile(state) {
  const maxDelayMs = Number(state.settings?.autoSwitch?.maxDelayMs || 0);
  const candidates = state.profiles
    .filter((profile) => !profile.autoSwitchExcluded)
    .filter((profile) => Number.isFinite(Number(profile.delayMs)) && Number(profile.delayMs) >= 0 && !profile.lastTestError)
    .filter((profile) => maxDelayMs <= 0 || Number(profile.delayMs) <= maxDelayMs)
    .sort((left, right) => Number(left.delayMs) - Number(right.delayMs));
  return candidates[0] || null;
}

async function activateFastestProfile(state, apply = true) {
  const profile = fastestProfile(state);
  if (!profile) return null;
  setActiveProfile(state, profile);
  await saveState(state);
  if (apply) await writeAndApplyXrayConfig(state, true);
  return profile;
}

async function saveState(state) {
  state.updatedAt = nowIso();
  normalizeActiveProfile(state);
  await writeJsonAtomic(STATE_PATH, state, 0o600);
}

function buildStreamSettings(profile) {
  const stream = {
    network: normalizeNetwork(profile.network),
    security: normalizeSecurity(profile.security)
  };

  if (stream.security === "reality") {
    stream.realitySettings = {
      serverName: profile.serverName || profile.address,
      fingerprint: profile.fingerprint || "chrome",
      show: false,
      publicKey: profile.publicKey || "",
      shortId: profile.shortId || "",
      spiderX: profile.spiderX || "",
      mldsa65Verify: profile.mldsa65Verify || ""
    };
  } else if (stream.security === "tls") {
    stream.tlsSettings = {
      serverName: profile.serverName || profile.address,
      allowInsecure: Boolean(profile.allowInsecure)
    };
    if (profile.fingerprint) stream.tlsSettings.fingerprint = profile.fingerprint;
    if (profile.alpn) stream.tlsSettings.alpn = profile.alpn.split(",").map((item) => item.trim()).filter(Boolean);
  }

  if (stream.network === "ws") {
    stream.wsSettings = { path: profile.path || "/" };
    if (profile.host) stream.wsSettings.headers = { Host: profile.host };
  }

  if (stream.network === "grpc") {
    stream.grpcSettings = {
      serviceName: profile.serviceName || "",
      multiMode: profile.mode === "multi"
    };
  }

  if (stream.network === "httpupgrade") {
    stream.httpupgradeSettings = { path: profile.path || "/" };
    if (profile.host) stream.httpupgradeSettings.host = profile.host;
  }

  if (stream.network === "xhttp") {
    stream.xhttpSettings = { path: profile.path || "/" };
    if (profile.host) stream.xhttpSettings.host = profile.host;
    if (profile.mode) stream.xhttpSettings.mode = profile.mode;
  }

  return stream;
}

function buildVlessOutbound(profile, tag = "proxy", settings = {}) {
  const user = {
    id: profile.uuid,
    email: `${tag}@xray-manager.local`,
    security: "auto",
    encryption: profile.encryption || "none"
  };
  if (profile.flow) user.flow = profile.flow;

  return {
    tag,
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: profile.address,
          port: toIntPort(profile.port, 443),
          users: [user]
        }
      ]
    },
    streamSettings: buildStreamSettings(profile),
    mux: {
      enabled: Boolean(settings.mux?.enabled),
      concurrency: Number.isInteger(settings.mux?.concurrency) ? settings.mux.concurrency : -1
    }
  };
}

function buildRouting(settings, hasProxy) {
  const mode = settings.routingMode || "global";
  const inboundTag = [settings.mixed?.tag || "mixed"];
  const domainStrategy = mode === "bypass-ru" ? "IPIfNonMatch" : (settings.domainStrategy || "AsIs");
  const rules = [];
  const customDirectDomains = directDomainMatchers(settings.routingDirectDomains);

  if (customDirectDomains.length) {
    rules.push({ type: "field", domain: customDirectDomains, outboundTag: "direct" });
  }

  if (!hasProxy || mode === "direct") {
    rules.push({ type: "field", inboundTag, outboundTag: "direct" });
  } else if (mode === "block") {
    rules.push({ type: "field", inboundTag, outboundTag: "block" });
  } else if (mode === "bypass-private") {
    rules.push({ type: "field", ip: ["geoip:private"], outboundTag: "direct" });
    rules.push({ type: "field", domain: ["geosite:private"], outboundTag: "direct" });
    rules.push({ type: "field", inboundTag, outboundTag: "proxy" });
  } else if (mode === "bypass-ru") {
    rules.push({ type: "field", ip: ["geoip:private"], outboundTag: "direct" });
    rules.push({
      type: "field",
      domain: ["geosite:private", "geosite:category-ru", "regexp:.*\\.ru$", "regexp:.*\\.xn--p1ai$"],
      outboundTag: "direct"
    });
    rules.push({ type: "field", ip: ["geoip:ru"], outboundTag: "direct" });
    rules.push({ type: "field", inboundTag, outboundTag: "proxy" });
  } else {
    rules.push({ type: "field", inboundTag, outboundTag: "proxy" });
  }

  return {
    domainStrategy,
    rules
  };
}

function generateXrayConfig(state, options = {}) {
  const settings = mergeState(defaultState(), state).settings;
  const activeProfile = options.profile || normalizeActiveProfile(state);
  const mixed = { ...defaultState().settings.mixed, ...(settings.mixed || {}) };
  const loglevel = settings.loglevel || "warning";
  const hasProxy = Boolean(activeProfile);
  const inbounds = [
    {
      tag: options.inboundTag || mixed.tag || "mixed",
      listen: options.listen || mixed.listen || "127.0.0.1",
      port: options.port || toIntPort(mixed.port, 10808),
      protocol: "socks",
      sniffing: {
        enabled: Boolean(mixed.sniffing),
        destOverride: Array.isArray(mixed.destOverride) ? mixed.destOverride : ["http", "tls"],
        routeOnly: Boolean(mixed.routeOnly)
      },
      settings: {
        auth: mixed.auth ? "password" : "noauth",
        udp: Boolean(mixed.udp)
      }
    }
  ];

  if (mixed.auth) {
    inbounds[0].settings.users = [
      {
        user: mixed.user || "xproxy",
        pass: mixed.pass || ""
      }
    ];
  }

  const outbounds = [];
  if (activeProfile) {
    outbounds.push(buildVlessOutbound(activeProfile, "proxy", settings));
  }
  outbounds.push({ tag: "direct", protocol: "freedom" });
  outbounds.push({ tag: "block", protocol: "blackhole" });

  return {
    log: {
      access: path.join(XRAY_LOG_DIR, "access.log"),
      error: path.join(XRAY_LOG_DIR, "error.log"),
      loglevel
    },
    inbounds,
    outbounds,
    routing: buildRouting(settings, hasProxy)
  };
}

function execFileP(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 30000, maxBuffer: 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function waitForTcp(host, port, timeoutMs = 6000) {
  const connectHost = !host || host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect({ host: connectHost, port, timeout: 500 });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("timeout", () => {
        socket.destroy();
      });
      socket.once("error", () => {});
      socket.once("close", () => {
        if (Date.now() > deadline) {
          reject(new Error(`Timed out waiting for ${connectHost}:${port}`));
          return;
        }
        setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

function xrayEnvironment() {
  return { ...process.env, XRAY_LOCATION_ASSET: path.dirname(XRAY_BIN) };
}

async function validateXrayConfig(configPath) {
  return execFileP(XRAY_BIN, ["run", "-test", "-format", "json", "-c", configPath], {
    env: xrayEnvironment()
  });
}

async function stopManagedXray() {
  const child = managedXrayProcess;
  if (!child || child.killed) return;
  managedXrayStopping = true;
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, 3000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
  managedXrayProcess = null;
  managedXrayStopping = false;
}

async function startManagedXray(state) {
  if (!IS_DOCKER_MODE) return;
  if (managedXrayProcess && !managedXrayProcess.killed) return;
  managedXrayStopping = false;
  const child = spawn(XRAY_BIN, ["run", "-c", XRAY_CONFIG], {
    env: xrayEnvironment(),
    stdio: ["ignore", "inherit", "inherit"]
  });
  managedXrayProcess = child;
  child.once("exit", (code, signal) => {
    if (managedXrayProcess === child) managedXrayProcess = null;
    if (!managedXrayStopping) {
      console.error(`managed xray exited: code=${code ?? ""} signal=${signal ?? ""}`);
      setTimeout(async () => {
        try {
          const latestState = await loadState();
          await startManagedXray(latestState);
        } catch (error) {
          console.error(`managed xray restart failed: ${error.message}`);
        }
      }, 2000).unref();
    }
  });

  const mixed = state.settings?.mixed || defaultState().settings.mixed;
  await waitForTcp(mixed.listen, toIntPort(mixed.port, 10808), 8000);
}

async function restartXray(state) {
  if (IS_DOCKER_MODE) {
    await stopManagedXray();
    await startManagedXray(state);
    return;
  }
  await execFileP("systemctl", ["restart", XRAY_SERVICE], { timeout: 30000 });
}

async function applyXrayPermissions() {
  if (IS_DOCKER_MODE) return;
  try {
    const uid = Number(execFileSync("id", ["-u", "xray-codex"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
    const gid = Number(execFileSync("id", ["-g", "xray-codex"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
    await fsp.chown(XRAY_CONFIG_DIR, 0, gid).catch(() => {});
    await fsp.chmod(XRAY_CONFIG_DIR, 0o750).catch(() => {});
    await fsp.chown(XRAY_CONFIG, 0, gid).catch(() => {});
    await fsp.chmod(XRAY_CONFIG, 0o640).catch(() => {});
    await fsp.chown(XRAY_LOG_DIR, uid, gid).catch(() => {});
    await fsp.chmod(XRAY_LOG_DIR, 0o750).catch(() => {});
  } catch {
    // Unit tests and non-system installs may not have the service account yet.
  }
}

async function writeAndApplyXrayConfig(state, restart = true) {
  await ensureDir(XRAY_CONFIG_DIR, 0o750);
  await ensureDir(XRAY_LOG_DIR, 0o750);
  await ensureDir(XRAY_BACKUP_DIR, 0o750);

  const nextConfig = generateXrayConfig(state);
  const tmp = path.join(XRAY_CONFIG_DIR, `config-${process.pid}-${Date.now()}.json`);
  await fsp.writeFile(tmp, `${JSON.stringify(nextConfig, null, 2)}\n`, { mode: 0o640 });
  await validateXrayConfig(tmp);

  try {
    await fsp.access(XRAY_CONFIG);
    const backup = path.join(XRAY_BACKUP_DIR, `config-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    await fsp.copyFile(XRAY_CONFIG, backup);
    await fsp.chmod(backup, 0o640);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  await fsp.rename(tmp, XRAY_CONFIG);
  await applyXrayPermissions();
  if (restart) {
    await restartXray(state);
    const mixed = state.settings?.mixed || defaultState().settings.mixed;
    await waitForTcp(mixed.listen, toIntPort(mixed.port, 10808));
  }
  return nextConfig;
}

async function ensureSelfSignedCert() {
  await ensureDir(CERT_DIR, 0o700);
  const certPath = path.join(CERT_DIR, "selfsigned.crt");
  const keyPath = path.join(CERT_DIR, "selfsigned.key");
  try {
    await Promise.all([fsp.access(certPath), fsp.access(keyPath)]);
    return { certPath, keyPath };
  } catch {
    execFileSync("openssl", [
      "req",
      "-x509",
      "-nodes",
      "-newkey",
      "rsa:2048",
      "-days",
      "30",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-subj",
      `/CN=${PUBLIC_IP}`,
      "-addext",
      `subjectAltName=IP:${PUBLIC_IP}`
    ], { stdio: "ignore" });
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(certPath, 0o644);
    return { certPath, keyPath };
  }
}

function getTlsFiles() {
  const leCert = `/etc/letsencrypt/live/${PUBLIC_IP}/fullchain.pem`;
  const leKey = `/etc/letsencrypt/live/${PUBLIC_IP}/privkey.pem`;
  if (fs.existsSync(leCert) && fs.existsSync(leKey)) {
    return { certPath: leCert, keyPath: leKey, source: "letsencrypt" };
  }
  const certPath = path.join(CERT_DIR, "selfsigned.crt");
  const keyPath = path.join(CERT_DIR, "selfsigned.key");
  return { certPath, keyPath, source: "selfsigned" };
}

async function readRequestBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 5 * 1024 * 1024) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  const type = req.headers["content-type"] || "";
  if (type.includes("application/json")) return JSON.parse(text);
  return { text };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, `${JSON.stringify(value)}\n`, JSON_TYPE);
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || "";
  const cookies = {};
  for (const item of cookieHeader.split(";")) {
    const index = item.indexOf("=");
    if (index === -1) continue;
    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();
    cookies[key] = value;
  }
  return cookies;
}

function clientIp(req) {
  const raw = req.socket.remoteAddress || "";
  return raw.startsWith("::ffff:") ? raw.slice(7) : raw;
}

function ipv4ToInt(ip) {
  const parts = String(ip).split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function cidrContains(cidr, ip) {
  if (!cidr) return false;
  if (!cidr.includes("/")) return cidr === ip;
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const baseInt = ipv4ToInt(base);
  const ipInt = ipv4ToInt(ip);
  if (baseInt === null || ipInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (baseInt & mask) === (ipInt & mask);
}

function isAllowedByCidrs(ip, cidrs) {
  if (!Array.isArray(cidrs) || cidrs.length === 0) return true;
  return cidrs.some((cidr) => cidrContains(cidr, ip));
}

class SessionStore {
  constructor(file, secret) {
    this.file = file;
    this.secret = secret || randomToken(32);
    this.sessions = new Map();
    this.load();
  }

  key(id) {
    return crypto.createHmac("sha256", this.secret).update(String(id || "")).digest("hex");
  }

  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.file, "utf8"));
      this.sessions = new Map(Object.entries(data.sessions || {}));
      this.prune(false);
    } catch {
      this.sessions = new Map();
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      const tmp = `${this.file}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, `${JSON.stringify({ updatedAt: nowIso(), sessions: Object.fromEntries(this.sessions) }, null, 2)}\n`, { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      fs.chmodSync(this.file, 0o600);
    } catch (error) {
      console.error(`Failed to persist sessions: ${error.message}`);
    }
  }

  prune(save = true) {
    const now = Date.now();
    let changed = false;
    for (const [key, session] of this.sessions) {
      if (!session || session.expiresAt < now) {
        this.sessions.delete(key);
        changed = true;
      }
    }
    if (changed && save) this.persist();
  }

  create(username, hours = 12, remember = false) {
    const id = randomToken(32);
    const csrf = randomToken(24);
    const expiresAt = Date.now() + hours * 60 * 60 * 1000;
    this.sessions.set(this.key(id), { username, csrf, expiresAt, remember: Boolean(remember), createdAt: nowIso() });
    this.persist();
    return { id, csrf, expiresAt };
  }

  get(id) {
    const session = this.sessions.get(this.key(id));
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(this.key(id));
      this.persist();
      return null;
    }
    return session;
  }

  delete(id) {
    this.sessions.delete(this.key(id));
    this.persist();
  }
}

async function tailFile(file, maxBytes = 50000) {
  try {
    const stat = await fsp.stat(file);
    const start = Math.max(0, stat.size - maxBytes);
    const handle = await fsp.open(file, "r");
    try {
      const buffer = Buffer.alloc(stat.size - start);
      await handle.read(buffer, 0, buffer.length, start);
      return buffer.toString("utf8");
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error.code === "ENOENT") return "";
    throw error;
  }
}

async function serviceStatus() {
  const result = {};
  if (IS_DOCKER_MODE) {
    result.active = managedXrayProcess && !managedXrayProcess.killed ? "active" : "inactive";
    result.enabled = "managed";
    result.mode = MANAGER_MODE;
    result.pid = managedXrayProcess?.pid || null;
    try {
      result.version = (await execFileP(XRAY_BIN, ["version"])).stdout.split("\n")[0].trim();
    } catch {
      result.version = "unknown";
    }
    return result;
  }
  try {
    result.active = (await execFileP("systemctl", ["is-active", XRAY_SERVICE])).stdout.trim();
  } catch (error) {
    result.active = "unknown";
    result.error = (error.stderr || error.message || "").trim();
  }
  try {
    result.enabled = (await execFileP("systemctl", ["is-enabled", XRAY_SERVICE])).stdout.trim();
  } catch {
    result.enabled = "unknown";
  }
  try {
    result.version = (await execFileP(XRAY_BIN, ["version"])).stdout.split("\n")[0].trim();
  } catch {
    result.version = "unknown";
  }
  return result;
}

async function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

async function runDelayTest(state, profile) {
  const port = await findFreePort();
  const tempDir = "/run/xray-manager";
  await ensureDir(tempDir, 0o700);
  const tempConfig = path.join(tempDir, `speedtest-${profile.id}-${Date.now()}.json`);
  const testState = mergeState(defaultState(), {
    ...state,
    activeProfileId: profile.id,
    profiles: [profile],
    settings: {
      ...state.settings,
      routingMode: "global",
      mixed: {
        ...state.settings.mixed,
        listen: "127.0.0.1",
        port,
        auth: false
      }
    }
  });

  await fsp.writeFile(tempConfig, `${JSON.stringify(generateXrayConfig(testState), null, 2)}\n`, { mode: 0o600 });
  await validateXrayConfig(tempConfig);

  const child = spawn(XRAY_BIN, ["run", "-c", tempConfig], {
    env: { ...process.env, XRAY_LOCATION_ASSET: path.dirname(XRAY_BIN) },
    stdio: ["ignore", "ignore", "ignore"]
  });

  await new Promise((resolve) => setTimeout(resolve, 900));
  const url = state.settings.speedTest?.url || "https://www.gstatic.com/generate_204";
  const timeout = String(state.settings.speedTest?.timeoutSeconds || 15);
  try {
    const start = Date.now();
    await execFileP("curl", [
      "-fsS",
      "--socks5-hostname",
      `127.0.0.1:${port}`,
      "--connect-timeout",
      "8",
      "--max-time",
      timeout,
      "-o",
      "/dev/null",
      url
    ], { timeout: (Number(timeout) + 5) * 1000 });
    return { delayMs: Date.now() - start, error: null };
  } catch (error) {
    return { delayMs: null, error: (error.stderr || error.message || "delay test failed").trim().slice(0, 400) };
  } finally {
    child.kill("SIGTERM");
    setTimeout(() => child.kill("SIGKILL"), 1500).unref();
    fsp.unlink(tempConfig).catch(() => {});
  }
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const workerCount = Math.min(items.length, concurrency);
  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }));
  return results;
}

function applyLatencyResult(profile, result) {
  profile.delayMs = result.delayMs;
  profile.lastTestAt = nowIso();
  profile.lastTestError = result.error;
}

async function testProfilesConcurrently(state, profiles, concurrency = DEFAULT_LATENCY_TEST_CONCURRENCY) {
  const width = clampNumber(concurrency, 1, 12);
  const results = await mapWithConcurrency(profiles, width, async (profile) => {
    const result = await runDelayTest(state, profile);
    applyLatencyResult(profile, result);
    return {
      id: profile.id,
      name: profile.name,
      delayMs: result.delayMs,
      error: result.error
    };
  });
  await saveState(state);
  return results;
}

function mergeProfiles(existingProfiles, incomingProfiles, options = {}) {
  const byKey = new Map(existingProfiles.map((profile) => [profile.key || profileKey(profile), profile]));
  let added = 0;
  let updated = 0;
  const profiles = [...existingProfiles];

  for (const incoming of incomingProfiles) {
    const key = incoming.key || profileKey(incoming);
    const existing = byKey.get(key);
    if (existing) {
      Object.assign(existing, {
        ...incoming,
        id: existing.id,
        name: options.keepNames ? existing.name : incoming.name,
        createdAt: existing.createdAt || incoming.createdAt,
        updatedAt: nowIso(),
        delayMs: existing.delayMs ?? null,
        lastTestAt: existing.lastTestAt ?? null,
        lastTestError: existing.lastTestError ?? null,
        autoSwitchExcluded: Boolean(existing.autoSwitchExcluded)
      });
      updated += 1;
    } else {
      profiles.push(incoming);
      byKey.set(key, incoming);
      added += 1;
    }
  }

  return { profiles, added, updated };
}

async function refreshSubscription(state, subscriptionId) {
  const sub = state.subscriptions.find((item) => item.id === subscriptionId);
  if (!sub) throw new Error("Subscription not found.");
  const response = await fetch(sub.url, {
    redirect: "follow",
    headers: { "user-agent": `xray-manager/${APP_VERSION}` }
  });
  if (!response.ok) {
    throw new Error(`Subscription fetch failed: HTTP ${response.status}`);
  }
  const body = await response.text();
  const links = extractLinks(body);
  const profiles = links.map((link) => parseVlessLink(link, {
    group: sub.group || sub.name || "import_sub",
    source: "subscription",
    sourceId: sub.id
  }));
  const merged = mergeProfiles(state.profiles, profiles, { keepNames: false });
  state.profiles = merged.profiles;
  sub.lastUpdateAt = nowIso();
  sub.lastUpdateStatus = `ok: ${merged.added} added, ${merged.updated} updated`;
  sub.lastUpdateError = null;
  await saveState(state);
  return { ...merged, totalLinks: links.length };
}

async function refreshAllSubscriptions(state) {
  const results = [];
  for (const sub of [...state.subscriptions]) {
    try {
      const result = await refreshSubscription(state, sub.id);
      results.push({ id: sub.id, ok: true, ...result });
    } catch (error) {
      const current = state.subscriptions.find((item) => item.id === sub.id);
      if (current) {
        current.lastUpdateAt = nowIso();
        current.lastUpdateStatus = "error";
        current.lastUpdateError = error.message;
        await saveState(state);
      }
      results.push({ id: sub.id, ok: false, error: error.message });
    }
  }
  return results;
}

function autoSwitchIntervalMs(settings) {
  if (!settings?.autoSwitch?.enabled) return 0;
  const minutes = clampNumber(settings.autoSwitch.intervalMinutes || 0, 0, 1440);
  return minutes > 0 ? minutes * 60 * 1000 : 0;
}

function failoverIntervalMs(settings) {
  if (!settings?.autoSwitch?.enabled || !settings.autoSwitch.failoverEnabled) return 0;
  const seconds = clampNumber(settings.autoSwitch.failoverIntervalSeconds || 60, 10, 3600);
  return seconds * 1000;
}

async function runAutoSwitchCycle(reason = "manual", options = {}) {
  if (autoSwitchTaskRunning) return { ok: false, skipped: true, reason: "already-running" };
  if (bulkLatencyTestRunning) {
    const state = await loadState();
    state.settings.autoSwitch.lastRunAt = nowIso();
    state.settings.autoSwitch.lastRunStatus = "skipped: latency check running";
    state.settings.autoSwitch.lastRunError = null;
    await saveState(state);
    return { ok: false, skipped: true, reason: "latency-running" };
  }

  autoSwitchTaskRunning = true;
  let state = await loadState();
  try {
    const settings = state.settings.autoSwitch || {};
    if (!settings.enabled && reason !== "manual") return { ok: false, skipped: true, reason: "disabled" };
    const refreshSubscriptions = options.refreshSubscriptions ?? settings.refreshSubscriptions;
    const testProfiles = options.testProfiles ?? settings.testProfiles;

    state.settings.autoSwitch.lastRunAt = nowIso();
    state.settings.autoSwitch.lastRunStatus = "running";
    state.settings.autoSwitch.lastRunError = null;
    await saveState(state);

    let subscriptionResults = [];
    if (refreshSubscriptions) {
      subscriptionResults = await refreshAllSubscriptions(state);
    }

    let latencyResults = [];
    if (testProfiles) {
      bulkLatencyTestRunning = true;
      try {
        latencyResults = await testProfilesConcurrently(state, state.profiles, DEFAULT_LATENCY_TEST_CONCURRENCY);
      } finally {
        bulkLatencyTestRunning = false;
      }
    }

    const selected = await activateFastestProfile(state, true);
    const failedSubs = subscriptionResults.filter((item) => !item.ok).length;
    state.settings.autoSwitch.lastRunAt = nowIso();
    state.settings.autoSwitch.lastRunStatus = selected
      ? `ok: ${selected.name || selected.address} (${selected.delayMs} ms)`
      : "ok: no candidate";
    state.settings.autoSwitch.lastRunError = failedSubs ? `subscription errors: ${failedSubs}` : null;
    state.settings.autoSwitch.lastSelectedProfileId = selected?.id || null;
    await saveState(state);

    return {
      ok: true,
      selectedProfile: selected,
      subscriptions: subscriptionResults,
      latency: {
        total: latencyResults.length,
        success: latencyResults.filter((item) => !item.error).length,
        failed: latencyResults.filter((item) => item.error).length
      },
      profiles: state.profiles
    };
  } catch (error) {
    state.settings.autoSwitch.lastRunAt = nowIso();
    state.settings.autoSwitch.lastRunStatus = "error";
    state.settings.autoSwitch.lastRunError = error.message;
    await saveState(state).catch(() => {});
    throw error;
  } finally {
    autoSwitchTaskRunning = false;
  }
}

async function runFailoverCheck() {
  if (autoSwitchTaskRunning || bulkLatencyTestRunning) return { ok: false, skipped: true, reason: "busy" };
  autoSwitchTaskRunning = true;
  let state = await loadState();
  try {
    const settings = state.settings.autoSwitch || {};
    if (!settings.enabled || !settings.failoverEnabled) return { ok: false, skipped: true, reason: "disabled" };

    const active = normalizeActiveProfile(state);
    if (!active) return { ok: false, skipped: true, reason: "no-active-profile" };

    const result = await runDelayTest(state, active);
    applyLatencyResult(active, result);

    if (!result.error) {
      state.settings.autoSwitch.failoverConsecutiveFailures = 0;
      state.settings.autoSwitch.lastFailoverAt = nowIso();
      state.settings.autoSwitch.lastFailoverStatus = `active ok: ${active.name || active.address} (${result.delayMs} ms)`;
      state.settings.autoSwitch.lastFailoverError = null;
      await saveState(state);
      return { ok: true, failed: false, activeProfile: active };
    }

    const failures = Number(state.settings.autoSwitch.failoverConsecutiveFailures || 0) + 1;
    state.settings.autoSwitch.failoverConsecutiveFailures = failures;
    state.settings.autoSwitch.lastFailoverAt = nowIso();
    state.settings.autoSwitch.lastFailoverStatus = `active failed: ${failures}/${settings.failoverFailures || 2}`;
    state.settings.autoSwitch.lastFailoverError = result.error;
    await saveState(state);

    if (failures < clampNumber(settings.failoverFailures || 2, 1, 10)) {
      return { ok: false, failed: true, switched: false, activeProfile: active };
    }
  } finally {
    autoSwitchTaskRunning = false;
  }

  const switchResult = await runAutoSwitchCycle("failover", {
    refreshSubscriptions: false,
    testProfiles: true
  });
  state = await loadState();
  state.settings.autoSwitch.failoverConsecutiveFailures = switchResult.selectedProfile ? 0 : Number(state.settings.autoSwitch.failoverConsecutiveFailures || 0);
  state.settings.autoSwitch.lastFailoverAt = nowIso();
  state.settings.autoSwitch.lastFailoverStatus = switchResult.selectedProfile
    ? `switched: ${switchResult.selectedProfile.name || switchResult.selectedProfile.address}`
    : "switch failed: no candidate";
  state.settings.autoSwitch.lastFailoverError = switchResult.selectedProfile ? null : "No eligible working profile.";
  await saveState(state);
  return { ...switchResult, failed: true, switched: Boolean(switchResult.selectedProfile) };
}

function sanitizeSettingsPatch(current, patch, secrets) {
  const next = mergeState(defaultState(), { settings: current }).settings;
  if (patch.loglevel) next.loglevel = String(patch.loglevel);
  if (patch.routingMode) next.routingMode = String(patch.routingMode);
  if (patch.domainStrategy) next.domainStrategy = String(patch.domainStrategy);
  if (Array.isArray(patch.routingDirectDomains)) next.routingDirectDomains = normalizeDirectDomainRules(patch.routingDirectDomains);
  if (patch.mux && typeof patch.mux === "object") {
    next.mux.enabled = Boolean(patch.mux.enabled);
    next.mux.concurrency = Number.isInteger(Number(patch.mux.concurrency)) ? Number(patch.mux.concurrency) : -1;
  }
  if (patch.speedTest && typeof patch.speedTest === "object") {
    if (patch.speedTest.url) next.speedTest.url = String(patch.speedTest.url);
    if (patch.speedTest.timeoutSeconds) next.speedTest.timeoutSeconds = Math.max(5, Math.min(60, Number(patch.speedTest.timeoutSeconds)));
  }
  if (patch.autoSwitch && typeof patch.autoSwitch === "object") {
    const autoSwitch = patch.autoSwitch;
    if (autoSwitch.enabled !== undefined) next.autoSwitch.enabled = Boolean(autoSwitch.enabled);
    if (autoSwitch.intervalMinutes !== undefined) next.autoSwitch.intervalMinutes = clampNumber(autoSwitch.intervalMinutes, 0, 1440);
    if (autoSwitch.refreshSubscriptions !== undefined) next.autoSwitch.refreshSubscriptions = Boolean(autoSwitch.refreshSubscriptions);
    if (autoSwitch.testProfiles !== undefined) next.autoSwitch.testProfiles = Boolean(autoSwitch.testProfiles);
    if (autoSwitch.failoverEnabled !== undefined) next.autoSwitch.failoverEnabled = Boolean(autoSwitch.failoverEnabled);
    if (autoSwitch.failoverIntervalSeconds !== undefined) next.autoSwitch.failoverIntervalSeconds = clampNumber(autoSwitch.failoverIntervalSeconds, 10, 3600);
    if (autoSwitch.failoverFailures !== undefined) next.autoSwitch.failoverFailures = clampNumber(autoSwitch.failoverFailures, 1, 10);
    if (autoSwitch.maxDelayMs !== undefined) next.autoSwitch.maxDelayMs = Math.max(0, Number(autoSwitch.maxDelayMs) || 0);
  }
  if (patch.mixed && typeof patch.mixed === "object") {
    const mixed = patch.mixed;
    if (mixed.listen !== undefined) next.mixed.listen = String(mixed.listen || "127.0.0.1");
    if (mixed.port !== undefined) next.mixed.port = toIntPort(mixed.port, 10808);
    if (mixed.udp !== undefined) next.mixed.udp = Boolean(mixed.udp);
    if (mixed.sniffing !== undefined) next.mixed.sniffing = Boolean(mixed.sniffing);
    if (mixed.routeOnly !== undefined) next.mixed.routeOnly = Boolean(mixed.routeOnly);
    if (mixed.auth !== undefined) next.mixed.auth = Boolean(mixed.auth);
    if (Array.isArray(mixed.destOverride)) next.mixed.destOverride = mixed.destOverride.map(String).filter(Boolean);
    if (Array.isArray(mixed.externalAllowedCidrs)) next.mixed.externalAllowedCidrs = mixed.externalAllowedCidrs.map(String).filter(Boolean);
    if (mixed.user !== undefined) next.mixed.user = String(mixed.user || secrets.proxy.username || "xproxy");
    if (mixed.pass !== undefined && String(mixed.pass).length > 0) {
      next.mixed.pass = String(mixed.pass);
    }
  }
  if (!next.mixed.user) next.mixed.user = secrets.proxy.username || "xproxy";
  if (!next.mixed.pass) next.mixed.pass = secrets.proxy.password || "";
  return next;
}

function publicSettings(settings) {
  const safe = clone(settings || {});
  if (safe.mixed?.pass) safe.mixed.pass = "********";
  return safe;
}

function routePattern(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  return parts;
}

function makeApp(secrets) {
  const sessions = new SessionStore(SESSION_PATH, secrets.sessionSecret);

  async function auth(req, res, state) {
    const ip = clientIp(req);
    if (!isAllowedByCidrs(ip, state.settings.security?.clientAllowCidrs || [])) {
      sendJson(res, 403, { error: "IP address is not allowed." });
      return null;
    }

    const cookies = parseCookies(req);
    const sessionId = cookies.xm_session;
    const session = sessions.get(sessionId);
    if (!session) {
      sendJson(res, 401, { error: "Authentication required." });
      return null;
    }

    if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      const csrf = req.headers["x-csrf-token"];
      if (!csrf || csrf !== session.csrf) {
        sendJson(res, 403, { error: "Bad CSRF token." });
        return null;
      }
    }

    return { sessionId, session };
  }

  async function handleApi(req, res, pathname) {
    let state = await loadState();
    const parts = routePattern(pathname);

    if (pathname === "/api/auth/login" && req.method === "POST") {
      const body = await readRequestBody(req);
      const username = String(body.username || "");
      const password = String(body.password || "");
      const remember = Boolean(body.remember);
      if (username !== secrets.admin.username || !verifyPassword(password, secrets.admin.passwordHash)) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        sendJson(res, 401, { error: "Invalid username or password." });
        return;
      }
      const sessionHours = remember ? 24 * 30 : (state.settings.security?.cookieTtlHours || 12);
      const created = sessions.create(username, sessionHours, remember);
      res.setHeader("set-cookie", [
        `xm_session=${created.id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor((created.expiresAt - Date.now()) / 1000)}`
      ]);
      sendJson(res, 200, { ok: true, username, csrf: created.csrf, remember });
      return;
    }

    const authResult = await auth(req, res, state);
    if (!authResult) return;

    if (pathname === "/api/auth/me" && req.method === "GET") {
      sendJson(res, 200, { username: authResult.session.username, csrf: authResult.session.csrf });
      return;
    }

    if (pathname === "/api/auth/logout" && req.method === "POST") {
      sessions.delete(authResult.sessionId);
      res.setHeader("set-cookie", "xm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
      sendJson(res, 200, { ok: true });
      return;
    }

    if (pathname === "/api/status" && req.method === "GET") {
      const activeProfile = normalizeActiveProfile(state);
      sendJson(res, 200, {
        appVersion: APP_VERSION,
        node: process.version,
        tls: getTlsFiles().source,
        service: await serviceStatus(),
        activeProfile,
        settings: publicSettings(state.settings),
        paths: { state: STATE_PATH, config: XRAY_CONFIG, logs: XRAY_LOG_DIR }
      });
      return;
    }

    if (pathname === "/api/profiles" && req.method === "GET") {
      normalizeActiveProfile(state);
      sendJson(res, 200, { activeProfileId: state.activeProfileId, activeProfileKey: state.activeProfileKey, profiles: state.profiles });
      return;
    }

    if (pathname === "/api/profiles/bulk-delete" && req.method === "POST") {
      const body = await readRequestBody(req);
      const ids = new Set(Array.isArray(body.ids) ? body.ids.map(String) : []);
      if (!ids.size) {
        sendJson(res, 400, { error: "No profiles selected." });
        return;
      }
      const before = state.profiles.length;
      state.profiles = state.profiles.filter((profile) => !ids.has(profile.id));
      const removed = before - state.profiles.length;
      if (state.activeProfileId && !state.profiles.some((profile) => profile.id === state.activeProfileId)) {
        setActiveProfile(state, state.profiles[0] || null);
      }
      await saveState(state);
      await writeAndApplyXrayConfig(state, true);
      sendJson(res, 200, { ok: true, removed, activeProfileId: state.activeProfileId });
      return;
    }

    if (pathname === "/api/profiles/bulk-auto-switch" && req.method === "POST") {
      const body = await readRequestBody(req);
      const ids = new Set(Array.isArray(body.ids) ? body.ids.map(String) : []);
      if (!ids.size) {
        sendJson(res, 400, { error: "No profiles selected." });
        return;
      }
      const excluded = Boolean(body.excluded);
      let updated = 0;
      for (const profile of state.profiles) {
        if (!ids.has(profile.id)) continue;
        profile.autoSwitchExcluded = excluded;
        profile.updatedAt = nowIso();
        updated += 1;
      }
      await saveState(state);
      sendJson(res, 200, { ok: true, updated, profiles: state.profiles });
      return;
    }

    if (pathname === "/api/import" && req.method === "POST") {
      const body = await readRequestBody(req);
      const links = extractLinks(body.text || body.links || "");
      const profiles = links.map((link) => parseVlessLink(link, {
        group: body.group || "MAIN",
        source: "manual"
      }));
      const merged = mergeProfiles(state.profiles, profiles, { keepNames: true });
      state.profiles = merged.profiles;
      if (!state.activeProfileId && profiles[0]) {
        const imported = state.profiles.find((profile) => profile.key === profiles[0].key) || profiles[0];
        setActiveProfile(state, imported);
      }
      await saveState(state);
      sendJson(res, 200, { ok: true, totalLinks: links.length, added: merged.added, updated: merged.updated });
      return;
    }

    if (parts[0] === "api" && parts[1] === "profiles" && parts[2]) {
      const id = parts[2];
      const profile = state.profiles.find((item) => item.id === id);
      if (!profile) {
        sendJson(res, 404, { error: "Profile not found." });
        return;
      }

      if (parts.length === 3 && req.method === "PATCH") {
        const body = await readRequestBody(req);
        const allowed = ["name", "group", "address", "port", "uuid", "encryption", "flow", "network", "security", "serverName", "fingerprint", "publicKey", "shortId", "spiderX", "alpn", "allowInsecure", "host", "path", "serviceName", "mode", "autoSwitchExcluded"];
        for (const key of allowed) {
          if (body[key] === undefined) continue;
          if (key === "port") profile[key] = toIntPort(body[key], profile.port);
          else if (key === "autoSwitchExcluded") profile[key] = Boolean(body[key]);
          else profile[key] = body[key];
        }
        profile.updatedAt = nowIso();
        profile.key = profileKey(profile);
        await saveState(state);
        sendJson(res, 200, { ok: true, profile });
        return;
      }

      if (parts.length === 3 && req.method === "DELETE") {
        state.profiles = state.profiles.filter((item) => item.id !== id);
        if (state.activeProfileId === id) setActiveProfile(state, state.profiles[0] || null);
        await saveState(state);
        await writeAndApplyXrayConfig(state, true);
        sendJson(res, 200, { ok: true });
        return;
      }

      if (parts[3] === "activate" && req.method === "POST") {
        setActiveProfile(state, profile);
        await saveState(state);
        await writeAndApplyXrayConfig(state, true);
        sendJson(res, 200, { ok: true, activeProfileId: state.activeProfileId, activeProfileKey: state.activeProfileKey });
        return;
      }
    }

    if (pathname === "/api/test-all" && req.method === "POST") {
      if (bulkLatencyTestRunning || autoSwitchTaskRunning) {
        sendJson(res, 409, { error: "Latency check is already running." });
        return;
      }
      const body = await readRequestBody(req);
      const ids = Array.isArray(body.ids) ? new Set(body.ids.map(String)) : null;
      const profiles = ids ? state.profiles.filter((profile) => ids.has(profile.id)) : state.profiles;
      if (!profiles.length) {
        sendJson(res, 400, { error: "No profiles to test." });
        return;
      }
      const concurrency = clampNumber(body.concurrency || DEFAULT_LATENCY_TEST_CONCURRENCY, 1, 12);
      bulkLatencyTestRunning = true;
      const results = await testProfilesConcurrently(state, profiles, concurrency).finally(() => {
        bulkLatencyTestRunning = false;
      });
      const selectedProfile = state.settings.autoSwitch?.enabled && body.autoSwitch !== false
        ? await activateFastestProfile(state, true)
        : null;
      sendJson(res, 200, {
        ok: true,
        total: results.length,
        success: results.filter((item) => !item.error).length,
        failed: results.filter((item) => item.error).length,
        concurrency,
        results,
        selectedProfile,
        activeProfileId: state.activeProfileId,
        activeProfileKey: state.activeProfileKey,
        profiles: state.profiles
      });
      return;
    }

    if (pathname === "/api/auto-switch/activate-fastest" && req.method === "POST") {
      const selectedProfile = await activateFastestProfile(state, true);
      if (!selectedProfile) {
        sendJson(res, 404, { error: "No eligible profile with successful latency." });
        return;
      }
      sendJson(res, 200, {
        ok: true,
        selectedProfile,
        activeProfileId: state.activeProfileId,
        activeProfileKey: state.activeProfileKey,
        profiles: state.profiles
      });
      return;
    }

    if (pathname === "/api/auto-switch/run" && req.method === "POST") {
      const result = await runAutoSwitchCycle("manual");
      sendJson(res, 200, result);
      return;
    }

    if (parts[0] === "api" && parts[1] === "test" && parts[2] && req.method === "POST") {
      const profile = state.profiles.find((item) => item.id === parts[2]);
      if (!profile) {
        sendJson(res, 404, { error: "Profile not found." });
        return;
      }
      const result = await runDelayTest(state, profile);
      applyLatencyResult(profile, result);
      await saveState(state);
      sendJson(res, result.error ? 502 : 200, { ok: !result.error, ...result, profile });
      return;
    }

    if (pathname === "/api/settings" && req.method === "GET") {
      sendJson(res, 200, { settings: publicSettings(state.settings) });
      return;
    }

    if (pathname === "/api/settings" && req.method === "PATCH") {
      const body = await readRequestBody(req);
      state.settings = sanitizeSettingsPatch(state.settings, body, secrets);
      await saveState(state);
      sendJson(res, 200, { ok: true, settings: state.settings });
      return;
    }

    if (pathname === "/api/apply" && req.method === "POST") {
      const config = await writeAndApplyXrayConfig(state, true);
      sendJson(res, 200, { ok: true, config });
      return;
    }

    if (pathname === "/api/subscriptions" && req.method === "GET") {
      sendJson(res, 200, { subscriptions: state.subscriptions });
      return;
    }

    if (pathname === "/api/subscriptions" && req.method === "POST") {
      const body = await readRequestBody(req);
      const url = String(body.url || "").trim();
      if (!/^https?:\/\//i.test(url)) throw new Error("Subscription URL must start with http:// or https://");
      const sub = {
        id: `s_${randomToken(8)}`,
        name: sanitizeName(body.name, new URL(url).hostname),
        url,
        group: sanitizeName(body.group, "import_sub"),
        createdAt: nowIso(),
        lastUpdateAt: null,
        lastUpdateStatus: null,
        lastUpdateError: null
      };
      state.subscriptions.push(sub);
      await saveState(state);
      sendJson(res, 200, { ok: true, subscription: sub });
      return;
    }

    if (parts[0] === "api" && parts[1] === "subscriptions" && parts[2]) {
      const id = parts[2];
      const sub = state.subscriptions.find((item) => item.id === id);
      if (!sub) {
        sendJson(res, 404, { error: "Subscription not found." });
        return;
      }

      if (parts[3] === "refresh" && req.method === "POST") {
        try {
          const result = await refreshSubscription(state, id);
          sendJson(res, 200, { ok: true, added: result.added, updated: result.updated, totalLinks: result.totalLinks });
        } catch (error) {
          sub.lastUpdateAt = nowIso();
          sub.lastUpdateStatus = "error";
          sub.lastUpdateError = error.message;
          await saveState(state);
          throw error;
        }
        return;
      }

      if (req.method === "DELETE") {
        state.subscriptions = state.subscriptions.filter((item) => item.id !== id);
        await saveState(state);
        sendJson(res, 200, { ok: true });
        return;
      }
    }

    if (pathname === "/api/logs" && req.method === "GET") {
      const access = await tailFile(path.join(XRAY_LOG_DIR, "access.log"));
      const error = await tailFile(path.join(XRAY_LOG_DIR, "error.log"));
      sendJson(res, 200, { access, error });
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  }

  async function serveStatic(req, res, pathname) {
    let filePath = pathname === "/" ? path.join(PUBLIC_DIR, "index.html") : path.join(PUBLIC_DIR, pathname);
    const normalized = path.normalize(filePath);
    if (!normalized.startsWith(PUBLIC_DIR)) {
      send(res, 403, "Forbidden", TEXT_TYPE);
      return;
    }
    try {
      const data = await fsp.readFile(normalized);
      send(res, 200, data, { "content-type": MIME_TYPES[path.extname(normalized)] || "application/octet-stream" });
    } catch (error) {
      if (error.code === "ENOENT") {
        const index = await fsp.readFile(path.join(PUBLIC_DIR, "index.html"));
        send(res, 200, index, { "content-type": MIME_TYPES[".html"] });
        return;
      }
      throw error;
    }
  }

  return async function app(req, res) {
    try {
      const url = new URL(req.url, `https://${req.headers.host || PUBLIC_IP}`);
      if (url.pathname.startsWith("/api/")) {
        await handleApi(req, res, url.pathname);
      } else {
        await serveStatic(req, res, url.pathname);
      }
    } catch (error) {
      const status = error.message?.includes("not found") ? 404 : 500;
      sendJson(res, status, { error: error.message || "Internal server error" });
    }
  };
}

async function serveAcmeOrRedirect(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || PUBLIC_IP}`);
  if (url.pathname.startsWith("/.well-known/acme-challenge/")) {
    const token = path.basename(url.pathname);
    const filePath = path.join(ACME_WEBROOT, ".well-known", "acme-challenge", token);
    try {
      const data = await fsp.readFile(filePath);
      send(res, 200, data, TEXT_TYPE);
      return;
    } catch {
      send(res, 404, "Not found", TEXT_TYPE);
      return;
    }
  }
  const host = req.headers.host ? req.headers.host.replace(/:\d+$/, "") : PUBLIC_IP;
  res.writeHead(308, { location: `https://${host}${url.pathname}${url.search}` });
  res.end();
}

async function ensureLayout() {
  await ensureDir(path.dirname(STATE_PATH), 0o700);
  await ensureDir(path.dirname(SESSION_PATH), 0o700);
  await ensureDir(path.dirname(SECRETS_PATH), 0o700);
  await ensureDir(path.dirname(CREDENTIALS_PATH), 0o700);
  await ensureDir(XRAY_CONFIG_DIR, 0o750);
  await ensureDir(XRAY_LOG_DIR, 0o750);
  await ensureDir(XRAY_BACKUP_DIR, 0o750);
  await ensureDir(path.join(ACME_WEBROOT, ".well-known", "acme-challenge"), 0o755);
  await ensureSelfSignedCert();
}

async function initCommand() {
  await ensureLayout();
  const secrets = await ensureSecrets();
  const state = await loadState();
  if (!state.settings.mixed.user) state.settings.mixed.user = secrets.proxy.username;
  if (!state.settings.mixed.pass) state.settings.mixed.pass = secrets.proxy.password;
  await saveState(state);
  await writeAndApplyXrayConfig(state, false);
  console.log(`Initialized xray-manager ${APP_VERSION}`);
  console.log(`State: ${STATE_PATH}`);
  console.log(`Xray config: ${XRAY_CONFIG}`);
  console.log(`Credentials: ${CREDENTIALS_PATH}`);
}

function installShutdownHandlers() {
  const shutdown = async (signal) => {
    console.log(`received ${signal}, shutting down`);
    await stopManagedXray().catch(() => {});
    process.exit(0);
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
}

function startAutoSwitchScheduler() {
  const fallbackDelayMs = 60 * 1000;
  const scheduleAutoSwitch = (delayMs) => {
    const timer = setTimeout(async () => {
      let nextDelayMs = fallbackDelayMs;
      try {
        const state = await loadState();
        const intervalMs = autoSwitchIntervalMs(state.settings);
        if (intervalMs > 0) {
          await runAutoSwitchCycle("schedule");
          nextDelayMs = intervalMs;
        }
      } catch (error) {
        console.error(`auto switch scheduler failed: ${error.message}`);
      } finally {
        scheduleAutoSwitch(nextDelayMs);
      }
    }, delayMs);
    timer.unref();
  };

  const scheduleFailover = (delayMs) => {
    const timer = setTimeout(async () => {
      let nextDelayMs = fallbackDelayMs;
      try {
        const state = await loadState();
        const intervalMs = failoverIntervalMs(state.settings);
        if (intervalMs > 0) {
          nextDelayMs = intervalMs;
          await runFailoverCheck();
        }
      } catch (error) {
        console.error(`failover watchdog failed: ${error.message}`);
      } finally {
        scheduleFailover(nextDelayMs);
      }
    }, delayMs);
    timer.unref();
  };

  loadState()
    .then((state) => {
      scheduleAutoSwitch(autoSwitchIntervalMs(state.settings) > 0 ? 15000 : fallbackDelayMs);
      scheduleFailover(failoverIntervalMs(state.settings) > 0 ? 15000 : fallbackDelayMs);
    })
    .catch(() => {
      scheduleAutoSwitch(fallbackDelayMs);
      scheduleFailover(fallbackDelayMs);
    });
}

async function start() {
  await ensureLayout();
  const secrets = await ensureSecrets();
  const state = await loadState();
  if (!state.settings.mixed.user || !state.settings.mixed.pass) {
    state.settings.mixed.user = secrets.proxy.username;
    state.settings.mixed.pass = secrets.proxy.password;
    await saveState(state);
  }
  if (IS_DOCKER_MODE) {
    await writeAndApplyXrayConfig(state, false);
    await startManagedXray(state);
    installShutdownHandlers();
  }
  startAutoSwitchScheduler();
  const tls = getTlsFiles();
  const app = makeApp(secrets);
  const tlsOptions = {
    key: await fsp.readFile(tls.keyPath),
    cert: await fsp.readFile(tls.certPath)
  };

  http.createServer((req, res) => {
    serveAcmeOrRedirect(req, res).catch((error) => sendJson(res, 500, { error: error.message }));
  }).listen(HTTP_PORT, LISTEN_HOST);

  https.createServer(tlsOptions, app).listen(HTTPS_PORT, LISTEN_HOST, () => {
    console.log(`xray-manager listening on https://${PUBLIC_IP}/ using ${tls.source} certificate`);
  });
}

if (require.main === module) {
  const command = process.argv[2];
  const run = command === "--init" ? initCommand : start;
  run().catch((error) => {
    console.error(error.stack || error.message || error);
    process.exit(1);
  });
}

module.exports = {
  parseVlessLink,
  decodeSubscriptionText,
  extractLinks,
  profileKey,
  generateXrayConfig,
  importProfilesFromXrayConfig,
  defaultState,
  buildVlessOutbound
};
