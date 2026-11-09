// edutraceug-extras-worker
//
// Standalone worker. Does not modify the marks, roster, teachers or school-other workers.
//
//   1. Compact report card (HTML, never wider than its container, iframe-friendly)
//   2. Bar graph data: current term vs previous term (all classes, or subjects of one class)
//   3. Custom data sets (text, note, date, file) with audience control and teacher uploads
//   4. Custom subjects + assign/unassign to classes
//   5. Yearly auto-promotion on 1 January (cron), preview, repeaters, undo
//   6. Class materials: PDF uploads by admin or permitted teachers, visible to students/parents by class
//
// Secrets:  ACCOUNT_SERVICE_FIREBASE, CLOUDINARY_URL, CLOUDMERSIVE_API_KEY
// Binding:  MARKS_WORKER (service binding to edutraceug-marks-worker)
//           or var MARKS_WORKER_URL as a fallback
//
// Storage (all under schools/{sid}):
//   subjects/{id}                  custom subjects
//   datasets/{id}                  data set definitions
//   datasetEntries/{id}            entries (no file URLs)
//   datasetFiles/{id}              file records (Cloudinary URL, never sent to clients)
//   analyticsSnapshots/{termId}    cached per-term averages
//   promotionExclusions/{rid}      repeaters for a given year
//   school doc fields: promotionRun, autoPromote
//   roster docs get: prevClass, promotedYear, promotedAt (used for undo and idempotency)
//   auditLog/{auto}

// ================================================================
// Constants
// ================================================================

const DEFAULT_PROJECT_ID = "edutrace-ug";
const COMMIT_CHUNK = 400;
const MAX_ROSTER_ROWS = 10000;
const MARKS_PAGE = 5000;
const MAX_MARK_PAGES = 8;
const CRON_CALL_BUDGET = 40;
const MANUAL_CALL_BUDGET = 35;
const MAX_FILE_MB = 10;
const MAX_FILES_PER_ENTRY = 5;
const MAX_FIELDS = 20;
const MAX_LIST = 500;
const SNAPSHOT_TTL_MS = 15 * 60 * 1000;

const SCAN_URL = "https://api.cloudmersive.com/virus/scan/file";
const SCAN_TIMEOUT_MS = 60_000;

const FIELD_TYPES = ["text", "note", "date", "file"];
const PREVIOUS_S6 = "Previous Senior 6";
const NUM_WORDS = ["", "one", "two", "three", "four", "five", "six"];
const CLASS_PREFIXES = new Set(["s", "sen", "senior", "f", "form"]);
const NUM_RE = /^(\D*?)(\d|one|two|three|four|five|six)(\s*)$/i;

const FILE_KINDS = {
  pdf: { mime: "application/pdf", exts: [".pdf"] },
  png: { mime: "image/png", exts: [".png"] },
  jpeg: { mime: "image/jpeg", exts: [".jpg", ".jpeg"] },
  gif: { mime: "image/gif", exts: [".gif"] },
  webp: { mime: "image/webp", exts: [".webp"] },
};

const MARK_FIELDS = ["rosterId", "class", "stream", "subject", "typeId", "status", "score", "level", "maxScore"];

// ================================================================
// Errors / HTTP
// ================================================================

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
  "Access-Control-Expose-Headers": "Content-Disposition",
  "Access-Control-Max-Age": "86400",
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS_HEADERS },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...CORS_HEADERS },
  });
}

async function safeJson(request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("not object");
    return body;
  } catch {
    throw new HttpError(400, "Invalid JSON body");
  }
}

// ================================================================
// Subrequest counter (free plan allows 50 per invocation)
// ================================================================

let CALLS = 0;
function xfetch(url, init) {
  CALLS += 1;
  return fetch(url, init);
}

// ================================================================
// Basic helpers
// ================================================================

function str(v) { return v === null || v === undefined ? "" : String(v); }
function enc(v) { return encodeURIComponent(v); }
function round1(n) { return Math.round(n * 10) / 10; }
function round2(n) { return Math.round(n * 100) / 100; }
function toNumberOrNull(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function utf8ToBytes(s) { return new TextEncoder().encode(s); }

function bytesToBase64Url(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = "";
  const CH = 0x8000;
  for (let i = 0; i < arr.length; i += CH) bin += String.fromCharCode.apply(null, arr.subarray(i, i + CH));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToString(s) { return new TextDecoder().decode(b64urlToBytes(s)); }

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", utf8ToBytes(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha1Hex(s) {
  const buf = await crypto.subtle.digest("SHA-1", utf8ToBytes(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateId(len = 20) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let s = "";
  for (const b of bytes) s += chars[b % chars.length];
  return s;
}

const EMOJI_RE = /[\u{1F000}-\u{1FAFF}\u{1F1E6}-\u{1F1FF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}\u{1F3FB}-\u{1F3FF}]/gu;

function escapeHtml(s) {
  return str(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function cleanText(input, maxLen, label) {
  if (typeof input !== "string") throw new HttpError(400, `${label} must be text`);
  const t = input.trim().replace(EMOJI_RE, "");
  if (!t) throw new HttpError(400, `${label} is required`);
  if (t.length > maxLen) throw new HttpError(400, `${label} is too long (max ${maxLen})`);
  return t;
}

function cleanOptionalText(input, maxLen, label) {
  if (input === null || input === undefined || input === "") return "";
  return cleanText(typeof input === "number" ? String(input) : input, maxLen, label);
}

function normKey(v) { return String(v || "").toLowerCase().replace(/[^a-z0-9]/g, ""); }

// ================================================================
// Class name handling (S1, S.1, s1, Senior 1, Senior one, Form 1, Form one ...)
// ================================================================

function parseClass(raw) {
  const s = String(raw || "").trim();
  if (!s) return null;
  if (/^(previous|former|alumni)/i.test(s)) return { previous: true, level: null };
  const m = s.match(NUM_RE);
  if (!m) return null;
  const prefix = m[1].toLowerCase().replace(/[^a-z]/g, "");
  if (!CLASS_PREFIXES.has(prefix)) return null;
  const tok = m[2].toLowerCase();
  const level = /\d/.test(tok) ? Number(tok) : NUM_WORDS.indexOf(tok);
  if (level < 1 || level > 6) return null;
  return { previous: false, level };
}

function replaceNumeral(original, newLevel) {
  const m = String(original).trim().match(NUM_RE);
  if (!m) return null;
  const tok = m[2];
  let next;
  if (/\d/.test(tok)) next = String(newLevel);
  else {
    const w = NUM_WORDS[newLevel];
    if (tok.length > 1 && tok === tok.toUpperCase()) next = w.toUpperCase();
    else if (tok[0] === tok[0].toUpperCase()) next = w[0].toUpperCase() + w.slice(1);
    else next = w;
  }
  return m[1] + next + m[3];
}

function nextClassName(cls) {
  const p = parseClass(cls);
  if (!p || p.previous) return null;
  if (p.level >= 6) return PREVIOUS_S6;
  return replaceNumeral(cls, p.level + 1);
}

function classKey(cls) {
  const p = parseClass(cls);
  if (p && p.previous) return "PREV";
  if (p) return `L${p.level}`;
  return `X:${normKey(cls)}`;
}

function classMatches(a, b) {
  const pa = parseClass(a), pb = parseClass(b);
  if (pa && pb) {
    if (pa.previous || pb.previous) return pa.previous === pb.previous;
    return pa.level === pb.level;
  }
  return normKey(a) !== "" && normKey(a) === normKey(b);
}

function classAllowed(list, className) {
  if (!Array.isArray(list) || list.length === 0) return true;
  if (!className) return false;
  return list.some((c) => classMatches(c, className));
}

// ================================================================
// Service account / Firebase auth
// ================================================================

let _saCache = { raw: null, parsed: null };
function getServiceAccount(env) {
  const raw = env["ACCOUNT_SERVICE_FIREBASE"] || env["ACCOUNT-SERVICE-FIREBASE"];
  if (!raw) throw new HttpError(500, "Server misconfigured: ACCOUNT_SERVICE_FIREBASE");
  if (_saCache.raw === raw && _saCache.parsed) return _saCache.parsed;
  const parsed = typeof raw === "object" ? raw : JSON.parse(raw);
  _saCache = { raw, parsed };
  return parsed;
}
function getProjectId(env) { return getServiceAccount(env).project_id || DEFAULT_PROJECT_ID; }

let jwksCache = { keys: null, expiry: 0 };
async function getJwks() {
  const now = Date.now();
  if (jwksCache.keys && now < jwksCache.expiry) return jwksCache.keys;
  const res = await xfetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  if (!res.ok) throw new HttpError(502, "JWKS fetch failed");
  const data = await res.json();
  jwksCache = { keys: data.keys, expiry: now + 3600_000 };
  return data.keys;
}

async function verifyIdToken(token, projectId) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new HttpError(401, "Malformed token");
  const [headerB64, payloadB64, sigB64] = parts;
  let header, payload;
  try {
    header = JSON.parse(b64urlToString(headerB64));
    payload = JSON.parse(b64urlToString(payloadB64));
  } catch {
    throw new HttpError(401, "Malformed token");
  }
  const keys = await getJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new HttpError(401, "Unknown signing key");
  const { alg, ...cleanJwk } = jwk;
  const key = await crypto.subtle.importKey("jwk", cleanJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(sigB64), utf8ToBytes(`${headerB64}.${payloadB64}`));
  if (!ok) throw new HttpError(401, "Invalid token signature");
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new HttpError(401, "Token expired");
  if (payload.iat > now + 60) throw new HttpError(401, "Token issued in future");
  if (payload.aud !== projectId) throw new HttpError(401, "Invalid audience");
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new HttpError(401, "Invalid issuer");
  if (!payload.sub) throw new HttpError(401, "Missing subject");
  return payload;
}

async function requireUser(request, env, schoolId, roles) {
  const m = (request.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError(401, "Missing Bearer token");
  const payload = await verifyIdToken(m[1], getProjectId(env));
  if (!roles.includes(payload.role)) throw new HttpError(403, "Not allowed for your role");
  if (String(payload.schoolId) !== String(schoolId)) throw new HttpError(403, "Not a member of this school");
  return { ...payload, token: m[1] };
}

const ALL_ROLES = ["schoolAdmin", "teacher", "student", "parent"];
const ADMIN = ["schoolAdmin"];
const STAFF = ["schoolAdmin", "teacher"];

// ================================================================
// Firestore REST
// ================================================================

const saTokenCache = new Map();

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/\\n/g, "\n")
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/[\r\n\s]/g, "");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

async function getFirestoreToken(env) {
  const sa = getServiceAccount(env);
  const cached = saTokenCache.get(sa.client_email);
  if (cached && cached.expiry > Date.now() + 60_000) return cached.token;

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const headerB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify(header)));
  const claimB64 = bytesToBase64Url(utf8ToBytes(JSON.stringify(claim)));
  const toSign = `${headerB64}.${claimB64}`;
  const key = await crypto.subtle.importKey("pkcs8", pemToArrayBuffer(sa.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, utf8ToBytes(toSign));
  const jwt = `${toSign}.${bytesToBase64Url(new Uint8Array(sigBuf))}`;

  const res = await xfetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) throw new HttpError(502, "Firestore auth failed: " + (await res.text()));
  const data = await res.json();
  saTokenCache.set(sa.client_email, { token: data.access_token, expiry: Date.now() + 3500_000 });
  return data.access_token;
}

function toFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFsValue) } };
  if (typeof v === "object") {
    const fields = {};
    for (const [k, val] of Object.entries(v)) fields[k] = toFsValue(val);
    return { mapValue: { fields } };
  }
  throw new HttpError(500, "Cannot serialize value");
}

function fromFsValue(v) {
  if (!v) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return parseInt(v.integerValue, 10);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fromFsValue);
  if ("mapValue" in v) {
    const out = {};
    for (const [k, val] of Object.entries(v.mapValue.fields || {})) out[k] = fromFsValue(val);
    return out;
  }
  return null;
}

function fromFsDoc(doc) {
  const out = {};
  for (const [k, v] of Object.entries(doc.fields || {})) out[k] = fromFsValue(v);
  return out;
}

function fieldsOf(data) {
  return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, toFsValue(v)]));
}

function fsBase(env) {
  return `https://firestore.googleapis.com/v1/projects/${getProjectId(env)}/databases/(default)/documents`;
}
function docName(env, segments) {
  return `projects/${getProjectId(env)}/databases/(default)/documents/${segments.map(enc).join("/")}`;
}

async function fsGet(env, docPath) {
  const token = await getFirestoreToken(env);
  const res = await xfetch(`${fsBase(env)}/${docPath}`, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) throw new HttpError(502, "Firestore read failed");
  return fromFsDoc(await res.json());
}

async function fsPatch(env, docPath, data) {
  const token = await getFirestoreToken(env);
  const mask = Object.keys(data).map((f) => `updateMask.fieldPaths=${enc(f)}`).join("&");
  const res = await xfetch(`${fsBase(env)}/${docPath}?${mask}`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: fieldsOf(data) }),
  });
  if (!res.ok) throw new HttpError(502, "Firestore write failed: " + (await res.text()));
  return fromFsDoc(await res.json());
}

async function fsCreate(env, collectionPath, data, docId) {
  const token = await getFirestoreToken(env);
  const qs = docId ? `?documentId=${enc(docId)}` : "";
  const res = await xfetch(`${fsBase(env)}/${collectionPath}${qs}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: fieldsOf(data) }),
  });
  if (res.status === 409) throw new HttpError(409, "Document already exists");
  if (!res.ok) throw new HttpError(502, "Firestore create failed: " + (await res.text()));
  const created = await res.json();
  return { id: created.name.split("/").pop(), data: fromFsDoc(created) };
}

async function fsDelete(env, docPath) {
  const token = await getFirestoreToken(env);
  const res = await xfetch(`${fsBase(env)}/${docPath}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok && res.status !== 404) throw new HttpError(502, "Firestore delete failed");
}

async function fsQuery(env, parentPath, structuredQuery) {
  const token = await getFirestoreToken(env);
  const url = parentPath ? `${fsBase(env)}/${parentPath}:runQuery` : `${fsBase(env)}:runQuery`;
  const res = await xfetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ structuredQuery }),
  });
  if (!res.ok) throw new HttpError(502, "Firestore query failed: " + (await res.text()));
  const rows = await res.json();
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (r.document) out.push({ id: r.document.name.split("/").pop(), data: fromFsDoc(r.document) });
  }
  return out;
}

async function fsCommit(env, writes) {
  const token = await getFirestoreToken(env);
  const res = await xfetch(`${fsBase(env)}:commit`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ writes }),
  });
  if (!res.ok) throw new HttpError(502, "Firestore commit failed: " + (await res.text()));
  return res.json();
}

async function commitAll(env, writes) {
  for (let i = 0; i < writes.length; i += COMMIT_CHUNK) await fsCommit(env, writes.slice(i, i + COMMIT_CHUNK));
}

function fsEq(field, value) {
  let v;
  if (typeof value === "string") v = { stringValue: value };
  else if (typeof value === "boolean") v = { booleanValue: value };
  else if (typeof value === "number") v = Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  else v = { stringValue: String(value) };
  return { fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: v } };
}

function andFilter(filters) {
  return filters.length === 1 ? filters[0] : { compositeFilter: { op: "AND", filters } };
}

function selectFields(list) { return { fields: list.map((f) => ({ fieldPath: f })) }; }

function wUpdate(env, segments, data, { mask, exists } = {}) {
  const w = {
    update: { name: docName(env, segments), fields: fieldsOf(data) },
    updateMask: { fieldPaths: mask || Object.keys(data) },
  };
  if (exists === true) w.currentDocument = { exists: true };
  return w;
}

async function logChange(env, schoolId, entry) {
  try {
    await fsCreate(env, `schools/${enc(schoolId)}/auditLog`, { ...entry, at: new Date().toISOString() });
  } catch (err) {
    console.error("Audit log write failed:", err && err.message);
  }
}

// ================================================================
// Roster / term / scoring helpers
// ================================================================

function schoolPath(schoolId) { return `schools/${enc(schoolId)}`; }

async function fetchStudents(env, schoolId, fields) {
  return fsQuery(env, schoolPath(schoolId), {
    from: [{ collectionId: "roster" }],
    where: fsEq("recordType", "student"),
    select: selectFields(fields),
    limit: MAX_ROSTER_ROWS,
  });
}

async function listTypes(env, schoolId) {
  const rows = await fsQuery(env, schoolPath(schoolId), { from: [{ collectionId: "assessmentTypes" }], limit: 100 });
  return rows
    .map((r) => ({ id: r.id, name: r.data.name || "", order: typeof r.data.order === "number" ? r.data.order : 100, archived: r.data.archived === true }))
    .filter((t) => !t.archived)
    .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
}

async function getScoring(env, schoolId) {
  const doc = await fsGet(env, `${schoolPath(schoolId)}/settings/scoring`);
  const mode = doc && (doc.mode === "cbc" || doc.mode === "percentage") ? doc.mode : "percentage";
  const levels = doc && Array.isArray(doc.cbcLevels) && doc.cbcLevels.length ? doc.cbcLevels : [{ level: 1 }, { level: 2 }, { level: 3 }];
  return { mode, maxLevel: Math.max(...levels.map((l) => Number(l.level) || 0), 1) };
}

function resolveWeights(term, types) {
  const arr = term && Array.isArray(term.weights) ? term.weights : [];
  const out = {};
  for (const t of types) out[t.id] = 0;
  for (const w of arr) {
    if (w && out[w.typeId] !== undefined && typeof w.weight === "number") out[w.typeId] = w.weight;
  }
  return out;
}

// Same arithmetic as the marks worker: normalise over present weights.
function subjectValue(cells, types, weights, mode) {
  if (mode === "cbc") {
    let hi = 0;
    for (const t of types) {
      const c = cells.get(t.id);
      if (c && c.status === "entered" && typeof c.level === "number" && c.level > hi) hi = c.level;
    }
    return hi > 0 ? hi : null;
  }
  let raw = 0, wp = 0;
  for (const t of types) {
    const c = cells.get(t.id);
    const w = weights[t.id] ?? 0;
    if (c && c.status === "entered" && typeof c.score === "number" && c.maxScore > 0) {
      raw += (c.score / c.maxScore) * w;
      wp += w;
    }
  }
  return wp > 0 ? round1((raw / wp) * 100) : null;
}

function groupBySubject(marks) {
  const bySubject = new Map();
  for (const m of marks) {
    if (!m.subject || !m.typeId) continue;
    if (!bySubject.has(m.subject)) bySubject.set(m.subject, new Map());
    bySubject.get(m.subject).set(m.typeId, m);
  }
  return bySubject;
}

// ================================================================
// Virus scan + Cloudinary
// ================================================================

async function scanFile(env, bytes, filename) {
  if (!env.CLOUDMERSIVE_API_KEY) throw new HttpError(500, "Server misconfigured: CLOUDMERSIVE_API_KEY");
  const form = new FormData();
  form.append("inputFile", new Blob([bytes]), filename || "upload");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  let res;
  try {
    res = await xfetch(SCAN_URL, {
      method: "POST",
      headers: { Apikey: env.CLOUDMERSIVE_API_KEY, Accept: "application/json" },
      body: form,
      signal: controller.signal,
    });
  } catch (err) {
    throw new HttpError(502, `Virus scan service unreachable: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new HttpError(502, `Virus scan failed (${res.status})`);
  const data = await res.json().catch(() => ({}));
  const found = Array.isArray(data.FoundViruses) ? data.FoundViruses : [];
  return { clean: data.CleanResult !== false && found.length === 0, found };
}

function parseCloudinaryUrl(env) {
  const m = String(env.CLOUDINARY_URL || "").match(/^cloudinary:\/\/([^:]+):([^@]+)@(.+)$/);
  if (!m) throw new HttpError(500, "Server misconfigured: CLOUDINARY_URL");
  return { apiKey: m[1], apiSecret: m[2], cloudName: m[3] };
}

async function uploadToCloudinary(env, bytes, ext, folder) {
  const { apiKey, apiSecret, cloudName } = parseCloudinaryUrl(env);
  const publicId = `${generateId(24)}${ext}`;
  const timestamp = String(Math.floor(Date.now() / 1000));
  const params = { folder, public_id: publicId, timestamp };
  const signature = await sha1Hex(Object.keys(params).sort().map((k) => `${k}=${params[k]}`).join("&") + apiSecret);

  const form = new FormData();
  form.append("file", new Blob([bytes]), publicId);
  form.append("api_key", apiKey);
  form.append("timestamp", timestamp);
  form.append("public_id", publicId);
  form.append("folder", folder);
  form.append("signature", signature);

  const res = await xfetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`, { method: "POST", body: form });
  if (!res.ok) throw new HttpError(502, "Cloudinary upload failed: " + (await res.text()).slice(0, 200));
  const data = await res.json();
  if (!data.secure_url) throw new HttpError(502, "Cloudinary response missing secure_url");
  return { url: data.secure_url, publicId: data.public_id || publicId };
}

async function destroyOnCloudinary(env, publicId) {
  try {
    const { apiKey, apiSecret, cloudName } = parseCloudinaryUrl(env);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await sha1Hex(`public_id=${publicId}&timestamp=${timestamp}${apiSecret}`);
    await xfetch(`https://api.cloudinary.com/v1_1/${cloudName}/raw/destroy`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `public_id=${enc(publicId)}&timestamp=${timestamp}&api_key=${enc(apiKey)}&signature=${signature}`,
    });
  } catch (err) {
    console.error("Cloudinary destroy failed:", err && err.message);
  }
}

// Real content check, never trust the client's MIME type.
function detectFileKind(bytes) {
  const b = new Uint8Array(bytes.slice ? bytes.slice(0, 1032) : bytes);
  const asText = (from, to) => String.fromCharCode(...b.subarray(from, to));
  if (b.length >= 8 && b[0] === 0x89 && asText(1, 4) === "PNG") return "png";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  if (b.length >= 6 && (asText(0, 6) === "GIF87a" || asText(0, 6) === "GIF89a")) return "gif";
  if (b.length >= 12 && asText(0, 4) === "RIFF" && asText(8, 12) === "WEBP") return "webp";
  if (asText(0, b.length).includes("%PDF-")) return "pdf";
  return null;
}

// ================================================================
// Marks worker bridge
// ================================================================

function callMarks(env, path, token) {
  const init = { headers: { Authorization: `Bearer ${token}` } };
  if (env.MARKS_WORKER) return env.MARKS_WORKER.fetch(`https://marks.internal${path}`, init);
  if (env.MARKS_WORKER_URL) return xfetch(`${String(env.MARKS_WORKER_URL).replace(/\/$/, "")}${path}`, init);
  throw new HttpError(500, "Server misconfigured: MARKS_WORKER binding");
}

async function fetchPoints(env, schoolId, user, rosterId, termId) {
  const base = `/schools/${enc(schoolId)}/points`;
  const path = STAFF.includes(user.role)
    ? `${base}/student/${enc(rosterId)}?termId=${enc(termId)}`
    : user.role === "student" ? `${base}/me?termId=${enc(termId)}` : `${base}/child?termId=${enc(termId)}`;
  try {
    if (!env.POINTS_WORKER) return null;
    const res = await env.POINTS_WORKER.fetch(`https://points.internal${path}`, { headers: { Authorization: `Bearer ${user.token}` } });
    return res.ok ? await res.json() : null;
  } catch { return null; }
}

// ================================================================
// 1. Report card
// ================================================================

async function computeRank(env, schoolId, termId, termDoc, classStr, stream, rosterId) {
  const [types, scoring] = await Promise.all([listTypes(env, schoolId), getScoring(env, schoolId)]);
  const weights = resolveWeights(termDoc, types);
  const filters = [fsEq("termId", termId), fsEq("class", classStr)];
  if (stream) filters.push(fsEq("stream", stream));
  const rows = await fsQuery(env, schoolPath(schoolId), {
    from: [{ collectionId: "marks" }],
    where: andFilter(filters),
    select: selectFields(MARK_FIELDS),
    limit: MARKS_PAGE,
  });
  const byStudent = new Map();
  for (const r of rows) {
    const rid = r.data.rosterId;
    if (!rid) continue;
    if (!byStudent.has(rid)) byStudent.set(rid, []);
    byStudent.get(rid).push(r.data);
  }
  const ranked = [];
  for (const [rid, marks] of byStudent) {
    if (scoring.mode === "cbc") {
      ranked.push({ rid, key: marks.filter((m) => m.status === "entered" && m.level === scoring.maxLevel).length });
    } else {
      let sum = 0, n = 0;
      for (const [, cells] of groupBySubject(marks)) {
        const v = subjectValue(cells, types, weights, "percentage");
        if (v !== null) { sum += v; n += 1; }
      }
      if (n > 0) ranked.push({ rid, key: round1(sum / n) });
    }
  }
  ranked.sort((a, b) => b.key - a.key);
  let lastKey = null, lastPos = 0, mine = null;
  ranked.forEach((r, i) => {
    if (r.key !== lastKey) { lastPos = i + 1; lastKey = r.key; }
    if (r.rid === rosterId) mine = lastPos;
  });
  return mine ? { position: mine, total: ranked.length } : null;
}

async function handleReportCard(request, env, schoolId, url) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const termId = url.searchParams.get("termId") || "";
  const q = termId ? `?termId=${enc(termId)}` : "";

  let path;
  if (STAFF.includes(user.role)) {
    const rid = url.searchParams.get("rosterId");
    if (!rid) throw new HttpError(400, "rosterId is required");
    path = `/schools/${enc(schoolId)}/reports/student/${enc(rid)}${q}`;
  } else if (user.role === "student") {
    path = `/schools/${enc(schoolId)}/reports/me${q}`;
  } else {
    path = `/schools/${enc(schoolId)}/reports/child${q}`;
  }

  const res = await callMarks(env, path, user.token);
  const report = await res.json().catch(() => ({}));
  if (!res.ok) throw new HttpError(res.status, report.error || "Report unavailable");

  const rosterId = report.student.rosterId;
  const [school, atTerm] = await Promise.all([
    fsGet(env, schoolPath(schoolId)),
    fsQuery(env, schoolPath(schoolId), {
      from: [{ collectionId: "marks" }],
      where: andFilter([fsEq("termId", report.term.id), fsEq("rosterId", rosterId)]),
      select: selectFields(["class", "stream"]),
      limit: 1,
    }),
  ]);

  // Class as it was during that term, not the current one (students get promoted).
  let classAtTerm = report.student.class;
  let streamAtTerm = report.student.stream;
  if (atTerm.length && atTerm[0].data.class) {
    classAtTerm = atTerm[0].data.class;
    streamAtTerm = atTerm[0].data.stream || "";
    report.student.class = classAtTerm;
    report.student.stream = streamAtTerm;
  }

  // The marks worker ranks using the current class. Re-rank using the term's class.
  if (report.rank) {
    const termDoc = await fsGet(env, `${schoolPath(schoolId)}/terms/${enc(report.term.id)}`);
    report.rank = await computeRank(env, schoolId, report.term.id, termDoc || {}, classAtTerm, streamAtTerm, rosterId);
  }

  const pc = parseClass(classAtTerm);
  if (pc && !pc.previous && pc.level >= 5) {
    report.points = await fetchPoints(env, schoolId, user, rosterId, report.term.id);
  }

  if (url.searchParams.get("format") === "json") return json(report);
  return html(renderReportCard(report, school || {}));
}

function renderReportCard(report, school) {
  const cbc = report.scoringMode === "cbc";
  const themeColor = /^#[0-9a-fA-F]{6}$/.test(school.themeColor || "") ? school.themeColor : "#3570BC";
  const schoolName = escapeHtml(school.name || "School");
  const logo = school.logoUrl ? escapeHtml(school.logoUrl) : "";
  const t = report.term, s = report.student;
  const dense = report.subjects.length > 14 ? " dense" : "";
  const pts = !cbc && report.points ? report.points : null;
  const ptMap = new Map(pts ? pts.subjects.map((x) => [x.name, x]) : []);

  const chip = (a) => {
    if (a.status === "missing") return "";
    const name = escapeHtml(a.typeName);
    if (a.status === "absent") return `<span>${name} ABS</span>`;
    if (a.status === "excused") return `<span>${name} EXC</span>`;
    if (a.status === "na") return `<span>${name} N/A</span>`;
    return cbc ? `<span>${name} L${escapeHtml(a.level)}</span>` : `<span>${name} ${escapeHtml(a.score)}/${escapeHtml(a.maxScore)}</span>`;
  };

  const rows = report.subjects.map((sub) => {
    const chips = sub.assessments.map(chip).join("") || `<span class="muted">No marks</span>`;
    if (cbc) {
      return `<tr><td class="subject">${escapeHtml(sub.name)}</td><td class="chips">${chips}</td><td class="final">${sub.level ? escapeHtml(sub.level.label) : "-"}</td></tr>`;
    }
    const pct = sub.pct !== null && sub.pct !== undefined ? Number(sub.pct).toFixed(1) : "-";
    const grade = sub.grade ? escapeHtml(sub.grade.grade) : "-";
    const pp = ptMap.get(sub.name);
    const ptsCell = pts ? `<td class="final">${pp && pp.points !== null ? pp.points : "-"}</td>` : "";
    return `<tr><td class="subject">${escapeHtml(sub.name)}</td><td class="chips">${chips}</td><td class="final">${pct}</td><td class="final">${grade}</td>${ptsCell}</tr>`;
  }).join("");

  const head = cbc
    ? `<tr><th class="l">Subject</th><th class="l">Assessments</th><th>Level</th></tr>`
    : `<tr><th class="l">Subject</th><th class="l">Assessments</th><th>Total %</th><th>Grade</th>${pts ? "<th>Points</th>" : ""}</tr>`;
  const cols = (cbc ? 3 : 4) + (pts ? 1 : 0);

  let summary;
  if (cbc) {
    const r = report.rollup && report.rollup.rows ? report.rollup.rows : [];
    summary = r.map((x) => `<div><label>${escapeHtml(x.label)}</label><strong>${x.count}</strong></div>`).join("") || `<div><label>Subjects</label><strong>0</strong></div>`;
  } else {
    const o = report.overall || {};
    summary =
      `<div><label>Overall</label><strong>${o.pct !== null && o.pct !== undefined ? Number(o.pct).toFixed(1) + "%" : "-"}</strong></div>` +
      `<div><label>Grade</label><strong>${o.grade ? escapeHtml(o.grade.grade) : "-"}</strong></div>` +
      (pts
        ? `<div><label>Total Points</label><strong>${pts.totalPoints}</strong></div>` +
          (pts.position ? `<div><label>Position</label><strong>${pts.position} of ${pts.outOf}</strong></div>` : "")
        : (report.rank && report.rank.position
            ? `<div><label>Position</label><strong>${report.rank.position} of ${report.rank.total}</strong></div>`
            : `<div><label>Subjects</label><strong>${report.subjects.length}</strong></div>`));
  }

  let legend = "";
  if (cbc && Array.isArray(report.cbcLevels)) {
    legend = report.cbcLevels.map((l) => `<span><b>${escapeHtml(l.level)}</b> ${escapeHtml(l.label)}</span>`).join("");
  } else if (report.gradingScale && Array.isArray(report.gradingScale.bands)) {
    legend = report.gradingScale.bands.slice().sort((a, b) => b.min - a.min)
      .map((b) => `<span><b>${escapeHtml(b.grade)}</b> ${escapeHtml(b.min)}-${escapeHtml(b.max)}</span>`).join("");
  }

  const note = report.note || {};
  const conduct = note.conduct ? `<p><b>Conduct:</b> ${escapeHtml(note.conduct)}</p>` : "";
  const hold = report.hold ? `<div class="hold">Report withheld: ${escapeHtml(report.hold.reason || "no reason given")}</div>` : "";

  return `<!DOCTYPE html><html lang="en-UG"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Report Card - ${escapeHtml(s.firstName)} ${escapeHtml(s.lastName)} - ${escapeHtml(t.name)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--primary:${themeColor};--text:#1A1A1A;--muted:#555;--border:#E5E5E5;--light:#F8F9FA}
*{margin:0;padding:0;box-sizing:border-box;border-radius:0!important}
html,body{width:100%;overflow-x:hidden}
body{font-family:'Plus Jakarta Sans',Arial,sans-serif;background:#fff;color:var(--text);padding:12px;line-height:1.45;word-wrap:break-word;overflow-wrap:anywhere}
.card{width:100%;max-width:820px;margin:0 auto;border:2px solid var(--primary)}
.header{display:flex;align-items:center;gap:16px;padding:16px 18px;border-bottom:3px solid var(--primary)}
.logo{width:64px;height:64px;object-fit:contain;flex-shrink:0}
.logo-fb{width:64px;height:64px;background:var(--primary);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1.4rem;flex-shrink:0}
.school h1{font-size:1.25rem;font-weight:800;color:var(--primary);line-height:1.2}
.school p{font-size:.75rem;color:var(--muted)}
.bar{background:var(--primary);color:#fff;padding:10px 18px;text-align:center}
.bar h2{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px}
.info{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:14px 18px;background:var(--light);border-bottom:1px solid var(--border)}
.info label{display:block;font-size:.65rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);font-weight:700}
.info strong{font-size:.85rem}
.hold{background:#111;color:#fff;padding:8px 18px;font-size:.8rem;font-weight:700}
table{width:100%;border-collapse:collapse;table-layout:fixed}
col.c-sub{width:26%}col.c-num{width:13%}
th,td{padding:8px 6px;border-bottom:1px solid var(--border);font-size:.8rem;text-align:center;vertical-align:top}
th{background:var(--primary);color:#fff;font-size:.65rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700}
th.l,td.subject,td.chips{text-align:left}
td.subject{font-weight:700}
td.chips{font-size:.72rem;color:var(--muted)}
td.chips span{display:inline-block;margin:0 10px 2px 0;white-space:nowrap}
td.chips .muted{font-style:italic}
td.final{font-weight:800;color:var(--primary)}
.dense th,.dense td{padding:4px 5px;font-size:.72rem}
.dense td.chips{font-size:.65rem}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));border-top:2px solid var(--primary)}
.summary>div{padding:12px;text-align:center;border-right:1px solid var(--border)}
.summary>div:last-child{border-right:none}
.summary label{display:block;font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:700}
.summary strong{font-size:1.2rem;font-weight:800;color:var(--primary)}
.legend{padding:8px 18px;background:var(--light);font-size:.68rem;color:var(--muted);border-top:1px solid var(--border)}
.legend span{display:inline-block;margin-right:12px;white-space:nowrap}
.comment{padding:14px 18px;border-top:1px solid var(--border)}
.comment h3{font-size:.7rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px}
.comment p{font-size:.85rem;min-height:36px}
.sign{display:flex;gap:24px;padding:20px 18px;border-top:1px solid var(--border)}
.sign>div{flex:1}
.sign .line{border-bottom:1px solid #999;height:30px;margin-bottom:4px}
.sign label{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:700}
.foot{background:#111;color:#ccc;padding:10px 18px;text-align:center;font-size:.7rem}
.noprint{padding:10px;text-align:center}
.noprint button{padding:9px 20px;background:var(--primary);color:#fff;border:none;font-weight:700;text-transform:uppercase;letter-spacing:.5px;cursor:pointer;font-family:inherit}
@page{size:A4;margin:10mm}
@media print{body{padding:0}.card{border:none;max-width:none}.noprint{display:none}thead{display:table-header-group}tr{page-break-inside:avoid}}
@media(max-width:560px){.info{grid-template-columns:repeat(2,1fr)}.sign{flex-direction:column;gap:12px}col.c-sub{width:30%}}
</style></head><body>
<div class="noprint"><button onclick="window.print()">Print Report Card</button></div>
<div class="card">
  <div class="header">
    ${logo ? `<img class="logo" src="${logo}" alt="">` : `<div class="logo-fb">${escapeHtml((school.name || "S")[0].toUpperCase())}</div>`}
    <div class="school"><h1>${schoolName}</h1>
      ${school.location ? `<p>${escapeHtml(school.location)}</p>` : ""}
      ${school.phone ? `<p>Tel: ${escapeHtml(school.phone)}</p>` : ""}
      ${school.email ? `<p>Email: ${escapeHtml(school.email)}</p>` : ""}
    </div>
  </div>
  <div class="bar"><h2>Term Report Card - ${escapeHtml(t.name)}${t.year ? ", " + escapeHtml(t.year) : ""}</h2></div>
  ${hold}
  <div class="info">
    <div><label>Name</label><strong>${escapeHtml(s.firstName)} ${escapeHtml(s.lastName)}</strong></div>
    <div><label>Class</label><strong>${escapeHtml(s.class)}</strong></div>
    <div><label>Stream</label><strong>${escapeHtml(s.stream || "-")}</strong></div>
    <div><label>Gender</label><strong>${escapeHtml(s.gender || "-")}</strong></div>
  </div>
  <table class="${dense.trim()}">
    <colgroup><col class="c-sub"><col>${cbc ? `<col class="c-num">` : `<col class="c-num"><col class="c-num">`}${pts ? `<col class="c-num">` : ""}</colgroup>
    <thead>${head}</thead>
    <tbody>${rows || `<tr><td colspan="${cols}" class="chips">No marks recorded for this term.</td></tr>`}</tbody>
  </table>
  <div class="summary">${summary}</div>
  ${legend ? `<div class="legend">${legend}</div>` : ""}
  <div class="comment"><h3>Class Teacher's Comment</h3>${conduct}<p>${escapeHtml(note.comment || "") || "&nbsp;"}</p></div>
  <div class="sign">
    <div><div class="line"></div><label>Class Teacher</label></div>
    <div><div class="line"></div><label>Head Teacher</label></div>
    <div><div class="line"></div><label>Date</label></div>
  </div>
  <div class="foot">&copy; ${new Date().getFullYear()} ${schoolName}. Powered by Edutrace.</div>
</div>
<script>
(function(){
  function send(){try{parent.postMessage({type:"edutrace-card-height",height:document.documentElement.scrollHeight},"*");}catch(e){}}
  window.addEventListener("load",send);window.addEventListener("resize",send);setTimeout(send,400);
})();
</script>
</body></html>`;
}

// ================================================================
// 2. Term comparison chart
// ================================================================

async function fetchTermMarks(env, schoolId, termId) {
  const out = [];
  for (let page = 0; page < MAX_MARK_PAGES; page++) {
    const rows = await fsQuery(env, schoolPath(schoolId), {
      from: [{ collectionId: "marks" }],
      where: fsEq("termId", termId),
      select: selectFields(MARK_FIELDS),
      limit: MARKS_PAGE,
      offset: page * MARKS_PAGE,
    });
    for (const r of rows) out.push(r.data);
    if (rows.length < MARKS_PAGE) break;
  }
  return out;
}

function buildSnapshotClasses(marks, types, weights, mode) {
  const rnd = mode === "cbc" ? round2 : round1;
  const classes = new Map();
  for (const m of marks) {
    if (!m.rosterId || !m.subject || !m.typeId) continue;
    const key = classKey(m.class);
    let c = classes.get(key);
    if (!c) {
      const p = parseClass(m.class);
      c = { key, label: str(m.class), level: p && !p.previous ? p.level : null, students: new Map() };
      classes.set(key, c);
    }
    if (!c.students.has(m.rosterId)) c.students.set(m.rosterId, new Map());
    const st = c.students.get(m.rosterId);
    if (!st.has(m.subject)) st.set(m.subject, new Map());
    st.get(m.subject).set(m.typeId, m);
  }
  const out = [];
  for (const c of classes.values()) {
    const agg = new Map();
    let sum = 0, n = 0;
    for (const st of c.students.values()) {
      let ssum = 0, sn = 0;
      for (const [subject, cells] of st) {
        const v = subjectValue(cells, types, weights, mode);
        if (v === null) continue;
        ssum += v; sn += 1;
        const a = agg.get(subject) || { sum: 0, n: 0 };
        a.sum += v; a.n += 1;
        agg.set(subject, a);
      }
      if (sn > 0) { sum += ssum / sn; n += 1; }
    }
    out.push({
      key: c.key,
      label: c.label,
      level: c.level,
      students: n,
      avg: n ? rnd(sum / n) : null,
      subjects: [...agg].map(([name, a]) => ({ name, avg: rnd(a.sum / a.n), n: a.n })).sort((a, b) => a.name.localeCompare(b.name)),
    });
  }
  out.sort((a, b) => (a.level ?? 99) - (b.level ?? 99) || a.label.localeCompare(b.label));
  return out;
}

async function getSnapshot(env, schoolId, termId, termDoc, isCurrent, force, types, mode) {
  const path = `${schoolPath(schoolId)}/analyticsSnapshots/${enc(termId)}`;
  const snap = await fsGet(env, path);
  const age = snap && snap.computedAt ? Date.now() - Date.parse(snap.computedAt) : Infinity;
  if (snap && !force && snap.metric === mode && (!isCurrent || age < SNAPSHOT_TTL_MS)) return snap;

  const marks = await fetchTermMarks(env, schoolId, termId);
  const classes = buildSnapshotClasses(marks, types, resolveWeights(termDoc, types), mode);
  const doc = { termId, metric: mode, computedAt: new Date().toISOString(), classes };
  await fsPatch(env, path, doc);
  return doc;
}

async function handleCompare(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ADMIN);
  const termRows = await fsQuery(env, schoolPath(schoolId), { from: [{ collectionId: "terms" }], limit: 100 });
  const terms = termRows.map((r) => ({ id: r.id, ...r.data }));
  terms.sort((a, b) =>
    str(a.startDate).localeCompare(str(b.startDate)) || (a.year || 0) - (b.year || 0) || str(a.name).localeCompare(str(b.name)));
  if (!terms.length) throw new HttpError(404, "No terms found");

  const wanted = url.searchParams.get("termId");
  const current = (wanted && terms.find((t) => t.id === wanted)) || terms.find((t) => t.isCurrent === true) || terms[terms.length - 1];
  const compareTo = url.searchParams.get("compareTo");
  let previous = compareTo ? terms.find((t) => t.id === compareTo) : null;
  if (!previous) {
    const idx = terms.findIndex((t) => t.id === current.id);
    previous = idx > 0 ? terms[idx - 1] : null;
  }

  const [types, scoring] = await Promise.all([listTypes(env, schoolId), getScoring(env, schoolId)]);
  const force = url.searchParams.get("refresh") === "1";
  const snapCur = await getSnapshot(env, schoolId, current.id, current, current.isCurrent === true, force, types, scoring.mode);
  const snapPrev = previous
    ? await getSnapshot(env, schoolId, previous.id, previous, previous.isCurrent === true, force, types, scoring.mode)
    : null;

  const snaps = [snapCur, snapPrev].filter(Boolean);
  const classMap = new Map();
  for (const sn of snaps) for (const c of sn.classes) if (!classMap.has(c.key)) classMap.set(c.key, { key: c.key, label: c.label, level: c.level });
  const classList = [...classMap.values()].sort((a, b) => (a.level ?? 99) - (b.level ?? 99) || a.label.localeCompare(b.label));

  const meta = (t) => ({ id: t.id, name: t.name || "", year: t.year || null });
  const series = [];
  let labels, view, selected = null;

  const classParam = url.searchParams.get("class");
  if (classParam) {
    const key = classKey(classParam);
    selected = classMap.get(key) || { key, label: classParam };
    view = "subjects";
    const names = new Set();
    for (const sn of snaps) {
      const c = sn.classes.find((x) => x.key === key);
      if (c) for (const s of c.subjects) names.add(s.name);
    }
    labels = [...names].sort((a, b) => a.localeCompare(b));
    for (const [sn, t] of [[snapPrev, previous], [snapCur, current]]) {
      if (!sn) continue;
      const c = sn.classes.find((x) => x.key === key);
      series.push({ termId: t.id, name: t.name || t.id, values: labels.map((l) => { const s = c && c.subjects.find((x) => x.name === l); return s ? s.avg : null; }) });
    }
  } else {
    view = "classes";
    labels = classList.map((c) => c.label);
    for (const [sn, t] of [[snapPrev, previous], [snapCur, current]]) {
      if (!sn) continue;
      series.push({ termId: t.id, name: t.name || t.id, values: classList.map((c) => { const x = sn.classes.find((y) => y.key === c.key); return x ? x.avg : null; }) });
    }
  }

  return json({
    metric: scoring.mode === "cbc" ? "level" : "percent",
    view,
    class: selected,
    current: meta(current),
    previous: previous ? meta(previous) : null,
    classes: classList,
    labels,
    series,
    computedAt: snapCur.computedAt,
  });
}

// ================================================================
// 3. Custom data sets
// ================================================================

async function viewerContext(env, schoolId, user) {
  const ctx = { role: user.role, uid: String(user.sub), className: "" };
  if (user.role === "student" || user.role === "parent") {
    const rid = String(user.role === "student" ? user.rosterId || "" : user.childRosterId || "");
    if (rid) {
      const r = await fsGet(env, `${schoolPath(schoolId)}/roster/${enc(rid)}`);
      ctx.className = r ? str(r.class) : "";
    }
  }
  return ctx;
}

function datasetVisible(ds, ctx) {
  if (ctx.role === "schoolAdmin") return true;
  if (ds.archived === true) return false;
  const a = ds.audience || {};
  if (ctx.role === "teacher") return a.teachers === true || ds.teachersCanUpload === true;
  if (ctx.role === "student") return a.students === true && classAllowed(a.classes, ctx.className);
  if (ctx.role === "parent") return a.parents === true && classAllowed(a.classes, ctx.className);
  return false;
}

function entryVisible(ds, entry, ctx) {
  if (ctx.role === "schoolAdmin") return true;
  if (!datasetVisible(ds, ctx)) return false;
  if (ctx.role === "teacher") return (ds.audience && ds.audience.teachers === true) || entry.createdBy === ctx.uid;
  return classAllowed(entry.classes, ctx.className);
}

function slugKey(label) {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 40) || "field";
}

function validateFields(input, existing) {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_FIELDS) {
    throw new HttpError(400, `fields must be a list of 1-${MAX_FIELDS} items`);
  }
  const seen = new Set();
  const out = [];
  for (const f of input) {
    if (!f || typeof f !== "object") throw new HttpError(400, "Invalid field");
    const label = cleanText(f.label, 60, "field label");
    if (!FIELD_TYPES.includes(f.type)) throw new HttpError(400, `field type must be one of ${FIELD_TYPES.join(", ")}`);
    let key = typeof f.key === "string" && /^[a-z0-9_]{1,40}$/.test(f.key) ? f.key : slugKey(label);
    while (seen.has(key)) key = `${key.slice(0, 36)}_${out.length + 1}`;
    seen.add(key);
    out.push({ key, label, type: f.type, required: f.required === true });
  }
  if (existing) {
    for (const old of existing) {
      const now = out.find((x) => x.key === old.key);
      if (now && now.type !== old.type) throw new HttpError(400, `Cannot change the type of field "${old.key}"`);
    }
  }
  return out;
}

function validateAudience(a) {
  a = a && typeof a === "object" ? a : {};
  const classes = Array.isArray(a.classes) ? a.classes.slice(0, 30).map((c) => cleanText(c, 40, "class")) : [];
  return { teachers: a.teachers === true, students: a.students === true, parents: a.parents === true, classes };
}

function publicDataset(id, d, role, ctxRole) {
  const admin = ctxRole === "schoolAdmin";
  return {
    id,
    name: d.name || "",
    description: d.description || "",
    fields: Array.isArray(d.fields) ? d.fields : [],
    teachersCanUpload: d.teachersCanUpload === true,
    canUpload: admin || (ctxRole === "teacher" && d.teachersCanUpload === true && d.archived !== true),
    archived: d.archived === true,
    createdAt: d.createdAt || null,
    ...(admin ? { audience: d.audience || {} } : {}),
  };
}

async function handleListDatasets(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const [ctx, rows] = await Promise.all([
    viewerContext(env, schoolId, user),
    fsQuery(env, schoolPath(schoolId), { from: [{ collectionId: "datasets" }], limit: 200 }),
  ]);
  const list = rows
    .filter((r) => datasetVisible(r.data, ctx))
    .map((r) => publicDataset(r.id, r.data, user.role, ctx.role))
    .sort((a, b) => a.name.localeCompare(b.name));
  return { datasets: list };
}

async function handleCreateDataset(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  const data = {
    name: cleanText(body.name, 100, "name"),
    description: cleanOptionalText(body.description, 500, "description"),
    fields: validateFields(body.fields, null),
    audience: validateAudience(body.audience),
    teachersCanUpload: body.teachersCanUpload === true,
    archived: false,
    createdBy: String(admin.sub),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const created = await fsCreate(env, `${schoolPath(schoolId)}/datasets`, data, generateId());
  await logChange(env, schoolId, { action: "dataset.create", by: String(admin.sub), datasetId: created.id, name: data.name });
  return publicDataset(created.id, { ...data }, "schoolAdmin", "schoolAdmin");
}

async function handleUpdateDataset(request, env, schoolId, datasetId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  const existing = await fsGet(env, `${schoolPath(schoolId)}/datasets/${enc(datasetId)}`);
  if (!existing) throw new HttpError(404, "Data set not found");

  const patch = { updatedAt: new Date().toISOString() };
  if (body.name !== undefined) patch.name = cleanText(body.name, 100, "name");
  if (body.description !== undefined) patch.description = cleanOptionalText(body.description, 500, "description");
  if (body.fields !== undefined) patch.fields = validateFields(body.fields, existing.fields || []);
  if (body.audience !== undefined) patch.audience = validateAudience(body.audience);
  if (body.teachersCanUpload !== undefined) patch.teachersCanUpload = body.teachersCanUpload === true;
  if (body.archived !== undefined) patch.archived = body.archived === true;

  await fsPatch(env, `${schoolPath(schoolId)}/datasets/${enc(datasetId)}`, patch);
  await logChange(env, schoolId, { action: "dataset.update", by: String(admin.sub), datasetId, changed: Object.keys(patch) });
  return publicDataset(datasetId, { ...existing, ...patch }, "schoolAdmin", "schoolAdmin");
}

function publicEntry(e, ds, ctx) {
  const canDelete = ctx.role === "schoolAdmin" || (ctx.role === "teacher" && e.data.createdBy === ctx.uid && ds.teachersCanUpload === true);
  return {
    id: e.id,
    datasetId: e.data.datasetId,
    title: e.data.title || "",
    values: e.data.values || {},
    classes: e.data.classes || [],
    createdAt: e.data.createdAt || null,
    createdBy: e.data.createdBy || null,
    createdByRole: e.data.createdByRole || null,
    canDelete,
  };
}

async function handleListEntries(request, env, schoolId, datasetId) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const [ctx, ds] = await Promise.all([
    viewerContext(env, schoolId, user),
    fsGet(env, `${schoolPath(schoolId)}/datasets/${enc(datasetId)}`),
  ]);
  if (!ds || !datasetVisible(ds, ctx)) throw new HttpError(404, "Data set not found");
  const rows = await fsQuery(env, schoolPath(schoolId), {
    from: [{ collectionId: "datasetEntries" }],
    where: fsEq("datasetId", datasetId),
    limit: MAX_LIST,
  });
  const entries = rows
    .filter((e) => entryVisible(ds, e.data, ctx))
    .sort((a, b) => str(b.data.createdAt).localeCompare(str(a.data.createdAt)))
    .map((e) => publicEntry(e, ds, ctx));
  return { dataset: publicDataset(datasetId, ds, user.role, ctx.role), entries };
}

async function handleCreateEntry(request, env, schoolId, datasetId) {
  const user = await requireUser(request, env, schoolId, STAFF);
  const ds = await fsGet(env, `${schoolPath(schoolId)}/datasets/${enc(datasetId)}`);
  if (!ds) throw new HttpError(404, "Data set not found");
  if (ds.archived === true) throw new HttpError(409, "This data set is archived");
  if (user.role === "teacher" && ds.teachersCanUpload !== true) {
    throw new HttpError(403, "Teachers are not allowed to add to this data set");
  }

  // Parse multipart (with files) or plain JSON
  let title, values = {}, classesIn = [];
  const files = {};
  const ctype = request.headers.get("Content-Type") || "";
  if (ctype.includes("multipart/form-data")) {
    let form;
    try { form = await request.formData(); } catch (err) { throw new HttpError(400, `Could not parse form: ${err.message}`); }
    title = str(form.get("title"));
    try { values = JSON.parse(str(form.get("values")) || "{}"); } catch { throw new HttpError(400, "values must be JSON"); }
    try { classesIn = JSON.parse(str(form.get("classes")) || "[]"); } catch { throw new HttpError(400, "classes must be JSON"); }
    for (const f of ds.fields || []) {
      if (f.type !== "file") continue;
      const part = form.get(`file_${f.key}`);
      if (part && typeof part !== "string" && typeof part.arrayBuffer === "function" && part.size > 0) files[f.key] = part;
    }
  } else {
    const body = await safeJson(request);
    title = str(body.title);
    values = body.values && typeof body.values === "object" ? body.values : {};
    classesIn = Array.isArray(body.classes) ? body.classes : [];
  }

  title = cleanText(title, 200, "title");
  if (!values || typeof values !== "object" || Array.isArray(values)) throw new HttpError(400, "values must be an object");
  const classes = Array.isArray(classesIn) ? classesIn.slice(0, 30).map((c) => cleanText(c, 40, "class")) : [];
  if (Object.keys(files).length > MAX_FILES_PER_ENTRY) throw new HttpError(400, `Max ${MAX_FILES_PER_ENTRY} files per entry`);

  // Validate everything before any upload happens
  const cleaned = {};
  for (const f of ds.fields || []) {
    if (f.type === "file") {
      if (!files[f.key]) {
        if (f.required) throw new HttpError(400, `${f.label} is required (send multipart with file_${f.key})`);
        continue;
      }
      const file = files[f.key];
      if (file.size > MAX_FILE_MB * 1024 * 1024) throw new HttpError(400, `${f.label}: file too large (max ${MAX_FILE_MB} MB)`);
      const name = str(file.name);
      const dot = name.lastIndexOf(".");
      const ext = dot >= 0 ? name.slice(dot).toLowerCase() : "";
      if (![].concat(...Object.values(FILE_KINDS).map((k) => k.exts)).includes(ext)) {
        throw new HttpError(400, `${f.label}: only PDF or image files (png, jpg, gif, webp)`);
      }
      continue;
    }
    if (f.type === "date") {
      const v = str(values[f.key]).trim();
      if (!v) { if (f.required) throw new HttpError(400, `${f.label} is required`); continue; }
      const d = new Date(`${v}T00:00:00Z`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) {
        throw new HttpError(400, `${f.label} must be a date as YYYY-MM-DD`);
      }
      cleaned[f.key] = v;
      continue;
    }
    const v = cleanOptionalText(values[f.key], f.type === "note" ? 5000 : 500, f.label);
    if (!v && f.required) throw new HttpError(400, `${f.label} is required`);
    if (v) cleaned[f.key] = v;
  }

  // Process files: content check, virus scan, store
  const entryId = generateId();
  const nowIso = new Date().toISOString();
  for (const f of ds.fields || []) {
    if (f.type !== "file" || !files[f.key]) continue;
    const file = files[f.key];
    const bytes = await file.arrayBuffer();
    const kind = detectFileKind(bytes);
    const name = str(file.name);
    const ext = name.lastIndexOf(".") >= 0 ? name.slice(name.lastIndexOf(".")).toLowerCase() : "";
    if (!kind || !FILE_KINDS[kind].exts.includes(ext)) throw new HttpError(400, `${f.label}: file content does not match its type`);

    const scan = await scanFile(env, bytes, name);
    if (!scan.clean) throw new HttpError(400, `${f.label}: file failed the virus scan`, { foundViruses: scan.found });

    const up = await uploadToCloudinary(env, bytes, FILE_KINDS[kind].exts[0], `edutraceug/datasets/${schoolId}/${datasetId}`);
    const fileId = generateId();
    const safeName = name.replace(/[^\w.\- ]+/g, "_").slice(0, 120) || `file${ext}`;
    await fsCreate(env, `${schoolPath(schoolId)}/datasetFiles`, {
      datasetId, entryId, fieldKey: f.key,
      url: up.url, publicId: up.publicId,
      name: safeName, mime: FILE_KINDS[kind].mime, size: file.size,
      uploadedBy: String(user.sub), uploadedAt: nowIso,
    }, fileId);
    cleaned[f.key] = { fileId, name: safeName, mime: FILE_KINDS[kind].mime, size: file.size };
  }

  const entry = {
    datasetId, title, values: cleaned, classes,
    createdBy: String(user.sub), createdByRole: user.role,
    createdAt: nowIso, updatedAt: nowIso,
  };
  await fsCreate(env, `${schoolPath(schoolId)}/datasetEntries`, entry, entryId);
  await logChange(env, schoolId, { action: "dataset.entry.create", by: String(user.sub), role: user.role, datasetId, entryId, title });
  return { status: "ok", id: entryId, entry: { id: entryId, ...entry } };
}

async function handleDeleteEntry(request, env, schoolId, entryId) {
  const user = await requireUser(request, env, schoolId, STAFF);
  const entry = await fsGet(env, `${schoolPath(schoolId)}/datasetEntries/${enc(entryId)}`);
  if (!entry) throw new HttpError(404, "Entry not found");
  if (user.role === "teacher") {
    const ds = await fsGet(env, `${schoolPath(schoolId)}/datasets/${enc(entry.datasetId)}`);
    if (!ds || ds.teachersCanUpload !== true || entry.createdBy !== String(user.sub)) {
      throw new HttpError(403, "You can only delete your own uploads");
    }
  }
  await fsDelete(env, `${schoolPath(schoolId)}/datasetEntries/${enc(entryId)}`);
  for (const v of Object.values(entry.values || {})) {
    if (v && typeof v === "object" && v.fileId) {
      const fp = `${schoolPath(schoolId)}/datasetFiles/${enc(v.fileId)}`;
      try {
        const f = await fsGet(env, fp);
        if (f && f.publicId) await destroyOnCloudinary(env, f.publicId);
        await fsDelete(env, fp);
      } catch (err) {
        console.error("File cleanup failed:", err && err.message);
      }
    }
  }
  await logChange(env, schoolId, { action: "dataset.entry.delete", by: String(user.sub), entryId, datasetId: entry.datasetId });
  return { status: "ok" };
}

// Role-checked proxy. The Cloudinary URL is never sent to the browser.
async function handleGetFile(request, env, schoolId, fileId) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const file = await fsGet(env, `${schoolPath(schoolId)}/datasetFiles/${enc(fileId)}`);
  if (!file) throw new HttpError(404, "File not found");
  const [entry, ds, ctx] = await Promise.all([
    fsGet(env, `${schoolPath(schoolId)}/datasetEntries/${enc(file.entryId)}`),
    fsGet(env, `${schoolPath(schoolId)}/datasets/${enc(file.datasetId)}`),
    viewerContext(env, schoolId, user),
  ]);
  if (!entry || !ds || !entryVisible(ds, entry, ctx)) throw new HttpError(403, "You cannot view this file");

  const upstream = await xfetch(file.url);
  if (!upstream.ok) throw new HttpError(502, "File storage unavailable");
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": file.mime || "application/octet-stream",
      "Content-Disposition": `inline; filename="${str(file.name).replace(/"/g, "")}"`,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "private, no-store",
      ...CORS_HEADERS,
    },
  });
}

// ================================================================
// 4. Custom subjects
// ================================================================

async function handleListSubjects(request, env, schoolId) {
  await requireUser(request, env, schoolId, ALL_ROLES);
  const rows = await fsQuery(env, schoolPath(schoolId), { from: [{ collectionId: "subjects" }], limit: MAX_LIST });
  return { subjects: rows.map((r) => ({ id: r.id, name: r.data.name || "" })).sort((a, b) => a.name.localeCompare(b.name)) };
}

async function upsertSubject(env, schoolId, name, by) {
  const id = (await sha256Hex(name.toLowerCase())).slice(0, 20);
  await fsPatch(env, `${schoolPath(schoolId)}/subjects/${id}`, { name, createdBy: by, createdAt: new Date().toISOString() });
  return id;
}

async function handleAddSubject(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  const name = cleanText(body.name, 120, "name");
  const id = await upsertSubject(env, schoolId, name, String(admin.sub));
  await logChange(env, schoolId, { action: "subject.add", by: String(admin.sub), name });
  return { id, name };
}

async function handleDeleteSubject(request, env, schoolId, id) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  await fsDelete(env, `${schoolPath(schoolId)}/subjects/${enc(id)}`);
  await logChange(env, schoolId, { action: "subject.delete", by: String(admin.sub), id });
  return { status: "ok", note: "Students keep the subject until you unassign it." };
}

async function handleAssignSubject(request, env, schoolId, mode) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  const subject = cleanText(body.subject, 120, "subject");
  const className = cleanText(body.class, 60, "class");
  const stream = body.stream ? cleanText(body.stream, 60, "stream") : "";
  const only = Array.isArray(body.rosterIds) && body.rosterIds.length ? new Set(body.rosterIds.map(String)) : null;

  const students = await fetchStudents(env, schoolId, ["class", "stream", "subjects"]);
  const writes = [];
  let matched = 0;
  const now = new Date();
  for (const s of students) {
    if (!classMatches(className, s.data.class)) continue;
    if (stream && normKey(s.data.stream) !== normKey(stream)) continue;
    if (only && !only.has(s.id)) continue;
    matched += 1;
    const cur = Array.isArray(s.data.subjects) ? s.data.subjects : [];
    const has = cur.some((x) => String(x).toLowerCase() === subject.toLowerCase());
    let next;
    if (mode === "add") { if (has) continue; next = [...cur, subject]; }
    else { if (!has) continue; next = cur.filter((x) => String(x).toLowerCase() !== subject.toLowerCase()); }
    writes.push(wUpdate(env, ["schools", schoolId, "roster", s.id], { subjects: next, updatedAt: now }, { exists: true }));
  }
  await commitAll(env, writes);
  if (mode === "add") await upsertSubject(env, schoolId, subject, String(admin.sub));
  await logChange(env, schoolId, { action: `subject.${mode}`, by: String(admin.sub), subject, class: className, stream, matched, changed: writes.length });
  return { status: "ok", matched, changed: writes.length };
}

// ================================================================
// 5. Yearly promotion
// ================================================================

// The year a promotion belongs to: Jan and Feb count as "this year", later months as "next year".
function promotionYear(now = new Date()) {
  return now.getUTCMonth() <= 1 ? now.getUTCFullYear() : now.getUTCFullYear() + 1;
}

async function fetchExclusions(env, schoolId, year) {
  return fsQuery(env, schoolPath(schoolId), {
    from: [{ collectionId: "promotionExclusions" }],
    where: fsEq("year", year),
    limit: 5000,
  });
}

function planPromotion(students, excludedIds, year) {
  const moves = [], unparsed = [];
  let already = 0, excluded = 0, done = 0;
  for (const s of students) {
    const cls = str(s.data.class);
    if (s.data.promotedYear === year) { done += 1; continue; }
    if (excludedIds.has(s.id)) { excluded += 1; continue; }
    const p = parseClass(cls);
    if (!p) { unparsed.push({ rosterId: s.id, class: cls }); continue; }
    if (p.previous) { already += 1; continue; }
    moves.push({ id: s.id, from: cls, to: nextClassName(cls) });
  }
  return { moves, unparsed, already, excluded, done };
}

async function executeMoves(env, schoolId, moves, year, limitCalls) {
  let written = 0, graduated = 0;
  for (let i = 0; i < moves.length; i += COMMIT_CHUNK) {
    if (CALLS >= limitCalls) break;
    const chunk = moves.slice(i, i + COMMIT_CHUNK);
    const at = new Date().toISOString();
    await fsCommit(env, chunk.map((m) =>
      wUpdate(env, ["schools", schoolId, "roster", m.id], { class: m.to, prevClass: m.from, promotedYear: year, promotedAt: at }, { exists: true })));
    written += chunk.length;
    graduated += chunk.filter((m) => m.to === PREVIOUS_S6).length;
  }
  return { written, graduated };
}

async function promoteSchool(env, schoolId, year, by, limitCalls, schoolDoc) {
  const school = schoolDoc || (await fsGet(env, schoolPath(schoolId))) || {};
  const run = school.promotionRun && school.promotionRun.year === year ? school.promotionRun : null;
  const [students, excl] = await Promise.all([
    fetchStudents(env, schoolId, ["class", "promotedYear"]),
    fetchExclusions(env, schoolId, year),
  ]);
  const plan = planPromotion(students, new Set(excl.map((e) => e.id)), year);
  const res = await executeMoves(env, schoolId, plan.moves, year, limitCalls);
  const remaining = plan.moves.length - res.written;
  const nowIso = new Date().toISOString();
  const next = {
    year,
    status: remaining === 0 ? "done" : "in_progress",
    promoted: ((run && run.promoted) || 0) + res.written,
    graduated: ((run && run.graduated) || 0) + res.graduated,
    skippedUnparsed: plan.unparsed.length,
    excluded: plan.excluded,
    startedAt: (run && run.startedAt) || nowIso,
    finishedAt: remaining === 0 ? nowIso : null,
    by,
  };
  await fsPatch(env, schoolPath(schoolId), { promotionRun: next });
  if (remaining === 0) await logChange(env, schoolId, { action: "promotion.done", by, year, promoted: next.promoted, graduated: next.graduated });
  return { run: next, remaining, unparsed: plan.unparsed.slice(0, 50) };
}

async function runScheduled(env) {
  CALLS = 0;
  const year = new Date().getUTCFullYear();
  let schools;
  try {
    schools = await fsQuery(env, "", { from: [{ collectionId: "schools" }], limit: 300 });
  } catch (err) {
    console.error("Promotion: could not list schools:", err && err.message);
    return;
  }
  for (const s of schools) {
    if (CALLS >= CRON_CALL_BUDGET) break;
    if (s.data.autoPromote === false) continue;
    const run = s.data.promotionRun;
    if (run && run.year === year && (run.status === "done" || run.status === "undone")) continue;
    try {
      await promoteSchool(env, s.id, year, "cron", CRON_CALL_BUDGET, s.data);
    } catch (err) {
      console.error(`Promotion failed for ${s.id}:`, err && err.message);
    }
  }
}

async function handlePromotionStatus(request, env, schoolId) {
  await requireUser(request, env, schoolId, ADMIN);
  const school = (await fsGet(env, schoolPath(schoolId))) || {};
  return { year: promotionYear(), autoPromote: school.autoPromote !== false, run: school.promotionRun || null };
}

async function handlePromotionSettings(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  if (typeof body.autoPromote !== "boolean") throw new HttpError(400, "autoPromote must be boolean");
  await fsPatch(env, schoolPath(schoolId), { autoPromote: body.autoPromote });
  await logChange(env, schoolId, { action: "promotion.settings", by: String(admin.sub), autoPromote: body.autoPromote });
  return { autoPromote: body.autoPromote };
}

async function handlePromotionPreview(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ADMIN);
  const year = Number(url.searchParams.get("year")) || promotionYear();
  const [students, excl] = await Promise.all([
    fetchStudents(env, schoolId, ["class", "promotedYear"]),
    fetchExclusions(env, schoolId, year),
  ]);
  const plan = planPromotion(students, new Set(excl.map((e) => e.id)), year);
  const groups = new Map();
  for (const m of plan.moves) {
    const k = `${m.from}|${m.to}`;
    groups.set(k, (groups.get(k) || 0) + 1);
  }
  const summary = [...groups].map(([k, count]) => { const [from, to] = k.split("|"); return { from, to, count }; })
    .sort((a, b) => a.from.localeCompare(b.from));
  return {
    year,
    willMove: plan.moves.length,
    summary,
    excluded: plan.excluded,
    alreadyPromoted: plan.done,
    alreadyPrevious: plan.already,
    unrecognisedClass: plan.unparsed.slice(0, 100),
  };
}

async function handlePromotionRun(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await request.json().catch(() => ({}));
  const year = Number(body.year) || promotionYear();
  const school = (await fsGet(env, schoolPath(schoolId))) || {};
  const run = school.promotionRun;
  if (run && run.year === year && run.status === "done" && body.force !== true) {
    throw new HttpError(409, "Promotion for this year is already done. Send force: true to promote students added since.");
  }
  if (run && run.year === year && run.status === "undone" && body.force !== true) {
    throw new HttpError(409, "Promotion for this year was undone. Send force: true to run it again.");
  }
  const result = await promoteSchool(env, schoolId, year, String(admin.sub), CALLS + MANUAL_CALL_BUDGET, school);
  return { status: "ok", ...result };
}

async function handlePromotionUndo(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await request.json().catch(() => ({}));
  const year = Number(body.year) || promotionYear();
  const limit = CALLS + MANUAL_CALL_BUDGET;

  // Mark undone first so the cron cannot promote again while this runs
  await fsPatch(env, schoolPath(schoolId), {
    promotionRun: { year, status: "undone", undoneAt: new Date().toISOString(), by: String(admin.sub) },
  });

  const students = await fetchStudents(env, schoolId, ["class", "prevClass", "promotedYear"]);
  const todo = students.filter((s) => s.data.promotedYear === year && s.data.prevClass);
  let reverted = 0;
  for (let i = 0; i < todo.length; i += COMMIT_CHUNK) {
    if (CALLS >= limit) break;
    const chunk = todo.slice(i, i + COMMIT_CHUNK);
    await fsCommit(env, chunk.map((s) =>
      wUpdate(env, ["schools", schoolId, "roster", s.id], { class: s.data.prevClass }, {
        mask: ["class", "prevClass", "promotedYear", "promotedAt"], exists: true,
      })));
    reverted += chunk.length;
  }
  const remaining = todo.length - reverted;
  await logChange(env, schoolId, { action: "promotion.undo", by: String(admin.sub), year, reverted, remaining });
  return { status: "ok", year, reverted, remaining };
}

async function handleListExclusions(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ADMIN);
  const year = Number(url.searchParams.get("year")) || promotionYear();
  const rows = await fetchExclusions(env, schoolId, year);
  return { year, exclusions: rows.map((r) => ({ rosterId: r.id, year: r.data.year, at: r.data.at || null })) };
}

async function handleAddExclusions(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  const year = Number(body.year) || promotionYear();
  if (!Array.isArray(body.rosterIds) || body.rosterIds.length === 0 || body.rosterIds.length > 500) {
    throw new HttpError(400, "rosterIds must be a list of 1-500 ids");
  }
  const at = new Date().toISOString();
  const writes = body.rosterIds.map((id) => {
    const rid = cleanText(String(id), 60, "rosterId");
    return wUpdate(env, ["schools", schoolId, "promotionExclusions", rid], { rosterId: rid, year, by: String(admin.sub), at });
  });
  await commitAll(env, writes);
  await logChange(env, schoolId, { action: "promotion.exclude", by: String(admin.sub), year, count: writes.length });
  return { status: "ok", year, count: writes.length };
}

async function handleRemoveExclusion(request, env, schoolId, rosterId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  await fsDelete(env, `${schoolPath(schoolId)}/promotionExclusions/${enc(rosterId)}`);
  await logChange(env, schoolId, { action: "promotion.unexclude", by: String(admin.sub), rosterId });
  return { status: "ok" };
}

// ================================================================
// 6. Class materials (PDF uploads by admin or permitted teachers)
// ================================================================
//
// schools/{sid}/materials/{id}        title, description, subject, classes[], uploader
// schools/{sid}/materialFiles/{id}    Cloudinary URL (never sent to clients), same id as the material
// schools/{sid}/settings/materials    { teacherAccess: "all" | "selected" | "none", teacherIds: [uid] }

async function getMaterialSettings(env, schoolId) {
  const doc = await fsGet(env, `${schoolPath(schoolId)}/settings/materials`);
  const mode = doc && ["all", "selected", "none"].includes(doc.teacherAccess) ? doc.teacherAccess : "none";
  const ids = doc && Array.isArray(doc.teacherIds) ? doc.teacherIds.map(String) : [];
  return { teacherAccess: mode, teacherIds: ids };
}

function teacherMayUpload(settings, uid) {
  return settings.teacherAccess === "all" || (settings.teacherAccess === "selected" && settings.teacherIds.includes(uid));
}

function materialVisible(d, ctx) {
  if (ctx.role === "schoolAdmin") return true;
  if (ctx.role === "teacher") return d.createdBy === ctx.uid;
  return classAllowed(d.classes, ctx.className);
}

function publicMaterial(id, d, ctx) {
  return {
    id,
    title: d.title || "",
    description: d.description || "",
    subject: d.subject || "",
    classes: Array.isArray(d.classes) ? d.classes : [],
    fileName: d.fileName || "",
    size: d.size || 0,
    createdAt: d.createdAt || null,
    createdBy: d.createdBy || null,
    createdByRole: d.createdByRole || null,
    canDelete: ctx.role === "schoolAdmin" || (ctx.role === "teacher" && d.createdBy === ctx.uid),
  };
}

async function handleGetMaterialSettings(request, env, schoolId) {
  await requireUser(request, env, schoolId, ADMIN);
  return getMaterialSettings(env, schoolId);
}

async function handleSetMaterialSettings(request, env, schoolId) {
  const admin = await requireUser(request, env, schoolId, ADMIN);
  const body = await safeJson(request);
  if (!["all", "selected", "none"].includes(body.teacherAccess)) {
    throw new HttpError(400, "teacherAccess must be all, selected or none");
  }
  const ids = Array.isArray(body.teacherIds) ? body.teacherIds.slice(0, 500).map((i) => cleanText(String(i), 128, "teacherId")) : [];
  const data = {
    teacherAccess: body.teacherAccess,
    teacherIds: ids,
    updatedAt: new Date().toISOString(),
    updatedBy: String(admin.sub),
  };
  await fsPatch(env, `${schoolPath(schoolId)}/settings/materials`, data);
  await logChange(env, schoolId, { action: "materials.settings", by: String(admin.sub), teacherAccess: data.teacherAccess, teachers: ids.length });
  return { teacherAccess: data.teacherAccess, teacherIds: ids };
}

async function handleListMaterials(request, env, schoolId, url) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const [ctx, settings, rows] = await Promise.all([
    viewerContext(env, schoolId, user),
    user.role === "teacher" ? getMaterialSettings(env, schoolId) : Promise.resolve(null),
    fsQuery(env, schoolPath(schoolId), { from: [{ collectionId: "materials" }], limit: MAX_LIST }),
  ]);
  const classFilter = url.searchParams.get("class");
  const subjectFilter = url.searchParams.get("subject");
  const list = rows
    .filter((r) => materialVisible(r.data, ctx))
    .filter((r) => !classFilter || classAllowed(r.data.classes, classFilter))
    .filter((r) => !subjectFilter || normKey(r.data.subject) === normKey(subjectFilter))
    .sort((a, b) => str(b.data.createdAt).localeCompare(str(a.data.createdAt)))
    .map((r) => publicMaterial(r.id, r.data, ctx));
  const canUpload = user.role === "schoolAdmin" || (user.role === "teacher" && teacherMayUpload(settings, ctx.uid));
  return { canUpload, materials: list };
}

async function handleCreateMaterial(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, STAFF);
  if (user.role === "teacher") {
    const settings = await getMaterialSettings(env, schoolId);
    if (!teacherMayUpload(settings, String(user.sub))) throw new HttpError(403, "The admin has not given you upload access");
  }

  let form;
  try { form = await request.formData(); } catch (err) { throw new HttpError(400, `Send multipart/form-data: ${err.message}`); }
  const file = form.get("file");
  if (!file || typeof file === "string" || typeof file.arrayBuffer !== "function") throw new HttpError(400, '"file" is required');

  const title = cleanText(str(form.get("title")), 200, "title");
  const description = cleanOptionalText(str(form.get("description")), 1000, "description");
  const subject = cleanOptionalText(str(form.get("subject")), 120, "subject");
  let classesIn = [];
  try { classesIn = JSON.parse(str(form.get("classes")) || "[]"); } catch { throw new HttpError(400, "classes must be JSON"); }
  const classes = Array.isArray(classesIn) ? classesIn.slice(0, 30).map((c) => cleanText(c, 40, "class")) : [];

  if (file.size > MAX_FILE_MB * 1024 * 1024) throw new HttpError(400, `File too large (max ${MAX_FILE_MB} MB)`);
  const name = str(file.name);
  if (!name.toLowerCase().endsWith(".pdf")) throw new HttpError(400, "Only PDF files are allowed");
  const bytes = await file.arrayBuffer();
  if (detectFileKind(bytes) !== "pdf") throw new HttpError(400, "File content is not a valid PDF");

  const scan = await scanFile(env, bytes, name);
  if (!scan.clean) throw new HttpError(400, "File failed the virus scan", { foundViruses: scan.found });
  const up = await uploadToCloudinary(env, bytes, ".pdf", `edutraceug/materials/${schoolId}`);

  const id = generateId();
  const nowIso = new Date().toISOString();
  const safeName = name.replace(/[^\w.\- ]+/g, "_").slice(0, 120) || "material.pdf";
  await fsCreate(env, `${schoolPath(schoolId)}/materialFiles`, {
    url: up.url, publicId: up.publicId, name: safeName, mime: "application/pdf", size: file.size,
  }, id);
  const doc = {
    title, description, subject, classes,
    fileName: safeName, size: file.size,
    createdBy: String(user.sub), createdByRole: user.role, createdAt: nowIso,
  };
  await fsCreate(env, `${schoolPath(schoolId)}/materials`, doc, id);
  await logChange(env, schoolId, { action: "material.create", by: String(user.sub), role: user.role, materialId: id, title, classes });
  return { status: "ok", material: publicMaterial(id, doc, { role: user.role, uid: String(user.sub) }) };
}

async function handleDeleteMaterial(request, env, schoolId, id) {
  const user = await requireUser(request, env, schoolId, STAFF);
  const doc = await fsGet(env, `${schoolPath(schoolId)}/materials/${enc(id)}`);
  if (!doc) throw new HttpError(404, "Material not found");
  if (user.role === "teacher" && doc.createdBy !== String(user.sub)) throw new HttpError(403, "You can only delete your own uploads");
  const fp = `${schoolPath(schoolId)}/materialFiles/${enc(id)}`;
  const f = await fsGet(env, fp);
  await fsDelete(env, `${schoolPath(schoolId)}/materials/${enc(id)}`);
  if (f) {
    if (f.publicId) await destroyOnCloudinary(env, f.publicId);
    await fsDelete(env, fp);
  }
  await logChange(env, schoolId, { action: "material.delete", by: String(user.sub), materialId: id });
  return { status: "ok" };
}

async function handleGetMaterialFile(request, env, schoolId, id) {
  const user = await requireUser(request, env, schoolId, ALL_ROLES);
  const [doc, file, ctx] = await Promise.all([
    fsGet(env, `${schoolPath(schoolId)}/materials/${enc(id)}`),
    fsGet(env, `${schoolPath(schoolId)}/materialFiles/${enc(id)}`),
    viewerContext(env, schoolId, user),
  ]);
  if (!doc || !file) throw new HttpError(404, "Material not found");
  if (!materialVisible(doc, ctx)) throw new HttpError(403, "You cannot view this file");
  const upstream = await xfetch(file.url);
  if (!upstream.ok) throw new HttpError(502, "File storage unavailable");
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename="${str(file.name).replace(/"/g, "")}"`,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "private, no-store",
      ...CORS_HEADERS,
    },
  });
}

// ================================================================
// Router
// ================================================================

async function handle(request, env) {
  CALLS = 0;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (method === "GET" && path === "/health") return json({ status: "ok", service: "edutraceug-extras-worker" });

  const d = decodeURIComponent;
  const S = "([^/]+)";
  const route = (verb, pattern) => (method === verb ? path.match(new RegExp(`^/schools/${S}${pattern}$`)) : null);
  let m;

  // Report card
  if ((m = route("GET", "/report-card"))) return handleReportCard(request, env, d(m[1]), url);

  // Analytics
  if ((m = route("GET", "/analytics/compare"))) return handleCompare(request, env, d(m[1]), url);

  // Subjects
  if ((m = route("GET", "/subjects"))) return json(await handleListSubjects(request, env, d(m[1])));
  if ((m = route("POST", "/subjects"))) return json(await handleAddSubject(request, env, d(m[1])), 201);
  if ((m = route("POST", "/subjects/assign"))) return json(await handleAssignSubject(request, env, d(m[1]), "add"));
  if ((m = route("POST", "/subjects/unassign"))) return json(await handleAssignSubject(request, env, d(m[1]), "remove"));
  if ((m = route("DELETE", `/subjects/${S}`))) return json(await handleDeleteSubject(request, env, d(m[1]), d(m[2])));

  // Data sets
  if ((m = route("GET", "/datasets"))) return json(await handleListDatasets(request, env, d(m[1])));
  if ((m = route("POST", "/datasets"))) return json(await handleCreateDataset(request, env, d(m[1])), 201);
  if ((m = route("PATCH", `/datasets/${S}`))) return json(await handleUpdateDataset(request, env, d(m[1]), d(m[2])));
  if ((m = route("GET", `/datasets/${S}/entries`))) return json(await handleListEntries(request, env, d(m[1]), d(m[2])));
  if ((m = route("POST", `/datasets/${S}/entries`))) return json(await handleCreateEntry(request, env, d(m[1]), d(m[2])), 201);
  if ((m = route("DELETE", `/entries/${S}`))) return json(await handleDeleteEntry(request, env, d(m[1]), d(m[2])));
  if ((m = route("GET", `/files/${S}`))) return handleGetFile(request, env, d(m[1]), d(m[2]));

  // Class materials (PDF)
  if ((m = route("GET", "/materials/settings"))) return json(await handleGetMaterialSettings(request, env, d(m[1])));
  if ((m = route("PUT", "/materials/settings"))) return json(await handleSetMaterialSettings(request, env, d(m[1])));
  if ((m = route("GET", "/materials"))) return json(await handleListMaterials(request, env, d(m[1]), url));
  if ((m = route("POST", "/materials"))) return json(await handleCreateMaterial(request, env, d(m[1])), 201);
  if ((m = route("GET", `/materials/${S}/file`))) return handleGetMaterialFile(request, env, d(m[1]), d(m[2]));
  if ((m = route("DELETE", `/materials/${S}`))) return json(await handleDeleteMaterial(request, env, d(m[1]), d(m[2])));

  // Promotion
  if ((m = route("GET", "/promotion/status"))) return json(await handlePromotionStatus(request, env, d(m[1])));
  if ((m = route("PUT", "/promotion/settings"))) return json(await handlePromotionSettings(request, env, d(m[1])));
  if ((m = route("GET", "/promotion/preview"))) return json(await handlePromotionPreview(request, env, d(m[1]), url));
  if ((m = route("POST", "/promotion/run"))) return json(await handlePromotionRun(request, env, d(m[1])));
  if ((m = route("POST", "/promotion/undo"))) return json(await handlePromotionUndo(request, env, d(m[1])));
  if ((m = route("GET", "/promotion/exclusions"))) return json(await handleListExclusions(request, env, d(m[1]), url));
  if ((m = route("POST", "/promotion/exclusions"))) return json(await handleAddExclusions(request, env, d(m[1])));
  if ((m = route("DELETE", `/promotion/exclusions/${S}`))) return json(await handleRemoveExclusion(request, env, d(m[1]), d(m[2])));

  return json({ error: "Not found" }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message, ...err.extra }, err.status);
      console.error("Unhandled error:", err && err.stack ? err.stack : err);
      return json({ error: "Internal server error" }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env));
  },
};
