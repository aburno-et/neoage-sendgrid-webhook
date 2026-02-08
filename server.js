"use strict";

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
// Lazy-load Google auth so missing deps never prevent SendGrid ingestion from running
let OAuth2Client = null;
function loadGoogleAuth() {
  if (OAuth2Client) return;
  try {
    ({ OAuth2Client } = require("google-auth-library"));
  } catch (e) {
    const msg = String(e?.message || e);
    throw new Error(
      `google-auth-library is not installed. Add it to package.json dependencies and redeploy. Original error: ${msg}`
    );
  }
}


// Node 18+ has global fetch (Render uses Node 25 in your logs)

// -------------------- App --------------------
const app = express();
app.use(express.json({ limit: "5mb" }));

// Hardening: keep the process alive through transient errors
process.on("unhandledRejection", (err) => console.error("[unhandledRejection]", err));
process.on("uncaughtException", (err) => console.error("[uncaughtException]", err));

// -------------------- Config --------------------
const PORT = process.env.PORT || 10000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) console.error("Missing DATABASE_URL env var");

// SendGrid Email Activity API only allows last ~30 days.
// Buffer avoids edge/clock/rounding issues.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const SAFETY_MS = 5 * 60 * 1000; // 5 minutes

// If /v3/logs search returns 1000, split windows.
// If we still hit 1000 at MIN_WINDOW_MS, we SKIP hydration and advance cursor (reliability-first).
const MIN_WINDOW_MS = Number(process.env.MIN_WINDOW_MS || 1000); // 1 second
const SG_LOGS_LIMIT = 1000;

// Concurrency for hydration (message detail fetches)
const HYDRATE_CONCURRENCY = Math.max(1, Number(process.env.HYDRATE_CONCURRENCY || 1));
const PER_REQUEST_DELAY_MS = Math.max(0, Number(process.env.PER_REQUEST_DELAY_MS || 100));

// Rolling window we actively update (data is retained 30 days total)
const ROLLING_WINDOW_HOURS = Number(process.env.ROLLING_WINDOW_HOURS || 48);
const ROLLING_WINDOW_MS = ROLLING_WINDOW_HOURS * 60 * 60 * 1000;

// Chunk the poll so we advance cursor progressively (helps avoid timeouts/stalls)
const CHUNK_MS = Math.max(60_000, Number(process.env.POLL_CHUNK_MS || 5 * 60 * 1000)); // default 5 min

// -------------------- Postgres --------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on("error", (err) => {
  console.error("[PG Pool Error]", err);
});

// -------------------- Google Postmaster Tools --------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;

const GPT_DOMAINS = (process.env.GPT_DOMAINS || "")
  .split(",")
  .map((d) => d.trim())
  .filter(Boolean);

function requireGptEnv() {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) {
    throw new Error("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN");
  }
  if (!GPT_DOMAINS.length) throw new Error("GPT_DOMAINS is empty");
}

async function getGptAccessToken() {
  loadGoogleAuth();
  const oauth2 = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
  oauth2.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  const { token } = await oauth2.getAccessToken();
  if (!token) throw new Error("Failed to obtain GPT access token");
  return token;
}

// Convert a JS Date (UTC) into the Gmail Postmaster Tools Date message shape.
function toGptDate(dt) {
  return { year: dt.getUTCFullYear(), month: dt.getUTCMonth() + 1, day: dt.getUTCDate() };
}

// IMPORTANT (v1): trafficStats is retrieved via LIST, not :query.
// Uses primitive query params: startDate.year/month/day and endDate.year/month/day.
async function fetchGptTrafficStats(domain, startDate, endDate, accessToken) {
  // startDate/endDate must be objects like: { year, month, day }
  const base =
    "https://gmailpostmastertools.googleapis.com/v1/domains/" +
    encodeURIComponent(domain) +
    "/trafficStats";

  const qs = new URLSearchParams({
    "startDate.year": String(startDate.year),
    "startDate.month": String(startDate.month),
    "startDate.day": String(startDate.day),
    "endDate.year": String(endDate.year),
    "endDate.month": String(endDate.month),
    "endDate.day": String(endDate.day),
    // optional: keep pages reasonable
    "pageSize": "500",
  });

  const url = base + "?" + qs.toString();

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: "Bearer " + accessToken,
    },
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    throw new Error("GPT API " + res.status + ": " + JSON.stringify(json, null, 2));
  }

  // Normalize: always return an object with trafficStats array
  // v1 responses generally return { trafficStats: [...], nextPageToken?: "..." }
  return json;
}



// -------------------- DB init --------------------
async function initDb() {
  await pool.query(`
    create table if not exists sendgrid_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      event_key text unique,

      sg_account text,
      sg_event_id text,
      sg_message_id text,

      event_ts timestamptz,

      event text not null,
      ip inet,
      email text,
      recipient_domain text,

      reason text,
      response text,
      status text,

      sending_domain text,
      stream text,
      campaign text,
      ip_pool text,
      environment text,

      raw jsonb not null
    );
  `);

  await pool.query(`create index if not exists idx_sge_event_ts on sendgrid_events (event_ts desc);`);
  await pool.query(
    `create index if not exists idx_sge_domain_ip_ts on sendgrid_events (sending_domain, ip, event_ts desc);`
  );
  await pool.query(`create index if not exists idx_sge_sg_account_ts on sendgrid_events (sg_account, event_ts desc);`);

  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  // Kept for historical visibility; endpoints are disabled below.
  await pool.query(`
    create table if not exists backfill_runs (
      run_id uuid primary key,
      started_at timestamptz not null default now(),
      finished_at timestamptz,
      status text not null default 'running',
      days int not null,
      note text,
      current_account text,
      current_window_start timestamptz,
      current_window_end timestamptz,
      windows_done int not null default 0,
      messages_found bigint not null default 0,
      hydrated bigint not null default 0,
      inserted bigint not null default 0,
      errors int not null default 0
    );
  `);

  await pool.query(`
    create table if not exists gpt_traffic_stats (
      id bigserial primary key,
      domain text not null,
      day date not null,
      raw jsonb not null,
      fetched_at timestamptz not null default now(),
      unique(domain, day)
    );
  `);
  await pool.query(`create index if not exists idx_gpt_domain_day on gpt_traffic_stats(domain, day desc);`);

  console.log("DB initialized");
}

initDb().catch((err) => console.error("DB init failed:", err));

// -------------------- Accounts --------------------
function loadAccounts() {
  const raw = process.env.SENDGRID_ACCOUNTS_JSON;
  if (raw) {
    try {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr) && arr.length) return arr;
    } catch (e) {
      console.error("Failed to parse SENDGRID_ACCOUNTS_JSON:", e);
    }
  }

  const accounts = [];
  if (process.env.SENDGRID_API_KEY_A) accounts.push({ id: "account_a", apiKey: process.env.SENDGRID_API_KEY_A });
  if (process.env.SENDGRID_API_KEY_B) accounts.push({ id: "account_b", apiKey: process.env.SENDGRID_API_KEY_B });
  if (process.env.SENDGRID_API_KEY_C) accounts.push({ id: "account_c", apiKey: process.env.SENDGRID_API_KEY_C });
  return accounts;
}

const SENDGRID_ACCOUNTS = loadAccounts();
if (!SENDGRID_ACCOUNTS.length) {
  console.warn("No SendGrid accounts found. Set SENDGRID_ACCOUNTS_JSON or SENDGRID_API_KEY_A/B/C.");
}

// -------------------- Helpers --------------------
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isoNoMs(dt) {
  return new Date(dt).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function clampRollingFloor(dt, anchorMs) {
  const floor = new Date(anchorMs - ROLLING_WINDOW_MS);
  return dt < floor ? floor : dt;
}

function makeEventKey({ sgAccount, sgMessageId, event, eventTs, email }) {
  const base = [
    sgAccount || "",
    sgMessageId || "",
    event || "",
    eventTs ? new Date(eventTs).toISOString() : "",
    email || "",
  ].join("|");
  return crypto.createHash("sha1").update(base).digest("hex");
}

function authAdmin(req) {
  const token = req.header("x-admin-token") || "";
  return ADMIN_TOKEN && token === ADMIN_TOKEN;
}

// -------------------- SendGrid fetch (retries) --------------------
async function sgFetch(account, method, path, body, attempt = 0) {
  const url = `https://api.sendgrid.com${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${account.apiKey}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  // Success
  if (res.ok) {
    const txt = await res.text();
    if (!txt) return {};
    try {
      return JSON.parse(txt);
    } catch {
      return { raw: txt };
    }
  }

  // Error body
  const txt = await res.text();
  const msg = txt ? txt.slice(0, 800) : "";

  // Some message_ids returned by /v3/logs search may be unavailable when hydrated.
  // Do not fail the whole poll on a single missing message.
  if (res.status === 404 && method === "GET" && path.startsWith("/v3/logs/")) {
    console.warn(`[SendGrid Skip] ${account.id} ${method} ${path} -> 404 not found`);
    return {};
  }

  // Retry on throttling / transient server errors
  const retryable = res.status === 429 || (res.status >= 500 && res.status <= 599);
  if (retryable && attempt < 6) {
    const backoff = Math.min(30_000, 500 * Math.pow(2, attempt));
    console.warn(`[SendGrid Retry] ${account.id} ${method} ${path} status=${res.status} backoff=${backoff}ms`);
    await sleep(backoff);
    return sgFetch(account, method, path, body, attempt + 1);
  }

  throw new Error(`SendGrid API error (${account.id}) ${res.status}: ${msg}`);
}

// -------------------- Poll state --------------------
async function getLastSeen(sgAccount, anchorMs) {
  const r = await pool.query(`select last_seen from sg_poll_state where sg_account = $1`, [sgAccount]);
  if (r.rows.length) return new Date(r.rows[0].last_seen);

  const seed = new Date(anchorMs - ROLLING_WINDOW_MS);
  await pool.query(
    `insert into sg_poll_state (sg_account, last_seen) values ($1, $2)
     on conflict (sg_account) do nothing`,
    [sgAccount, seed]
  );
  return seed;
}

async function setLastSeen(sgAccount, dt) {
  await pool.query(
    `insert into sg_poll_state (sg_account, last_seen) values ($1, $2)
     on conflict (sg_account) do update set last_seen = excluded.last_seen`,
    [sgAccount, dt]
  );
}

// -------------------- Search IDs in window --------------------
async function sgSearchMessageIds(account, sinceDt, untilDt, anchorMs) {
  const since = clampRollingFloor(sinceDt, anchorMs);
  const until = new Date(untilDt);

  const sinceStr = isoNoMs(since);
  const untilStr = isoNoMs(until);

  const body = {
    query:
      `sg_message_id_created_at > TIMESTAMP "${sinceStr}" ` +
      `AND sg_message_id_created_at <= TIMESTAMP "${untilStr}"`,
    limit: SG_LOGS_LIMIT,
  };

  const search = await sgFetch(account, "POST", "/v3/logs", body);

  const messages = search?.result || search?.results || search?.messages || [];
  const ids = [];
  for (const m of messages) {
    const id = m.sg_message_id || m.message_id || m.sg_message_id_string;
    if (id) ids.push(id);
  }

  return { ids, count: ids.length, sinceStr, untilStr };
}

// -------------------- Hydrate + upsert --------------------
async function upsertEventRow(client, row) {
  const {
    event_key,
    sg_account,
    sg_event_id,
    sg_message_id,
    event_ts,
    event,
    ip,
    email,
    recipient_domain,
    reason,
    response,
    status,
    sending_domain,
    stream,
    campaign,
    ip_pool,
    environment,
    raw,
  } = row;

  await client.query(
    `
    insert into sendgrid_events (
      event_key,
      sg_account, sg_event_id, sg_message_id,
      event_ts, event, ip, email, recipient_domain,
      reason, response, status,
      sending_domain, stream, campaign, ip_pool, environment,
      raw
    )
    values (
      $1,
      $2, $3, $4,
      $5, $6, $7, $8, $9,
      $10, $11, $12,
      $13, $14, $15, $16, $17,
      $18::jsonb
    )
    on conflict (event_key) do update
    set
      sg_event_id     = excluded.sg_event_id,
      event_ts        = excluded.event_ts,
      ip              = excluded.ip,
      reason          = excluded.reason,
      response        = excluded.response,
      status          = excluded.status,
      sending_domain  = excluded.sending_domain,
      stream          = excluded.stream,
      campaign        = excluded.campaign,
      ip_pool         = excluded.ip_pool,
      environment     = excluded.environment,
      raw             = excluded.raw
    `,
    [
      event_key,
      sg_account,
      sg_event_id,
      sg_message_id,
      event_ts,
      event,
      ip,
      email,
      recipient_domain,
      reason,
      response,
      status,
      sending_domain,
      stream,
      campaign,
      ip_pool,
      environment,
      JSON.stringify(raw),
    ]
  );
}

async function hydrateOneMessage(account, sgMessageId) {
  const detail = await sgFetch(account, "GET", `/v3/logs/${encodeURIComponent(sgMessageId)}`);

  const events = detail?.events || detail?.event || detail?.items || detail?.results || [];
  const normalizedEvents = Array.isArray(events) ? events : [events];

  const email = detail?.to_email || detail?.email || detail?.recipient || detail?.to || null;
  const recipientDomain =
    typeof email === "string" && email.includes("@") ? email.split("@").pop().toLowerCase() : null;

  const ca = detail?.custom_args || detail?.unique_args || {};

  if (!normalizedEvents.length) {
    const now = new Date();
    return [
      {
        event_key: makeEventKey({ sgAccount: account.id, sgMessageId, event: "log", eventTs: now, email }),
        sg_account: account.id,
        sg_event_id: null,
        sg_message_id: sgMessageId,
        event_ts: now,
        event: "log",
        ip: detail?.ip || null,
        email,
        recipient_domain: recipientDomain,
        reason: detail?.reason || null,
        response: detail?.response || null,
        status: detail?.status || null,
        sending_domain: ca.sending_domain || null,
        stream: ca.stream || null,
        campaign: ca.campaign || null,
        ip_pool: ca.ip_pool || null,
        environment: ca.environment || null,
        raw: detail,
      },
    ];
  }

  const out = [];
  for (const ev of normalizedEvents) {
    const eventName = (ev?.event || ev?.type || ev?.name || detail?.status || "unknown").toString().toLowerCase();

    let ts = null;
    if (typeof ev?.timestamp === "number") ts = new Date(ev.timestamp * 1000);
    else if (typeof ev?.time === "number") ts = new Date(ev.time * 1000);
    else if (typeof ev?.created_at === "string") ts = new Date(ev.created_at);
    else if (typeof ev?.timestamp === "string") ts = new Date(ev.timestamp);
    else ts = new Date();

    const ip = ev?.ip || detail?.ip || null;
    const reason = ev?.reason || detail?.reason || null;
    const response = ev?.response || detail?.response || null;
    const status = ev?.status || detail?.status || null;

    const eventKey = makeEventKey({ sgAccount: account.id, sgMessageId, event: eventName, eventTs: ts, email });

    out.push({
      event_key: eventKey,
      sg_account: account.id,
      sg_event_id: ev?.sg_event_id || detail?.sg_event_id || null,
      sg_message_id: sgMessageId,
      event_ts: ts,
      event: eventName,
      ip,
      email,
      recipient_domain: recipientDomain,
      reason,
      response,
      status,
      sending_domain: ca.sending_domain || null,
      stream: ca.stream || null,
      campaign: ca.campaign || null,
      ip_pool: ca.ip_pool || null,
      environment: ca.environment || null,
      raw: { detail, ev },
    });
  }

  return out;
}

async function hydrateAndStore(account, sgMessageIds, progressCb) {
  let hydrated = 0;
  let inserted = 0;

  // Single writer (serial DB writes = avoids deadlocks)
  const writer = await pool.connect();
  writer.on("error", (err) => console.error("[PG Client Error]", err));

  const queue = [];
  let doneProducing = false;
  let writerError = null;

  async function writerLoop() {
    try {
      while (!doneProducing || queue.length > 0) {
        const item = queue.shift();
        if (!item) {
          await sleep(5);
          continue;
        }
        await upsertEventRow(writer, item);
        inserted += 1;
      }
    } catch (e) {
      writerError = e;
    }
  }

  const writerPromise = writerLoop();

  try {
    let idx = 0;

    const workers = new Array(HYDRATE_CONCURRENCY).fill(null).map(async () => {
      while (true) {
        if (writerError) throw writerError;

        const myIdx = idx++;
        if (myIdx >= sgMessageIds.length) break;

        const sgMessageId = sgMessageIds[myIdx];
        hydrated += 1;

        const rows = await hydrateOneMessage(account, sgMessageId);
        for (const row of rows) queue.push(row);

        if (PER_REQUEST_DELAY_MS) await sleep(PER_REQUEST_DELAY_MS);

        if (progressCb && hydrated % 100 === 0) {
          await progressCb({ hydrated, inserted });
        }
      }
    });

    await Promise.all(workers);
    doneProducing = true;

    await writerPromise;
    if (writerError) throw writerError;
  } finally {
    doneProducing = true;
    writer.release();
  }

  return { hydrated, inserted };
}

// -------------------- Window splitting --------------------
async function processWindowRecursive(account, sinceDt, untilDt, anchorMs) {
  const since = clampRollingFloor(sinceDt, anchorMs);
  const until = new Date(untilDt);
  const windowMs = until.getTime() - since.getTime();

  const search = await sgSearchMessageIds(account, since, until, anchorMs);

  // If we hit the ceiling, split. If we can't split further, DO NOT hydrate (reliability first).
  if (search.count >= SG_LOGS_LIMIT) {
    if (windowMs <= MIN_WINDOW_MS) {
      console.warn(
        `[Poll] ${account.id} SATURATED at min window since=${search.sinceStr} until=${search.untilStr} count=${search.count} -> skipping hydrate and advancing cursor`
      );

      return {
        foundMessages: search.count,
        hydrated: 0,
        inserted: 0,
        capped: true,
        suggestedAdvanceTo: new Date(until.getTime()),
      };
    }

    const mid = new Date(since.getTime() + Math.floor(windowMs / 2));
    const left = await processWindowRecursive(account, since, mid, anchorMs);
    const right = await processWindowRecursive(account, mid, until, anchorMs);

    return {
      foundMessages: (left.foundMessages || 0) + (right.foundMessages || 0),
      hydrated: (left.hydrated || 0) + (right.hydrated || 0),
      inserted: (left.inserted || 0) + (right.inserted || 0),
      capped: Boolean(left.capped || right.capped),
      suggestedAdvanceTo: [left.suggestedAdvanceTo, right.suggestedAdvanceTo]
        .filter(Boolean)
        .sort((a, b) => b.getTime() - a.getTime())[0],
    };
  }

  // Below ceiling: hydrate
  const store = await hydrateAndStore(account, search.ids, null);
  return { foundMessages: search.count, ...store, capped: false, suggestedAdvanceTo: null };
}

// -------------------- Retention --------------------
async function cleanupOldData() {
  const r = await pool.query(`delete from sendgrid_events where event_ts < now() - interval '30 days'`);
  return r.rowCount || 0;
}

// -------------------- Routes --------------------
app.get("/health", async (_req, res) => {
  try {
    await pool.query("select 1 as ok");
    res.status(200).send("ok");
  } catch (err) {
    console.error("Health DB check failed:", err);
    res.status(500).send("db error");
  }
});

app.get("/admin/db-info", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const info = {};
  info.database = (await pool.query("select current_database() as db")).rows[0].db;
  info.schema = (await pool.query("select current_schema() as schema")).rows[0].schema;
  info.search_path = (await pool.query("show search_path")).rows[0].search_path;

  const reg = await pool.query("select to_regclass('sendgrid_events') as resolved");
  info.resolved_table = reg.rows[0].resolved;

  const t = await pool.query(`
    select table_schema, table_name
    from information_schema.tables
    where table_name='sendgrid_events'
    order by table_schema
  `);
  info.all_tables = t.rows;

  const c = await pool.query(`
    select column_name
    from information_schema.columns
    where table_name='sendgrid_events' and column_name='sg_account'
    order by table_schema, ordinal_position
  `);
  info.sg_account_columns = c.rows;

  res.json({ ok: true, info });
});



app.get("/admin/db/whoami", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  const r = await pool.query(`
    select
      current_database() as db,
      current_user as user,
      inet_server_addr() as server_ip,
      inet_server_port() as server_port,
      now() as now
  `);
  res.json({ ok: true, ...r.rows[0] });
});



// Admin: incremental poll (cursor -> now)
app.post("/admin/poll", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  // Prevent overlapping cron runs
  const lockId = 987654321;
  const lock = await pool.query("select pg_try_advisory_lock($1) as locked", [lockId]);
  if (!lock.rows[0].locked) return res.status(409).json({ ok: false, error: "poll already running" });

  // Helper: enforce timeouts on awaited work so we never hold the lock indefinitely
  function withTimeout(promise, ms, label) {
    let t;
    const timeout = new Promise((_, reject) => {
      t = setTimeout(() => reject(new Error(`timeout after ${ms}ms: ${label}`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
  }

  const results = [];
  try {
    // Use DB time to avoid app clock skew
    const dbNow = await pool.query("select now() as now");
    const until = new Date(dbNow.rows[0].now);
    const anchorMs = until.getTime();

    // Hard guard: never query earlier than ~30 days (SendGrid constraint)
    const thirtyDayFloor = new Date(anchorMs - (THIRTY_DAYS_MS - SAFETY_MS));
    const rollingFloor = new Date(anchorMs - ROLLING_WINDOW_MS);

    // Hardening: bound the runtime so one poll can't hold the lock for ages
    const startedAt = Date.now();
    const MAX_RUNTIME_MS = 90 * 1000; // 90s

    // Per-chunk timeout. Must be < MAX_RUNTIME_MS, and typically < cron --max-time.
    const CHUNK_TIMEOUT_MS = 75 * 1000; // 75s

    for (const acct of SENDGRID_ACCOUNTS) {
      // Stop early if we’re approaching the runtime budget (prevents lock backlog)
      if (Date.now() - startedAt > MAX_RUNTIME_MS) {
        console.warn("[Poll] Max runtime reached; stopping early to avoid overlap/backlog.");
        break;
      }

      try {
        const lastSeen = await getLastSeen(acct.id, anchorMs);

        // Never re-ingest older than rolling window; also respect 30-day hard floor.
        let since = lastSeen < rollingFloor ? rollingFloor : lastSeen;
        if (since < thirtyDayFloor) since = thirtyDayFloor;

        // Safety: prevent invalid time range
        if (since >= until) {
          const safeSince = new Date(anchorMs - 60_000);
          console.warn(
            `[Safety] ${acct.id} since>=until; clamping since from ${isoNoMs(since)} to ${isoNoMs(safeSince)}`
          );
          since = safeSince;
        }

        console.log(`[Poll] ${acct.id} since=${isoNoMs(since)} until=${isoNoMs(until)}`);

        let cursor = new Date(since);
        const agg = { foundMessages: 0, hydrated: 0, inserted: 0, capped: false };
        let stoppedEarly = false;

        while (cursor < until) {
          // Stop early if we’re approaching the runtime budget (prevents lock backlog)
          if (Date.now() - startedAt > MAX_RUNTIME_MS) {
            console.warn(`[Poll] Max runtime reached mid-run for ${acct.id}; pausing at ${isoNoMs(cursor)}.`);
            stoppedEarly = true;
            break;
          }

          const chunkEnd = new Date(Math.min(cursor.getTime() + CHUNK_MS, until.getTime()));

          try {
            const r = await withTimeout(
              processWindowRecursive(acct, cursor, chunkEnd, anchorMs),
              CHUNK_TIMEOUT_MS,
              `${acct.id} ${isoNoMs(cursor)}→${isoNoMs(chunkEnd)}`
            );

            agg.foundMessages += Number(r.foundMessages || 0);
            agg.hydrated += Number(r.hydrated || 0);
            agg.inserted += Number(r.inserted || 0);
            agg.capped = Boolean(agg.capped || r.capped);

            const nextCursor = r.suggestedAdvanceTo ? new Date(r.suggestedAdvanceTo) : chunkEnd;

            // Commit progress as we go (so a later chunk failure doesn't lose prior work)
            await setLastSeen(acct.id, nextCursor);

            // Ensure forward progress even if timestamps collide
            if (nextCursor.getTime() <= cursor.getTime()) {
              cursor = new Date(cursor.getTime() + 1000);
              await setLastSeen(acct.id, cursor);
            } else {
              cursor = nextCursor;
            }
          } catch (e) {
            // Critical: do not allow a single bad/hung chunk to stall the poll forever.
            console.error(
              `[Poll] chunk failed ${acct.id} ${isoNoMs(cursor)}→${isoNoMs(chunkEnd)}: ${String(e?.message || e)}`
            );

            // Mark degraded and advance past the problematic chunk for reliability.
            agg.capped = true;

            // Advance cursor and persist it so we don't retry this same bad chunk endlessly.
            await setLastSeen(acct.id, chunkEnd);
            cursor = chunkEnd;
          }
        }

        results.push({
          account: acct.id,
          ok: true,
          since: isoNoMs(since),
          until: isoNoMs(until),
          stoppedEarly,
          ...agg,
        });
      } catch (err) {
        results.push({ account: acct.id, ok: false, error: String(err?.message || err) });
      }
    }

    await cleanupOldData();
    return res.json({ ok: true, results });
  } finally {
    await pool.query("select pg_advisory_unlock($1)", [lockId]);
  }
});

// Backfill / maintenance disabled (by design)
app.post("/admin/backfill", (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  return res.status(410).json({ ok: false, error: "Backfill permanently disabled" });
});
app.get("/admin/backfill-status", (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  return res.status(410).json({ ok: false, error: "Backfill permanently disabled" });
});
app.post("/admin/maintenance", (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  return res.status(410).json({ ok: false, error: "Maintenance disabled" });
});

// Admin: cleanup only
app.post("/admin/cleanup", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  const deleted = await cleanupOldData();
  res.json({ ok: true, deleted });
});





// Admin: Gmail Postmaster Tools pull (daily)
app.post("/admin/gpt/pull", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  try {
    requireGptEnv();

    const days = Math.min(Math.max(Number((req.body && req.body.days) || 14), 1), 30);

    // Use DB time to avoid app clock skew
    const dbNow = await pool.query("select now() as now");
    const anchor = new Date(dbNow.rows[0].now);

    // GPT is daily; pull up to yesterday (UTC)
    const end = new Date(anchor);
    end.setUTCHours(0, 0, 0, 0);
    end.setUTCDate(end.getUTCDate() - 1);

    const start = new Date(end);
    start.setUTCDate(start.getUTCDate() - (days - 1));

    // Strings for response payload/logging (Grafana-friendly)
    const startDateStr = start.toISOString().slice(0, 10);
    const endDateStr = end.toISOString().slice(0, 10);

    // Date objects required by Gmail Postmaster Tools API
    const startDateObj = toGptDate(start);
    const endDateObj = toGptDate(end);

    const accessToken = await getGptAccessToken();

    const results = [];
    for (const domain of GPT_DOMAINS) {
      try {
        const data = await fetchGptTrafficStats(domain, startDateObj, endDateObj, accessToken);
        const stats = (data && data.trafficStats) ? data.trafficStats : [];

        let written = 0;
        let missingDate = 0;

        for (const item of stats) {
          const d = item.date;
          let dayStr = null;

          if (typeof d === "string") {
            dayStr = d.slice(0, 10);
          } else if (d && d.year && d.month && d.day) {
            dayStr =
              String(d.year) +
              "-" +
              String(d.month).padStart(2, "0") +
              "-" +
              String(d.day).padStart(2, "0");
          } else {
            missingDate++;
            continue;
          }

          await upsertGptDay(domain, dayStr, item);
          written++;
        }

        results.push({ domain: domain, ok: true, rows: stats.length, written: written, missingDate: missingDate });
      } catch (e) {
        results.push({ domain: domain, ok: false, error: String((e && e.message) || e) });
      }
    }

    res.json({ ok: true, startDate: startDateStr, endDate: endDateStr, results });
  } catch (e) {
    res.status(500).json({ ok: false, error: String((e && e.message) || e) });
  }
});






// -------------------- Start --------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});
