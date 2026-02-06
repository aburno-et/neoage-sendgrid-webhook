const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

// Node 18+ has global fetch (Render uses Node 25 in your logs)

const app = express();
app.use(express.json({ limit: "5mb" }));

// -------------------- Config --------------------
const PORT = process.env.PORT || 10000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
}

// SendGrid Email Activity API only allows last 30 days.
// Use a buffer to avoid edge/clock/rounding issues.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const SAFETY_MS = 5 * 60 * 1000; // 5 minutes
const MIN_WINDOW_MS = 10 * 1000; // 10 seconds
const SG_LOGS_LIMIT = 1000;

// Concurrency for hydration (message detail fetches)
const HYDRATE_CONCURRENCY = Number(process.env.HYDRATE_CONCURRENCY || 4);
const PER_REQUEST_DELAY_MS = Number(process.env.PER_REQUEST_DELAY_MS || 10);

// Authoritative rolling window
const ROLLING_WINDOW_HOURS = 48;
const ROLLING_WINDOW_MS = ROLLING_WINDOW_HOURS * 60 * 60 * 1000;




// -------------------- Postgres --------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

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
  await pool.query(`create index if not exists idx_sge_domain_ip_ts on sendgrid_events (sending_domain, ip, event_ts desc);`);

  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  await pool.query(`
    create table if not exists backfill_runs (
      run_id uuid primary key,
      started_at timestamptz not null default now(),
      finished_at timestamptz,
      status text not null default 'running', -- running|success|failed
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

  console.log("DB initialized");
}

initDb().catch((err) => {
  console.error("DB init failed:", err);
});

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
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function isoNoMs(dt) { return new Date(dt).toISOString().replace(/\.\\d{3}Z$/, "Z"); }

function minAllowedLowerBound() {
  return new Date(Date.now() - (THIRTY_DAYS_MS - SAFETY_MS));
}
function clampLowerBound(dt) {
  const rollingFloor = new Date(Date.now() - ROLLING_WINDOW_MS);
  return dt < rollingFloor ? rollingFloor : dt;
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

  if (res.ok) {
    const txt = await res.text();
    if (!txt) return {};
    try { return JSON.parse(txt); } catch { return { raw: txt }; }
  }

  const txt = await res.text();
  const msg = txt ? txt.slice(0, 800) : "";

  const retryable = res.status === 429 || (res.status >= 500 && res.status <= 599);
  if (retryable && attempt < 6) {
    const backoff = Math.min(30000, 500 * Math.pow(2, attempt));
    console.warn(`[SendGrid Retry] ${account.id} ${method} ${path} status=${res.status} backoff=${backoff}ms`);
    await sleep(backoff);
    return sgFetch(account, method, path, body, attempt + 1);
  }

  throw new Error(`SendGrid API error (${account.id}) ${res.status}: ${msg}`);
}

// -------------------- Poll state --------------------
async function getLastSeen(sgAccount) {
  const r = await pool.query(`select last_seen from sg_poll_state where sg_account = $1`, [sgAccount]);
  if (r.rows.length) return new Date(r.rows[0].last_seen);

  const seed = new Date(Date.now() - 15 * 60 * 1000);
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
async function sgSearchMessageIds(account, sinceDt, untilDt) {
  const since = clampLowerBound(sinceDt);
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
    return [{
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
    }];
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

  const client = await pool.connect();
  try {
    await client.query("begin");

    let idx = 0;
    const workers = new Array(Math.max(1, HYDRATE_CONCURRENCY)).fill(null).map(async () => {
      while (idx < sgMessageIds.length) {
        const myIdx = idx++;
        const sgMessageId = sgMessageIds[myIdx];

        hydrated += 1;

        const rows = await hydrateOneMessage(account, sgMessageId);
        for (const row of rows) {
          await upsertEventRow(client, row);
          inserted += 1;
        }

        if (PER_REQUEST_DELAY_MS) await sleep(PER_REQUEST_DELAY_MS);

        if (progressCb && hydrated % 100 === 0) {
          await progressCb({ hydrated, inserted });
        }
      }
    });

    await Promise.all(workers);

    await client.query("commit");
  } catch (e) {
    await client.query("rollback");
    throw e;
  } finally {
    client.release();
  }

  return { hydrated, inserted };
}

// -------------------- Window splitting --------------------
async function processWindowRecursive(account, sinceDt, untilDt) {
  const since = clampLowerBound(sinceDt);
  const until = new Date(untilDt);
  const windowMs = until.getTime() - since.getTime();

  const search = await sgSearchMessageIds(account, since, until);

  if (search.count >= SG_LOGS_LIMIT) {
    if (windowMs <= MIN_WINDOW_MS) {
      console.warn(`[Backfill] ${account.id} HIT LIMIT at min window since=${search.sinceStr} until=${search.untilStr} count=${search.count}`);
      const store = await hydrateAndStore(account, search.ids, null);
      return { foundMessages: search.count, ...store, capped: true };
    }

    const mid = new Date(since.getTime() + Math.floor(windowMs / 2));
    const left = await processWindowRecursive(account, since, mid);
    const right = await processWindowRecursive(account, mid, until);

    return {
      foundMessages: (left.foundMessages || 0) + (right.foundMessages || 0),
      hydrated: (left.hydrated || 0) + (right.hydrated || 0),
      inserted: (left.inserted || 0) + (right.inserted || 0),
      capped: Boolean(left.capped || right.capped),
    };
  }

  const store = await hydrateAndStore(account, search.ids, null);
  return { foundMessages: search.count, ...store, capped: false };
}

// -------------------- Backfill runner (fire-and-forget) --------------------
async function createBackfillRun(days, note) {
  const runId = crypto.randomUUID();
  await pool.query(`insert into backfill_runs (run_id, days, note) values ($1, $2, $3)`, [runId, days, note || null]);
  return runId;
}

async function backfillAccountLastNDays(account, days, runId) {
  const now = new Date();
  const start = clampLowerBound(new Date(now.getTime() - days * 24 * 60 * 60 * 1000));

  let cursor = new Date(start);
  let windowsDone = 0;

  while (cursor < now) {
    const dayEnd = new Date(Math.min(cursor.getTime() + 24 * 60 * 60 * 1000, now.getTime()));
    windowsDone += 1;

    await pool.query(
      `
      update backfill_runs
      set
        current_account = $2,
        current_window_start = $3,
        current_window_end = $4,
        windows_done = $5
      where run_id = $1
      `,
      [runId, account.id, cursor, dayEnd, windowsDone]
    );

    console.log(`[Backfill] ${account.id} ${isoNoMs(cursor)} → ${isoNoMs(dayEnd)}`);

    try {
      const r = await processWindowRecursive(account, cursor, dayEnd);
      await pool.query(
        `
        update backfill_runs
        set
          messages_found = messages_found + $2,
          hydrated = hydrated + $3,
          inserted = inserted + $4
        where run_id = $1
        `,
        [runId, Number(r.foundMessages || 0), Number(r.hydrated || 0), Number(r.inserted || 0)]
      );
    } catch (err) {
      console.error(`[Backfill] window failed ${account.id}:`, err);
      await pool.query(`update backfill_runs set errors = errors + 1 where run_id = $1`, [runId]);
    }

    cursor = dayEnd;
    await sleep(200);
  }
}

async function runBackfillAll(days, note) {
  const d = Math.min(Number(days || 2), 2);
  const runId = await createBackfillRun(d, note || "manual");

  try {
    for (const acct of SENDGRID_ACCOUNTS) {
      await backfillAccountLastNDays(acct, d, runId);
    }
    await pool.query(`update backfill_runs set status='success', finished_at=now() where run_id=$1`, [runId]);
    console.log(`[Backfill] DONE run_id=${runId}`);
  } catch (err) {
    console.error("[Backfill] FAILED:", err);
    await pool.query(
      `update backfill_runs set status='failed', finished_at=now(), note=$2 where run_id=$1`,
      [runId, String(err?.message || err)]
    );
  }
}

// -------------------- Maintenance: delete >90 days --------------------
async function cleanupOldData() {
  const r = await pool.query(`delete from sendgrid_events where event_ts < now() - interval '30 days'`);
  return r.rowCount || 0;
}

// -------------------- Routes --------------------
app.get("/health", async (req, res) => {
  try {
    await pool.query("select 1 as ok");
    res.status(200).send("ok");
  } catch (err) {
    console.error("Health DB check failed:", err);
    res.status(500).send("db error");
  }
});

// Admin: incremental poll (cursor -> now)
app.post("/admin/poll", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const results = [];
  for (const acct of SENDGRID_ACCOUNTS) {
    try {
     const lastSeen = await getLastSeen(acct.id);
const rollingFloor = new Date(Date.now() - ROLLING_WINDOW_MS);

// Never re-ingest older than 48h
const since = lastSeen < rollingFloor ? rollingFloor : lastSeen;
const until = new Date();


      console.log(`[Poll] ${acct.id} since=${isoNoMs(since)} until=${isoNoMs(until)}`);

      const r = await processWindowRecursive(acct, since, until);
      await setLastSeen(acct.id, until);
await cleanupOldData();

      results.push({ account: acct.id, ok: true, since: isoNoMs(since), until: isoNoMs(until), ...r });
    } catch (err) {
      results.push({ account: acct.id, ok: false, error: String(err?.message || err) });
    }
  }

  res.json({ ok: true, results });
});

// Admin: fire-and-forget backfill (<=30 days)
app.post("/admin/backfill", (_, res) =>
  res.status(410).json({ error: "Backfill permanently disabled" })
);
  const days = Math.min(Number(req.body?.days || 30), 30);

  // Respond immediately to avoid Cloudflare/Render timeouts
  res.status(202).json({ ok: true, started: true, days, note: "Backfill started. Check /admin/backfill-status or Render logs." });

  runBackfillAll(days, "manual").catch((e) => console.error("Backfill runner crashed:", e));
});

// Admin: backfill status
app.get("/admin/backfill-status", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const r = await pool.query(`select * from backfill_runs order by started_at desc limit 10`);
  res.json({ ok: true, runs: r.rows });
});

// Admin: maintenance (backfill 30d async + cleanup >90d)
app.post("/admin/maintenance", (_, res) =>
  res.status(410).json({ error: "Maintenance disabled" })
);

  res.status(202).json({ ok: true, started: true, note: "Maintenance started. Check /admin/backfill-status or logs." });

  (async () => {
    try {
      await runBackfillAll(30, "maintenance");
      const deleted = await cleanupOldData();
      console.log(`[Maintenance] cleanup deleted=${deleted}`);
    } catch (e) {
      console.error("[Maintenance] failed:", e);
    }
  })();
});

// Admin: cleanup only
app.post("/admin/cleanup", async (req, res) => {
  if (!authAdmin(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  const deleted = await cleanupOldData();
  res.json({ ok: true, deleted });
});

// -------------------- Start --------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});
