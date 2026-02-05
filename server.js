// RELIABLE DROP-IN REPLACEMENT
// SendGrid Email Activity → Postgres → Grafana
// Model: 48h rolling authoritative window, days 3–30 static, >30d purged
// Designed for ~200k msgs/day with correctness > completeness

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "5mb" }));

// -------------------- CONFIG --------------------
const PORT = process.env.PORT || 10000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) throw new Error("Missing DATABASE_URL");

// Rolling authoritative window
const ROLLING_WINDOW_HOURS = 48;
const ROLLING_WINDOW_MS = ROLLING_WINDOW_HOURS * 60 * 60 * 1000;

// SendGrid constraints
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const SAFETY_MS = 5 * 60 * 1000;
const MIN_WINDOW_MS = 10 * 1000; // critical for high volume
const SG_LOGS_LIMIT = 1000;

// Throughput tuning
const HYDRATE_CONCURRENCY = Number(process.env.HYDRATE_CONCURRENCY || 4);
const PER_REQUEST_DELAY_MS = Number(process.env.PER_REQUEST_DELAY_MS || 10);

// -------------------- POSTGRES --------------------
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
      sg_message_id text,
      event_ts timestamptz,
      event text not null,
      email text,
      ip inet,
      reason text,
      response text,
      status text,
      raw jsonb not null
    );
  `);

  await pool.query(`create index if not exists idx_event_ts on sendgrid_events (event_ts desc);`);

  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  console.log("DB ready");
}

initDb().catch(err => {
  console.error("DB init failed", err);
  process.exit(1);
});

// -------------------- HELPERS --------------------
const sleep = ms => new Promise(r => setTimeout(r, ms));
const iso = d => new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");

function clamp30Days(dt) {
  const min = new Date(Date.now() - (THIRTY_DAYS_MS - SAFETY_MS));
  return dt < min ? min : dt;
}

function rollingFloor() {
  return new Date(Date.now() - ROLLING_WINDOW_MS);
}

function makeEventKey(acct, msgId, ev, ts, email) {
  return crypto.createHash("sha1").update([
    acct, msgId, ev, ts?.toISOString(), email
  ].join("|"))
  .digest("hex");
}

function auth(req) {
  return ADMIN_TOKEN && req.header("x-admin-token") === ADMIN_TOKEN;
}

// -------------------- SENDGRID --------------------
async function sgFetch(account, method, path, body, attempt = 0) {
  const res = await fetch(`https://api.sendgrid.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${account.apiKey}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.ok) return res.json().catch(() => ({}));

  if ((res.status === 429 || res.status >= 500) && attempt < 6) {
    const backoff = Math.min(30000, 500 * 2 ** attempt);
    await sleep(backoff);
    return sgFetch(account, method, path, body, attempt + 1);
  }

  throw new Error(`SendGrid ${res.status}: ${await res.text()}`);
}

// -------------------- ACCOUNTS --------------------
function loadAccounts() {
  const raw = process.env.SENDGRID_ACCOUNTS_JSON;
  if (!raw) throw new Error("SENDGRID_ACCOUNTS_JSON required");
  const a = JSON.parse(raw);
  if (!Array.isArray(a) || !a.length) throw new Error("No SendGrid accounts");
  return a;
}

const ACCOUNTS = loadAccounts();

// -------------------- POLL STATE --------------------
async function getLastSeen(acct) {
  const r = await pool.query(`select last_seen from sg_poll_state where sg_account=$1`, [acct]);
  if (r.rows.length) return new Date(r.rows[0].last_seen);

  const seed = rollingFloor();
  await pool.query(
    `insert into sg_poll_state (sg_account,last_seen) values ($1,$2) on conflict do nothing`,
    [acct, seed]
  );
  return seed;
}

async function setLastSeen(acct, ts) {
  await pool.query(
    `insert into sg_poll_state values ($1,$2)
     on conflict (sg_account) do update set last_seen=excluded.last_seen`,
    [acct, ts]
  );
}

// -------------------- INGESTION --------------------
async function searchIds(account, since, until) {
  since = clamp30Days(since);

  const body = {
    query: `sg_message_id_created_at > TIMESTAMP "${iso(since)}" AND sg_message_id_created_at <= TIMESTAMP "${iso(until)}"`,
    limit: SG_LOGS_LIMIT,
  };

  const r = await sgFetch(account, "POST", "/v3/logs", body);
  return (r.result || []).map(m => m.sg_message_id).filter(Boolean);
}

async function hydrateAndInsert(account, ids) {
  const client = await pool.connect();
  try {
    await client.query("begin");

    let idx = 0;
    const workers = new Array(HYDRATE_CONCURRENCY).fill(null).map(async () => {
      while (idx < ids.length) {
        const id = ids[idx++];
        const d = await sgFetch(account, "GET", `/v3/logs/${id}`);
        const email = d.to_email || null;
        const events = Array.isArray(d.events) ? d.events : [];

        for (const ev of events) {
          const ts = new Date((ev.timestamp || Date.now() / 1000) * 1000);
          await client.query(
            `insert into sendgrid_events (event_key, sg_account, sg_message_id, event_ts, event, email, raw)
             values ($1,$2,$3,$4,$5,$6,$7)
             on conflict do nothing`,
            [
              makeEventKey(account.id, id, ev.event, ts, email),
              account.id,
              id,
              ts,
              ev.event,
              email,
              ev,
            ]
          );
        }

        if (PER_REQUEST_DELAY_MS) await sleep(PER_REQUEST_DELAY_MS);
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
}

async function processWindow(account, since, until) {
  const ids = await searchIds(account, since, until);

  if (ids.length >= SG_LOGS_LIMIT && (until - since) > MIN_WINDOW_MS) {
    const mid = new Date((since.getTime() + until.getTime()) / 2);
    await processWindow(account, since, mid);
    await processWindow(account, mid, until);
  } else {
    await hydrateAndInsert(account, ids);
  }
}

// -------------------- ROUTES --------------------
app.post("/admin/poll", async (req, res) => {
  if (!auth(req)) return res.sendStatus(401);

  for (const acct of ACCOUNTS) {
    const last = await getLastSeen(acct.id);
    const floor = rollingFloor();
    const since = last < floor ? floor : last;
    const until = new Date();

    await processWindow(acct, since, until);
    await setLastSeen(acct.id, until);
  }

  res.json({ ok: true, rolling_hours: ROLLING_WINDOW_HOURS });
});

app.post("/admin/cleanup", async (req, res) => {
  if (!auth(req)) return res.sendStatus(401);
  const r = await pool.query(`delete from sendgrid_events where event_ts < now() - interval '30 days'`);
  res.json({ deleted: r.rowCount });
});

app.get("/health", async (_, res) => {
  await pool.query("select 1");
  res.send("ok");
});

app.listen(PORT, "0.0.0.0", () => console.log(`Listening on ${PORT}`));
