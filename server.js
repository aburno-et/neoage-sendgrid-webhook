const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

// =====================
// Config
// =====================
const SENDGRID_ACCOUNTS = [
  { id: "account_a", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_A },
  { id: "account_b", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_B },
  { id: "account_c", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_C },
].filter((a) => a.apiKey);

function requireAdmin(req, res) {
  const token = req.header("x-admin-token");
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isoNoMs(dt) {
  return new Date(dt).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// =====================
// Postgres
// =====================
const app = express();
app.use(express.json({ limit: "5mb" }));

if (!process.env.DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    create table if not exists sendgrid_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),

      -- identifiers
      sg_event_id text,
      sg_message_id text,

      -- SendGrid event time
      event_ts timestamptz,

      -- event info
      event text not null,
      ip inet,
      email text,
      recipient_domain text,

      -- diagnostics
      reason text,
      response text,
      status text,

      -- custom_args for filtering (webhook payloads)
      sending_domain text,
      stream text,
      campaign text,
      ip_pool text,
      environment text,

      -- polling support
      sg_account text,
      event_key text,

      raw jsonb not null
    );
  `);

  await pool.query(`alter table sendgrid_events add column if not exists sg_account text;`);
  await pool.query(`alter table sendgrid_events add column if not exists event_key text;`);

  // Webhook dedupe by sg_event_id
  await pool.query(`
    create unique index if not exists ux_sendgrid_events_sg_event_id
    on sendgrid_events (sg_event_id)
    where sg_event_id is not null;
  `);

  // Poller upsert key
  await pool.query(`
    create unique index if not exists ux_sendgrid_events_event_key
    on sendgrid_events (event_key)
    where event_key is not null;
  `);

  await pool.query(`
    create index if not exists idx_sendgrid_events_event_ts
    on sendgrid_events (event_ts desc);
  `);

  await pool.query(`
    create index if not exists idx_sge_domain_ip_ts
    on sendgrid_events (sending_domain, ip, event_ts desc);
  `);

  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  console.log("DB initialized");
}

// =====================
// SendGrid API helpers
// =====================
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

  // simple retry for transient SG 5xx
  if (!res.ok) {
    const text = await res.text();
    if (res.status >= 500 && res.status <= 599 && attempt < 5) {
      const backoff = 300 * Math.pow(2, attempt);
      console.warn(
        `[SendGrid Retry] ${account.id} ${method} ${path} ${res.status} attempt=${attempt + 1} backoff=${backoff}ms`
      );
      await sleep(backoff);
      return sgFetch(account, method, path, body, attempt + 1);
    }
    throw new Error(
      `SendGrid API error (${account.id}) ${res.status}: ${text.slice(0, 500)}`
    );
  }

  // Some endpoints may return empty; handle safely
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return {};
  return res.json();
}

// =====================
// Poll state
// =====================
async function getLastSeen(sgAccount) {
  const r = await pool.query(
    `select last_seen from sg_poll_state where sg_account = $1`,
    [sgAccount]
  );
  if (r.rows.length) return new Date(r.rows[0].last_seen);

  // default: start 15 minutes back for first run
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

// =====================
// Windowed ingestion (fixes 1000-cap)
// =====================
const SG_LOGS_LIMIT = 1000;

// Must be strictly within last 30 days to satisfy SendGrid; add safety buffer.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const SAFETY_MS = 5 * 60 * 1000; // 5 minutes
const MIN_WINDOW_MS = 5 * 60 * 1000; // 5 minutes minimum split window
const OVERLAP_MS = 2 * 60 * 1000; // overlap for edge events

function minAllowedLowerBound() {
  return new Date(Date.now() - (THIRTY_DAYS_MS - SAFETY_MS));
}

function clampLowerBound(dt) {
  const minAllowed = minAllowedLowerBound();
  return dt < minAllowed ? minAllowed : dt;
}

function makeEventKey({ sgAccount, sgMessageId, event, eventTs, email, ip, status, response }) {
  const raw = [
    sgAccount || "",
    sgMessageId || "",
    event || "",
    eventTs ? new Date(eventTs).toISOString() : "",
    email || "",
    ip || "",
    status || "",
    response || "",
  ].join("|");

  return crypto.createHash("sha1").update(raw).digest("hex");
}

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

async function hydrateAndStore(account, sgMessageIds) {
  let inserted = 0;
  let hydrated = 0;

  const client = await pool.connect();
  try {
    await client.query("begin");

    for (const sgMessageId of sgMessageIds) {
      hydrated += 1;

      const detail = await sgFetch(
        account,
        "GET",
        `/v3/logs/${encodeURIComponent(sgMessageId)}`
      );

      const events =
        detail?.events || detail?.event || detail?.items || detail?.results || [];

      const email =
        detail?.to_email || detail?.email || detail?.recipient || detail?.to || null;

      const recipientDomain =
        typeof email === "string" && email.includes("@")
          ? email.split("@").pop().toLowerCase()
          : null;

      const normalizedEvents = Array.isArray(events) ? events : [events];

      // If no events array, store a single "log" row so the message isn't lost.
      if (!normalizedEvents.length) {
        const tsLog = new Date();
        const eventKeyLog = makeEventKey({
          sgAccount: account.id,
          sgMessageId,
          event: "log",
          eventTs: tsLog,
          email,
          ip: null,
          status: detail?.status || null,
          response: detail?.response || null,
        });

        await client.query(
          `
          insert into sendgrid_events (
            event_key,
            sg_account, sg_message_id, event_ts, event, email, recipient_domain, raw
          )
          values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
          on conflict (event_key) do update
          set
            event_ts = excluded.event_ts,
            raw      = excluded.raw
          `,
          [
            eventKeyLog,
            account.id,
            sgMessageId,
            tsLog,
            "log",
            email,
            recipientDomain,
            JSON.stringify(detail),
          ]
        );
        inserted += 1;
        continue;
      }

      for (const ev of normalizedEvents) {
        const eventName =
          ev?.event || ev?.type || ev?.name || detail?.status || "unknown";

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

        const eventKey = makeEventKey({
          sgAccount: account.id,
          sgMessageId,
          event: String(eventName).toLowerCase(),
          eventTs: ts,
          email,
          ip,
          status,
          response,
        });

        await client.query(
          `
          insert into sendgrid_events (
            event_key,
            sg_account, sg_message_id, event_ts, event, ip, email, recipient_domain,
            reason, response, status, raw
          )
          values (
            $1,
            $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12::jsonb
          )
          on conflict (event_key) do update
          set
            event_ts = excluded.event_ts,
            reason   = excluded.reason,
            response = excluded.response,
            status   = excluded.status,
            raw      = excluded.raw
          `,
          [
            eventKey,
            account.id,
            sgMessageId,
            ts,
            String(eventName).toLowerCase(),
            ip,
            email,
            recipientDomain,
            reason,
            response,
            status,
            JSON.stringify({ detail, ev }),
          ]
        );

        inserted += 1;
      }

      // Gentle throttle; increase if you hit rate limits
      await sleep(20);
    }

    await client.query("commit");
  } catch (err) {
    await client.query("rollback");
    throw err;
  } finally {
    client.release();
  }

  return { hydrated, inserted };
}

async function processWindowRecursive(account, sinceDt, untilDt) {
  const since = clampLowerBound(sinceDt);
  const until = new Date(untilDt);
  const windowMs = until.getTime() - since.getTime();

  const search = await sgSearchMessageIds(account, since, until);

  // If we hit the cap, split the window smaller
  if (search.count >= SG_LOGS_LIMIT) {
    if (windowMs <= MIN_WINDOW_MS) {
      console.warn(
        `[Backfill] ${account.id} HIT LIMIT at min window since=${search.sinceStr} until=${search.untilStr} count=${search.count}`
      );
      const store = await hydrateAndStore(account, search.ids);
      return {
        ok: true,
        split: false,
        capped: true,
        since: search.sinceStr,
        until: search.untilStr,
        foundMessages: search.count,
        ...store,
      };
    }

    const mid = new Date(since.getTime() + Math.floor(windowMs / 2));
    const left = await processWindowRecursive(account, since, mid);
    const right = await processWindowRecursive(account, mid, until);

    return {
      ok: true,
      split: true,
      capped: false,
      since: isoNoMs(since),
      until: isoNoMs(until),
      foundMessages: (left.foundMessages || 0) + (right.foundMessages || 0),
      hydrated: (left.hydrated || 0) + (right.hydrated || 0),
      inserted: (left.inserted || 0) + (right.inserted || 0),
    };
  }

  const store = await hydrateAndStore(account, search.ids);

  return {
    ok: true,
    split: false,
    capped: false,
    since: search.sinceStr,
    until: search.untilStr,
    foundMessages: search.count,
    ...store,
  };
}

async function pollEmailLogsForAccount(account) {
  const rawSince = await getLastSeen(account.id);
  const until = new Date();

  // Apply overlap, then clamp to allowed range (prevents 30-day error)
  const sinceOverlapCandidate = new Date(rawSince.getTime() - OVERLAP_MS);
  const since = clampLowerBound(sinceOverlapCandidate);

  const sinceStr = isoNoMs(since);
  const untilStr = isoNoMs(until);

  console.log(`[SendGrid Poll] ${account.id} since=${sinceStr} until=${untilStr}`);

  const r = await processWindowRecursive(account, since, until);

  // Advance cursor to "until"
  await setLastSeen(account.id, until);

  return {
    account: account.id,
    ok: true,
    since: sinceStr,
    until: untilStr,
    ...r,
  };
}

async function pollAllAccountsOnce() {
  const results = [];
  for (const acct of SENDGRID_ACCOUNTS) {
    try {
      results.push(await pollEmailLogsForAccount(acct));
    } catch (err) {
      console.error(`Polling failed for ${acct.id}:`, err);
      results.push({
        account: acct.id,
        ok: false,
        error: String(err?.message || err),
      });
    }
  }
  return results;
}

// Refresh last N days by iterating day windows (each day splits as needed)
async function refreshAccount(account, days = 30) {
  const now = new Date();
  const startRaw = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  const start = clampLowerBound(startRaw);

  let cursor = new Date(start);

  while (cursor < now) {
    const dayEnd = new Date(Math.min(cursor.getTime() + 24 * 60 * 60 * 1000, now.getTime()));
    const windowStart = clampLowerBound(new Date(cursor.getTime() - OVERLAP_MS));

    console.log(
      `[Refresh] ${account.id} ${isoNoMs(windowStart)} → ${isoNoMs(dayEnd)}`
    );

    await processWindowRecursive(account, windowStart, dayEnd);

    cursor = dayEnd;
    await sleep(300);
  }

  await setLastSeen(account.id, now);
}

async function refreshAllAccounts(days = 30) {
  for (const acct of SENDGRID_ACCOUNTS) {
    await refreshAccount(acct, days);
  }
}

async function cleanupOldEvents(days = 90) {
  await pool.query(
    `
    delete from sendgrid_events
    where event_ts < now() - make_interval(days => $1)
    `,
    [days]
  );
}

// =====================
// Webhook endpoint (optional but useful)
// =====================
app.post("/webhooks/sendgrid/events", async (req, res) => {
  const events = req.body;
  if (!Array.isArray(events)) return res.status(204).send();

  const client = await pool.connect();
  try {
    await client.query("begin");
    for (const e of events) {
      const email = e.email || null;
      const recipientDomain =
        typeof email === "string" && email.includes("@")
          ? email.split("@").pop().toLowerCase()
          : null;

      const ca = e.custom_args || {};
      await client.query(
        `
        insert into sendgrid_events (
          sg_event_id, sg_message_id, event_ts, event, ip, email, recipient_domain,
          reason, response, status,
          sending_domain, stream, campaign, ip_pool, environment,
          raw
        )
        values (
          $1, $2, to_timestamp($3), $4, $5, $6, $7,
          $8, $9, $10,
          $11, $12, $13, $14, $15,
          $16::jsonb
        )
        on conflict (sg_event_id) do nothing
        `,
        [
          e.sg_event_id || null,
          e.sg_message_id || null,
          e.timestamp || null,
          e.event || "unknown",
          e.ip || null,
          email,
          recipientDomain,
          e.reason || null,
          e.response || null,
          e.status || null,
          ca.sending_domain || null,
          ca.stream || null,
          ca.campaign || null,
          ca.ip_pool || null,
          ca.environment || null,
          JSON.stringify(e),
        ]
      );
    }
    await client.query("commit");
  } catch (err) {
    await client.query("rollback");
    console.error("Webhook insert failed:", err);
  } finally {
    client.release();
  }

  res.status(204).send();
});

// =====================
// Routes
// =====================
app.get("/health", async (req, res) => {
  try {
    await pool.query("select 1 as ok");
    res.status(200).send("ok");
  } catch (err) {
    console.error("Health DB check failed:", err);
    res.status(500).send("db error");
  }
});

app.get("/admin/accounts", (req, res) => {
  res.json({ accountsConfigured: SENDGRID_ACCOUNTS.map((a) => a.id) });
});

app.post("/admin/poll-email-logs", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const results = await pollAllAccountsOnce();
    res.json({ ok: true, results });
  } catch (err) {
    console.error("Polling failed:", err);
    res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

app.post("/admin/maintenance", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await refreshAllAccounts(30);
    await cleanupOldEvents(90);
    res.json({ ok: true });
  } catch (err) {
    console.error("Maintenance failed:", err);
    res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

// =====================
// Startup
// =====================
initDb().catch((err) => {
  console.error("DB init failed:", err);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});
