const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

// ---- SendGrid accounts (Email Logs polling) ----
// Set these in Render Environment Variables.
// Example IDs: account_a/account_b/account_c
const SENDGRID_ACCOUNTS = [
  { id: "account_a", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_A },
  { id: "account_b", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_B },
  { id: "account_c", apiKey: process.env.SENDGRID_API_KEY_ACCOUNT_C },
].filter((a) => a.apiKey);

function requireAdmin(req, res) {
  const token = req.header("x-admin-token");
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    res.status(401).json({ error: "unauthorized" });
    return false;
  }
  return true;
}

function makeEventKey({
  sgAccount,
  sgMessageId,
  event,
  eventTs,
  email,
  ip,
  status,
  response,
}) {
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

const app = express();
app.use(express.json({ limit: "5mb" }));

// ---- Postgres ----
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

  // Ensure columns exist even if table predates them
  await pool.query(`alter table sendgrid_events add column if not exists sg_account text;`);
  await pool.query(`alter table sendgrid_events add column if not exists event_key text;`);

  // Webhook dedupe
  await pool.query(`
    create unique index if not exists ux_sendgrid_events_sg_event_id
    on sendgrid_events (sg_event_id)
    where sg_event_id is not null;
  `);

  // Polling dedupe/upsert key
  await pool.query(`
    create unique index if not exists ux_sendgrid_events_event_key
    on sendgrid_events (event_key)
    where event_key is not null;
  `);

  // Helpful indexes
  await pool.query(`
    create index if not exists idx_sendgrid_events_event_ts
    on sendgrid_events (event_ts desc);
  `);

  await pool.query(`
    create index if not exists idx_sge_domain_ip_ts
    on sendgrid_events (sending_domain, ip, event_ts desc);
  `);

  // Poll cursor state
  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  console.log("DB initialized");
}

// ---- Email Logs Polling Helpers ----

async function getLastSeen(sgAccount) {
  const r = await pool.query(
    `select last_seen from sg_poll_state where sg_account = $1`,
    [sgAccount]
  );
  if (r.rows.length) return r.rows[0].last_seen;

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

function toSendGridTimestamp(dt) {
  return new Date(dt).toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function sgFetch(account, method, path, body) {
  const url = `https://api.sendgrid.com${path}`;

  // Retry transient SendGrid errors (429/5xx)
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${account.apiKey}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.ok) return res.json();

    const text = await res.text();
    const retryable =
      res.status === 429 || (res.status >= 500 && res.status <= 599);

    if (!retryable || attempt === maxAttempts) {
      throw new Error(
        `SendGrid API error (${account.id}) ${res.status}: ${text.slice(0, 500)}`
      );
    }

    const baseMs = 500 * Math.pow(2, attempt - 1);
    const jitterMs = Math.floor(Math.random() * 250);
    const waitMs = baseMs + jitterMs;

    console.warn(
      `SendGrid transient error (${account.id}) ${res.status} attempt ${attempt}/${maxAttempts} — retrying in ${waitMs}ms`
    );
    await new Promise((r) => setTimeout(r, waitMs));
  }
}

async function pollEmailLogsForAccount(account) {
  const since = await getLastSeen(account.id);
  const until = new Date();

// --- SendGrid API hard limit: 30-day lookback ---
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const minAllowed = new Date(Date.now() - THIRTY_DAYS_MS);

// Clamp lookback to last 30 days (SendGrid requirement)
const effectiveSince = since < minAllowed ? minAllowed : since;


  // overlap to avoid missing edge events (upsert handles duplicates safely)
  const overlapMs = 2 * 60 * 1000;
  const sinceOverlap = new Date(new Date(effectiveSince).getTime() - overlapMs);

  const sinceStr = toSendGridTimestamp(sinceOverlap);
  const untilStr = toSendGridTimestamp(until);

  // Search logs for messages created in the window
  const searchBody = {
    query:
      `sg_message_id_created_at > TIMESTAMP "${sinceStr}" ` +
      `AND sg_message_id_created_at <= TIMESTAMP "${untilStr}"`,
    limit: 1000,
  };

  const search = await sgFetch(account, "POST", "/v3/logs", searchBody);
  const messages = search?.result || search?.results || search?.messages || [];
  const sgMessageIds = [];

  for (const m of messages) {
    const id = m.sg_message_id || m.message_id || m.sg_message_id_string;
    if (id) sgMessageIds.push(id);
  }

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

      if (normalizedEvents.length === 0) {
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
    }

    await client.query("commit");
  } catch (err) {
    await client.query("rollback");
    throw err;
  } finally {
    client.release();
  }

  await setLastSeen(account.id, until);

  return {
    account: account.id,
    since: sinceStr,
    until: untilStr,
    foundMessages: sgMessageIds.length,
    hydrated,
    inserted,
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

async function refreshAccount(account, days = 30) {
  const now = new Date();
  const start = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);

  const windowMs = 6 * 60 * 60 * 1000; // 6 hours
  let cursor = start;

  while (cursor < now) {
    await setLastSeen(account.id, cursor);
    await pollEmailLogsForAccount(account);

    cursor = new Date(Math.min(cursor.getTime() + windowMs, now.getTime()));
    await new Promise((r) => setTimeout(r, 500));
  }
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

// Initialize DB on startup
initDb().catch((err) => {
  console.error("DB init failed:", err);
});

// ---- Routes ----
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

app.post("/admin/test-sendgrid-logs", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { accountId = "account_a", minutes = 15 } = req.body || {};
  const acct = SENDGRID_ACCOUNTS.find((a) => a.id === accountId);
  if (!acct) return res.status(400).json({ ok: false, error: "unknown accountId" });

  const until = new Date();
  const since = new Date(until.getTime() - Number(minutes) * 60 * 1000);

  const sinceStr = toSendGridTimestamp(since);
  const untilStr = toSendGridTimestamp(until);

  const searchBody = {
    query:
      `sg_message_id_created_at > TIMESTAMP "${sinceStr}" ` +
      `AND sg_message_id_created_at <= TIMESTAMP "${untilStr}"`,
    limit: 25,
  };

  try {
    const search = await sgFetch(acct, "POST", "/v3/logs", searchBody);
    res.json({ ok: true, window: { since: sinceStr, until: untilStr }, sample: search });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
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

// Webhook endpoint (optional)
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

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});
