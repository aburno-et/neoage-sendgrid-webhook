const express = require("express");
const { Pool } = require("pg");


// ---- SendGrid accounts (Email Logs polling) ----
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


const crypto = require("crypto");

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
    sgAccount,
    sgMessageId,
    event,
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

// Render Postgres typically requires SSL. This setting is safe for managed DBs.
// If your Internal URL doesn't require SSL, Postgres will still connect fine.
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

      -- custom_args for filtering
      sending_domain text,
      stream text,
      campaign text,
      ip_pool text,
      environment text,

      raw jsonb not null
    );
  `);

  await pool.query(`
    create unique index if not exists ux_sendgrid_events_sg_event_id
    on sendgrid_events (sg_event_id)
    where sg_event_id is not null;
  `);

  await pool.query(`
    create index if not exists idx_sge_event_ts on sendgrid_events (event_ts desc);
  `);

  await pool.query(`
    create index if not exists idx_sge_domain_ip_ts on sendgrid_events (sending_domain, ip, event_ts desc);
  `);

  // Track polling cursor per SendGrid account
  await pool.query(`
    create table if not exists sg_poll_state (
      sg_account text primary key,
      last_seen timestamptz not null
    );
  `);

  // Helpful dedupe for polling (webhook has sg_event_id; logs polling might not)
  await pool.query(`
    create unique index if not exists ux_sendgrid_events_poll_dedupe
    on sendgrid_events (sg_account, sg_message_id, event_ts, event, coalesce(email,''));
  `);

  // Ensure sg_account column exists (you already added it, this is just safe)
  await pool.query(`
    alter table sendgrid_events
    add column if not exists sg_account text;
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
  // SendGrid logs query expects TIMESTAMP "YYYY-MM-DDTHH:MM:SSZ"
  return new Date(dt).toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function sgFetch(account, method, path, body) {
  const url = `https://api.sendgrid.com${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${account.apiKey}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `SendGrid API error (${account.id}) ${res.status}: ${text.slice(0, 500)}`
    );
  }

  return res.json();
}

async function pollEmailLogsForAccount(account, windowMinutes = 10) {
  const since = await getLastSeen(account.id);
  const until = new Date();

  // small overlap to avoid missing edge events; dedupe index prevents duplicates
  const overlapMs = 2 * 60 * 1000;
  const sinceOverlap = new Date(new Date(since).getTime() - overlapMs);

  const sinceStr = toSendGridTimestamp(sinceOverlap);
  const untilStr = toSendGridTimestamp(until);

  // 1) Search logs for messages created in the window
  const searchBody = {
    query:
      `sg_message_id_created_at > TIMESTAMP "${sinceStr}" ` +
      `AND sg_message_id_created_at <= TIMESTAMP "${untilStr}"`,
    limit: 1000,
  };

  const search = await sgFetch(account, "POST", "/v3/logs", searchBody);

  // The response shape can vary slightly; try common fields
  const messages = search?.result || search?.results || search?.messages || [];
  const sgMessageIds = [];

  for (const m of messages) {
    const id = m.sg_message_id || m.message_id || m.sg_message_id_string;
    if (id) sgMessageIds.push(id);
  }

  let inserted = 0;
  let hydrated = 0;

  // 2) Hydrate each message for its event trail/details
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

      // We’ll try to locate an events array. If none, we store at least a “log” row.
      const events =
        detail?.events || detail?.event || detail?.items || detail?.results || [];

      // Try to locate a recipient email if provided (shape varies)
      const email =
        detail?.to_email || detail?.email || detail?.recipient || detail?.to || null;

      const recipientDomain =
        typeof email === "string" && email.includes("@")
          ? email.split("@").pop().toLowerCase()
          : null;

      // If events is not an array, normalize
      const normalizedEvents = Array.isArray(events) ? events : [events];

      if (normalizedEvents.length === 0) {
        // Insert a single row as “log” if no event details found
        await client.query(
          `
          insert into sendgrid_events (
            sg_account, sg_message_id, event_ts, event, email, recipient_domain, raw
          )
          values ($1, $2, now(), $3, $4, $5, $6::jsonb)
          on conflict do nothing
          `,
          [account.id, sgMessageId, "log", email, recipientDomain, JSON.stringify(detail)]
        );
        inserted += 1;
        continue;
      }

      for (const ev of normalizedEvents) {
        // Try to derive event name + timestamp (varies by API response)
        const eventName =
          ev?.event || ev?.type || ev?.name || detail?.status || "unknown";

        // Prefer unix seconds, then ISO timestamps, else now()
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

        await client.query(
          `
          insert into sendgrid_events (
            sg_account, sg_message_id, event_ts, event, ip, email, recipient_domain,
            reason, response, status, raw
          )
          values (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11::jsonb
          )
          on conflict do nothing
          `,
          [
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

  // Advance cursor to "until"
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
    results.push(await pollEmailLogsForAccount(acct));
  }
  return results;
}

// Initialize DB on startup
initDb().catch((err) => {
  console.error("DB init failed:", err);
});

// ---- Routes ----
app.get("/health", async (req, res) => {
  // basic DB connectivity check
  try {
    await pool.query("select 1 as ok");
    res.status(200).send("ok");
  } catch (err) {
    console.error("Health DB check failed:", err);
    res.status(500).send("db error");
  }
});

app.post("/admin/poll-email-logs", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  try {
    const results = await pollAllAccountsOnce();
    res.json({ ok: true, results });
  } catch (err) {
    console.error("Polling failed:", err);
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.get("/admin/accounts", (req, res) => {
  res.json({
    accountsConfigured: SENDGRID_ACCOUNTS.map((a) => a.id),
  });
});

app.post("/webhooks/sendgrid/events", async (req, res) => {
  const events = req.body;

  if (!Array.isArray(events)) {
    console.log("Received non-array payload");
    return res.status(204).send();
  }

  console.log(`Received ${events.length} SendGrid events`);

  // Bulk insert (simple + reliable for your scale)
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
          e.timestamp || null, // SendGrid gives unix seconds
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
    console.error("Insert failed:", err);
  } finally {
    client.release();
  }

  res.status(204).send();
});

// ---- Listen ----
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});