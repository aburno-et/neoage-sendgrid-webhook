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

  console.log("DB initialized");
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