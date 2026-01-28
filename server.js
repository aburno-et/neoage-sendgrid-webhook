const express = require("express");
const app = express();

app.use(express.json({ limit: "5mb" }));

// Health check (Render will call this)
app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

// SendGrid Event Webhook endpoint
app.post("/webhooks/sendgrid/events", (req, res) => {
  const events = req.body;

  if (Array.isArray(events)) {
    console.log(`Received ${events.length} SendGrid events`);
  } else {
    console.log("Received non-array payload");
  }

  // For now: just acknowledge receipt
  res.status(204).send();
});

// IMPORTANT: listen on Render's port
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});