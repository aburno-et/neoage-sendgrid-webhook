@ -927,78 +927,65 @@ app.post("/admin/gpt/pull", async (req, res) => {
        let written = 0;
        let missingDate = 0;

       let loggedSample = false;

for (const item of stats) {
let dayStr = null;

// Primary (your current response): name ends with YYYYMMDD
// Example: "domains/dinfacil.net/trafficStats/20260125"
if (item && typeof item.name === "string") {
  const m = item.name.match(/\/trafficStats\/(\d{8})$/);
  if (m && m[1]) {
    const yyyymmdd = m[1];
    dayStr =
      yyyymmdd.slice(0, 4) +
      "-" +
      yyyymmdd.slice(4, 6) +
      "-" +
      yyyymmdd.slice(6, 8);
  }
}

// Fallbacks if Google returns Date messages in other shapes
for (const item of stats) {
  let dayStr = null;

  // Primary: parse YYYYMMDD from the resource name
  // Example name: "domains/dinfacil.net/trafficStats/20260125"
  if (item && typeof item.name === "string") {
    const m = item.name.match(/\/trafficStats\/(\d{8})$/);
    if (m && m[1]) {
      const yyyymmdd = m[1];
      dayStr =
        yyyymmdd.slice(0, 4) +
        "-" +
        yyyymmdd.slice(4, 6) +
        "-" +
        yyyymmdd.slice(6, 8);
    }
  }

  // Fallbacks (in case Google returns Date message fields in the future)
  if (!dayStr) {
    const d =
      (item && item.deliveryDay) ||
      (item && item.date) ||
      (item && item.day) ||
      (item && item.trafficStat && (item.trafficStat.deliveryDay || item.trafficStat.date || item.trafficStat.day)) ||
      null;

    if (typeof d === "string") {
      dayStr = d.slice(0, 10);
    } else if (d && d.year && d.month && d.day) {
      dayStr =
        String(d.year) +
        "-" +
        String(d.month).padStart(2, "0") +
        "-" +
        String(d.day).padStart(2, "0");
    }
  }

  if (!dayStr) {
    missingDate++;
    continue;
  }
        for (const item of stats) {
          let dayStr = null;

          // Primary (your actual payload): parse YYYYMMDD from item.name
          // Example: "domains/dinfacil.net/trafficStats/20260125"
          if (item && typeof item.name === "string") {
            const m = item.name.match(/\/trafficStats\/(\d{8})$/);
            if (m && m[1]) {
              const yyyymmdd = m[1];
              dayStr =
                yyyymmdd.slice(0, 4) +
                "-" +
                yyyymmdd.slice(4, 6) +
                "-" +
                yyyymmdd.slice(6, 8);
            }
          }

  await upsertGptDay(domain, dayStr, item);
  written++;
}
          // Fallbacks if Google ever returns Date message fields
          if (!dayStr) {
            const d =
              (item && item.deliveryDay) ||
              (item && item.date) ||
              (item && item.day) ||
              (item && item.trafficStat && (item.trafficStat.deliveryDay || item.trafficStat.date || item.trafficStat.day)) ||
              null;

            if (typeof d === "string") {
              dayStr = d.slice(0, 10);
            } else if (d && d.year && d.month && d.day) {
              dayStr =
                String(d.year) +
                "-" +
                String(d.month).padStart(2, "0") +
                "-" +
                String(d.day).padStart(2, "0");
            }
          }

          if (!dayStr) {
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



