import { getStore } from "@netlify/blobs";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

export default async function handler(request) {
  try {
    // Simple IT-admin protection.
    // The admin email is checked using an HTTP Basic Auth username.
    const adminEmail = required("AWARENESS_ADMIN_EMAIL");
    const adminPassword = required("AWARENESS_ADMIN_PASSWORD");

    const auth = request.headers.get("authorization") || "";

    if (!auth.startsWith("Basic ")) {
      return new Response("Authentication required.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Awareness Results"'
        }
      });
    }

    const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
    const separator = decoded.indexOf(":");

    const username = separator >= 0 ? decoded.slice(0, separator) : "";
    const password = separator >= 0 ? decoded.slice(separator + 1) : "";

    if (
      username.toLowerCase() !== adminEmail.toLowerCase() ||
      password !== adminPassword
    ) {
      return new Response("Access denied.", {
        status: 403,
        headers: {
          "WWW-Authenticate": 'Basic realm="Awareness Results"'
        }
      });
    }

    const store = getStore("awareness-events");

    const { blobs } = await store.list();

    const records = [];

    for (const blob of blobs) {
      if (!blob.key.startsWith("event:")) continue;

      const record = await store.get(blob.key, { type: "json" });

      if (record) {
        records.push({
          eventId: record.eventId || blob.key.replace("event:", ""),
          email: record.email || "",
          startedAt: record.startedAt || "",
          clickedAt: record.clickedAt || record.startedAt || "",
          completedAt: record.completedAt || "",
          status: record.status || ""
        });
      }
    }

    records.sort((a, b) => {
      const timeA = Date.parse(a.completedAt || a.startedAt || 0);
      const timeB = Date.parse(b.completedAt || b.startedAt || 0);
      return timeB - timeA;
    });

    const rows = records.map(record => `
      <tr>
        <td>${escapeHtml(record.email)}</td>
        <td>${escapeHtml(record.startedAt)}</td>
        <td>${escapeHtml(record.completedAt)}</td>
        <td>${escapeHtml(record.status)}</td>
        <td><code>${escapeHtml(record.eventId)}</code></td>
      </tr>
    `).join("");

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Awareness Results</title>
<style>
body {
  margin: 0;
  padding: 30px;
  background: #f5f6f8;
  font-family: Arial, Helvetica, sans-serif;
  color: #111;
}

.container {
  max-width: 1200px;
  margin: auto;
}

h1 {
  margin-bottom: 6px;
}

.subtitle {
  color: #666;
  margin-bottom: 25px;
}

.card {
  background: white;
  border-radius: 14px;
  padding: 20px;
  box-shadow: 0 5px 25px rgba(0,0,0,.08);
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 850px;
}

th, td {
  padding: 13px;
  border-bottom: 1px solid #ddd;
  text-align: left;
}

th {
  background: #f0f1f3;
}

code {
  font-size: 11px;
}

.count {
  margin-bottom: 15px;
  font-weight: bold;
}
</style>
</head>

<body>
<div class="container">

<h1>🔐 Security Awareness Results</h1>

<div class="subtitle">
IT Department — Authorized Awareness Exercise
</div>

<div class="card">

<div class="count">
Total recorded events: ${records.length}
</div>

<table>
<thead>
<tr>
<th>Work Email</th>
<th>Started</th>
<th>Completed</th>
<th>Status</th>
<th>Event ID</th>
</tr>
</thead>

<tbody>
${rows || `
<tr>
<td colspan="5">No awareness events recorded yet.</td>
</tr>
`}
</tbody>

</table>

</div>
</div>
</body>
</html>`;

    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    });

  } catch (err) {
    console.error("RESULTS ERROR:", err);

    return new Response(
      "Unable to load awareness results.",
      { status: 500 }
    );
  }
}