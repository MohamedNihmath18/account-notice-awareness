import crypto from "node:crypto";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { getStore } from "@netlify/blobs";

const REDIRECT_URI = "https://account-notice.netlify.app/.netlify/functions/auth-callback";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function verifyState(state) {
  const parts = String(state || "").split(".");
  if (parts.length !== 2) throw new Error("Invalid state");

  const [raw, suppliedSig] = parts;
  const expectedSig = crypto.createHmac("sha256", required("AZURE_CLIENT_SECRET"))
    .update(raw).digest("base64url");

  const a = Buffer.from(suppliedSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("Invalid state signature");
  }

  const payload = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));

  // State is valid for 10 minutes.
  if (!payload.issuedAt || Date.now() - payload.issuedAt > 10 * 60 * 1000) {
    throw new Error("Expired state");
  }

  if (!payload.eventId) throw new Error("Missing event ID");
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

export default async function handler(request) {
  try {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error) {
      return new Response("Authentication was cancelled or failed.", { status: 400 });
    }
    if (!code || !state) {
      return new Response("Missing authentication response.", { status: 400 });
    }

    const { eventId } = verifyState(state);

    const msal = new ConfidentialClientApplication({
      auth: {
        clientId: required("AZURE_CLIENT_ID"),
        clientSecret: required("AZURE_CLIENT_SECRET"),
        authority: `https://login.microsoftonline.com/${required("AZURE_TENANT_ID")}`
      }
    });

    const tokenResponse = await msal.acquireTokenByCode({
      code,
      scopes: ["openid", "profile", "email"],
      redirectUri: REDIRECT_URI
    });

    const account = tokenResponse.account;
    const email =
      account?.username ||
      tokenResponse.idTokenClaims?.preferred_username ||
      tokenResponse.idTokenClaims?.email ||
      "";

    if (!email) throw new Error("Authenticated account did not provide an email/UPN.");

    const store = getStore("awareness-events");
    const key = `event:${eventId}`;
    const existing = await store.get(key, { type: "json" });

    if (!existing) {
      throw new Error("Awareness event was not found.");
    }

    const completedAt = new Date().toISOString();

    await store.setJSON(key, {
      ...existing,
      email,
      completedAt,
      status: "authenticated"
    });

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Awareness</title>
<style>
body{margin:0;min-height:100vh;background:#f7f7f7;font-family:Arial,Helvetica,sans-serif;
display:flex;align-items:center;justify-content:center;padding:24px;color:#111}
.card{max-width:680px;width:100%;background:#fff;border-radius:16px;padding:38px;
box-shadow:0 12px 40px rgba(0,0,0,.15);text-align:center}
.icon{font-size:54px}h1{font-size:32px;margin:8px 0 18px}
p{font-size:17px;line-height:1.6}.small{font-size:13px;color:#666;margin-top:22px}
</style>
</head>
<body>
<div class="card">
<div class="icon">⚠️</div>
<h1>YOU CLICKED IT</h1>
<p><strong>This was an authorized IT security awareness exercise.</strong></p>
<p>No password was collected.<br>No account was compromised.</p>
<p><strong>Think before clicking links in unexpected emails.</strong></p>
<p class="small">Cybersecurity Awareness • IT Department</p>
</div>
</body>
</html>`;

    return new Response(html, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=UTF-8" }
    });
  } catch (err) {
    console.error("AUTH CALLBACK ERROR:", err);
    return new Response(
      "The awareness exercise could not complete authentication. Please contact the IT Department.",
      { status: 500 }
    );
  }
}
