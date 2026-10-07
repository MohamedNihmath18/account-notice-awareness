import crypto from "node:crypto";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { getStore } from "@netlify/blobs";

const REDIRECT_URI = "https://account-notice.netlify.app/.netlify/functions/auth-callback";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function signState(payload) {
  const raw = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", required("AZURE_CLIENT_SECRET"))
    .update(raw).digest("base64url");
  return `${raw}.${sig}`;
}

export default async function handler() {
  const clientId = required("AZURE_CLIENT_ID");
  const tenantId = required("AZURE_TENANT_ID");
  const clientSecret = required("AZURE_CLIENT_SECRET");

  const eventId = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const store = getStore("awareness-events");
  await store.setJSON(`event:${eventId}`, {
    eventId,
    createdAt,
    email: null,
    status: "started"
  });

  const state = signState({
    eventId,
    issuedAt: Date.now()
  });

  const msal = new ConfidentialClientApplication({
    auth: {
      clientId,
      clientSecret,
      authority: `https://login.microsoftonline.com/${tenantId}`
    }
  });

  const authUrl = await msal.getAuthCodeUrl({
    scopes: ["openid", "profile", "email"],
    redirectUri: REDIRECT_URI,
    state,
    prompt: "select_account"
  });

  return Response.redirect(authUrl, 302);
}
