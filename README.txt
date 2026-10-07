ACCOUNT-NOTICE.NETLIFY.APP
Authorized IT Security Awareness Simulation

FILES
-----
index.html
netlify.toml
package.json
netlify/functions/login.mjs
netlify/functions/auth-callback.mjs

BEFORE DEPLOYING
----------------
1. In Microsoft Entra ID, app registration:
   IT Security Awareness

2. Under Authentication > Web, register exactly:
   https://account-notice.netlify.app/.netlify/functions/auth-callback

3. In Netlify, create these environment variables:
   AZURE_CLIENT_ID
   AZURE_TENANT_ID
   AZURE_CLIENT_SECRET

4. Make sure the variables are available to Functions.

5. Deploy the whole project.

DATA STORED
-----------
Netlify Blobs store one event record containing:
- event ID
- initial click/start timestamp
- authenticated work email/UPN
- authentication completion timestamp
- status

No Microsoft password or MFA code is collected or stored.

IMPORTANT
---------
Do not put AZURE_CLIENT_SECRET in index.html or commit it to GitHub.
The client secret must remain a Netlify server-side environment variable.

The simulation is intended for an authorized internal security-awareness campaign.
