WiFi Audio Robot Python license server for Vercel

STATUS: source is ready and 12 local API tests pass. A separate rolled-back
transaction verified the live Supabase seven-day trial RPC. No Vercel deployment
or live URL has been created yet. Tests mock database API responses.

Use PythonServer as the Vercel project root. Vercel detects FastAPI and loads
app.py:app; Python version is 3.12. Install Vercel CLI, login, run vercel to link
the project, then configure these server-only Environment Variables:

SUPABASE_URL=https://xzwsnbyoiezktuusiysq.supabase.co
SUPABASE_SECRET_KEY=your backend sb_secret_ key or legacy service-role key
OWNER_PRIVATE_KEY_PEM=the full ORIGINAL owner-private.pem with header/footer
and newlines (literal escaped newline sequences are also supported).

Never commit these secrets or put them in the PC app. Private key is deliberately
absent from the archive. Preserve the original key for existing licenses.
Redeploy with vercel --prod after setting environment variables.

schema.sql has already been provisioned in the connected Supabase project.
For another database, run that SQL first. Trial/IP/PC/MAC history, rate limits
and license revocations persist in Postgres, not Vercel's temporary filesystem.
Existing self-hosted trial databases must be migrated before customer use;
this package does not import files from your PC automatically.

After deploying, check https://YOUR-PROJECT.vercel.app/health. This health endpoint
checks that the API is running, not database credentials. Then test real trial
and paid activation. In the PC Subscription window set server URL to:
https://YOUR-PROJECT.vercel.app (the client appends /v1/authorize).
Use the HTTPS hostname rather than an IP address. Production API must be usable
without a Vercel account login. Never ship a deployment bypass token to customers.

Existing RSA-PSS/SHA256 WAR2 owner keys are supported. Paid keys stay PC-bound;
exact expiry is preserved for offline-cache compatibility. Expired trials and
revoked keys are rejected. Manage revocation in Supabase war.licenses by setting
revoked=true for the corresponding license_id. No public key-issuing endpoint,
public administrator API or automatic payment checkout is included.

Vercel overwrites X-Forwarded-For; trust it only under platform-provided VERCEL=1.
Outside Vercel the code uses the socket IP. Do not manually set VERCEL=1 on
another host. Additional proxies require review before enforcing trials by IP.
Audio remains direct between PC and phone over WiFi/Bluetooth. Only the license
API runs on Vercel; Windows GUI/audio and Android background behavior are unchanged.

Local setup: python -m venv .venv; install -r requirements.txt in that environment.
Set server variables securely, then run:
uvicorn app:app --host 127.0.0.1 --port 45900 --no-proxy-headers
Tests: python -m unittest -v test_server
Live Vercel routing, gateway IP behavior and native Windows activation still
require post-deployment validation.

References:
https://vercel.com/docs/functions/runtimes/python
https://vercel.com/docs/headers/request-headers
https://supabase.com/docs/guides/getting-started/api-keys
