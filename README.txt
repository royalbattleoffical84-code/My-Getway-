PayX Professional Upgrade — API Docs, PayX AI and Premium Plan

Files:
- index-backend-connected.html: merchant/user panel with Developer Centre, endpoint guide, PHP server-to-server order example, hosted checkout/QR flow, API documentation, searchable copy-ready AI prompt library, PayX AI helper, and Premium membership plan card.
- admin-backend-connected.html: admin panel with API docs CRUD, AI prompt CRUD, PayX AI enable/welcome-message controls, and Premium plan settings (enable/disable, price, duration, description, three benefits).
- server.js: backend with /api/docs, /api/ai/prompts, protected admin management endpoints, and validated persistence/public exposure of PayX AI and Premium display settings.

Theme: retains the existing PayX navy/blue/cyan theme; the new features follow that visual system.

Deployment:
1. Back up your current files first.
2. Deploy server.js to your trusted backend host. Install dependencies using your existing package.json/lockfile and configure Firebase plus FAM/payment secrets as server environment variables.
3. Deploy both HTML files to your static host and set the correct backend API base URL in the frontend configuration if your deployment requires it.
4. Sign in to Admin > Settings to configure the PayX AI welcome message and Premium price/duration/benefits. API docs and prompt library are managed in Admin > API Docs / Settings.
5. Test in a staging environment before launch.

Important limits/security:
- PayX AI in this package is a built-in guided FAQ helper with curated answers, not a live generative AI model. A live model requires a configured AI provider and secure backend endpoint.
- Premium plan settings are displayed and configurable, but this UI does not collect membership payments or securely activate a subscription. Verify payment and implement a trusted admin/backend activation workflow before selling memberships.
- The API example uses POST /api/v1/orders with X-PayX-Key and returns a hosted checkoutUrl. Replace YOUR-PAYX-DOMAIN with your deployed backend domain. The hosted checkout handles payment instructions/QR where supported; this sample does not create a standalone QR itself.
- Never embed API secrets in public HTML, browser JavaScript, mobile apps, query strings, or the AI assistant. Verify payment status server-side and validate webhook signatures before fulfilment.


NAVIGATION / UI UPDATE
- Admin panel navigation is now a top-left three-line hamburger that opens a full-height left drawer. The old bottom row of six admin buttons is removed.
- Merchant/user panel has its own refreshed responsive layout: sticky top header, horizontally scrollable labeled navigation chips, and better spacing on mobile/desktop.

FIREBASE REALTIME DATABASE RULES
- See database.rules.json. This backend uses the Firebase Admin SDK with a service-account credential, which bypasses Realtime Database client rules. The frontend should call the PayX backend API rather than connect directly to the database. Therefore the recommended production rules deny all direct client reads/writes. This protects user credentials, payment orders, API key mappings, wallet ledger, admin settings, Premium config and AI prompts. Do not replace this with public read/write rules.
- Firebase Console > Realtime Database > Rules > paste database.rules.json > Publish. Back up existing rules first. Admin SDK backend operations continue to work with these rules.

GEMINI LIVE PAYX AI
- Added POST /api/ai/chat. The browser calls the backend; the Gemini API key stays on the server. If the key is absent or the model fails, the UI falls back to the built-in FAQ responses.
- Add GEMINI_API_KEY and GEMINI_MODEL in the backend host's Environment / Variables page. Never add the Gemini key to either HTML file, Firebase config, a public .env file, or a Git repository.
- Required existing variables: FIREBASE_DB_URL, FIREBASE_SERVICE_ACCOUNT, TOKEN_SECRET (16+ chars; use a strong random value), FAMAPI_KEY for payments. Also configure PUBLIC_URL and ALLOWED_ORIGINS for your deployment. A sample is in .env.example; do not upload real secrets in that file.
- Gemini API key: create/manage it in Google AI Studio, restrict it to the Gemini/Generative Language API where supported, and rotate it if exposed. Set usage limits/monitor usage.
- The AI endpoint has a basic per-IP rate limit; add a stronger edge/server rate limiter for production and monitor API usage.

DEPLOYMENT NOTES
1. Deploy the updated server.js to the backend host and set the environment variables above. Restart/redeploy the backend after adding variables.
2. Upload updated index-backend-connected.html and admin-backend-connected.html to your frontend host. Keep the existing API base URL pointed at your real backend.
3. Apply database.rules.json in Firebase Realtime Database Rules. This app's backend Admin SDK uses the service account and is not blocked by client rules.
4. Test admin drawer links, user navigation, API docs, prompt copy buttons, Gemini chat, login, payment status and webhook handling on staging before production.

IMPORTANT
- Premium settings currently configure the offer display; they do not by themselves collect Premium payment or securely activate a subscription. Do not advertise a membership as paid/active until a trusted backend verifies payment and applies activation.
- Gemini answers are informational. Never use AI output as payment proof.
