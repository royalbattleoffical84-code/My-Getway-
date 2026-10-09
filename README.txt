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
