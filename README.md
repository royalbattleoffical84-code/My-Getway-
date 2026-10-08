# PayX — Single Backend FAM + Merchant Wallet

## Flow
1. Merchant creates a payment link from the merchant panel or `POST /api/v1/orders`.
2. Customer opens the PayX checkout link.
3. The backend creates the provider order using the **single `FAMAPI_KEY` configured on Render**.
4. Customer pays through the provider.
5. Backend polls/verifies the provider order.
6. On confirmed success, the merchant's PayX wallet is credited by the **full payment amount**. The platform fee is tracked separately in `totalFees` and the order `fee`; it is not deducted from the wallet credit in this build.
7. The payment money itself is collected by the account/provider represented by the backend FAM API key. PayX does not expose FAM credentials to merchants.
8. Merchant can request a withdrawal from wallet; admin marks it paid or rejects it. Rejected withdrawals are refunded to the wallet.

## Render environment
- `FIREBASE_DB_URL`
- `FIREBASE_SERVICE_ACCOUNT`
- `FAMAPI_KEY` — the single backend/provider key
- `FAMAPI_BASE` — defaults to `https://famapi-orcin.vercel.app`
- `TOKEN_SECRET` — random secret, 16+ characters
- `PUBLIC_URL` — public checkout base URL, e.g. `https://payxoffical.infinityfreeapp.com`
- `ALLOWED_ORIGINS` — comma-separated frontend origins
- `ADMIN_USER` / `ADMIN_PASS` — used only on first startup if no admin exists

## Firebase
Import `firebase-rules.json` into Realtime Database Rules.

## Deploy
Use Node 18+ and `npm start`.
