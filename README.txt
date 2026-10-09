PayX package

Files:
- server.js: Node/Express backend for Render
- admin.html: Admin panel frontend
- user.html: Merchant/user panel frontend

URLs configured in user.html:
- API backend: https://my-getway.onrender.com
- Customer payment page: https://payxoffical.infinityfreeapp.com/#/pay/ORDER_ID

Admin loading fix:
- The admin data endpoint now avoids Firebase orderByChild index requirements for the initial dashboard load.
- The admin panel shows an error and Retry button instead of staying on Loading forever if the API request fails.

Deployment:
1. Replace server.js in the GitHub repository connected to Render and redeploy the Render service.
2. Upload admin.html to the location where the admin panel is hosted, replacing the old admin file.
3. Upload user.html to InfinityFree as index.html (rename it to index.html when uploading).
4. Keep FAM API keys and other secrets only in Render environment variables, never in HTML.

Important: Editing these local files does not automatically update the live sites. Backend secrets must remain configured in Render.
