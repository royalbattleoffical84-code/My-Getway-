PayX package

Files:
- server.js: Node/Express backend for Render
- admin.html: Admin panel frontend
- user.html: Merchant/user panel frontend

Important frontend URLs configured in user.html:
- API backend: https://my-getway.onrender.com
- Customer payment page: https://payxoffical.infinityfreeapp.com/#/pay/ORDER_ID

Deployment notes:
1. Deploy server.js to the Git repository connected to Render, then redeploy the Render service.
2. Upload user.html to InfinityFree as the site's index.html (rename it to index.html when uploading).
3. Upload admin.html to the intended admin-panel hosting location.
4. Set backend secrets/environment variables on Render; do not put FAM API keys in HTML files.

The ZIP contains the current panel files and backend source. Updating these local files does not automatically deploy them to Render or InfinityFree.
