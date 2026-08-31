# Once P2P v9.1

KYC + Wallet + Marketplace development build with protected P2P trade and escrow flows.

## Project structure

- `index.js` — Express server and API
- `package.json` — Node dependencies and start script
- `public/index.html` — user interface
- `public/admin.html` — admin interface
- `.gitignore` — ignores local data and uploads

## Local development

```bash
npm install
npm start
```

Open `http://localhost:3000` for the user app and `http://localhost:3000/admin` for the admin page.

The default development admin key is `change-me-admin-key`. Set `ADMIN_KEY` to a strong secret before any real deployment.

## Important

This is a development build. Do not use real identity documents or real money until production authentication, database storage, secure document storage, audit logging, rate limiting, and a suitable regulated payment provider are implemented and reviewed.
