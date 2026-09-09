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

## Telegram notifications

The app can mirror in-app notifications (deposit confirmed, order accepted, payment/trade completed, order expired, KYC status) out to Telegram, styled like:

> 🎉 *Deposit Successful\!*
>
> Your USDT deposit has been processed and credited to your wallet\.
>
> *Deposit Details:*
> • Amount: 10\.09 USDT
> • Status: ✅ Confirmed

Without any setup this is a safe no-op — `telegram.js` just logs what it would have sent. To actually enable it:

1. **Create a bot.** Message [@BotFather](https://t.me/BotFather) on Telegram, run `/newbot`, and note the token and the bot's `@username`.
2. **Set environment variables** before starting the server:
   - `TELEGRAM_BOT_TOKEN` — the token BotFather gave you
   - `TELEGRAM_BOT_USERNAME` — the bot's username, without the `@`
   - `APP_URL` — the public URL of this app (used for the "Open the app" link in messages)
   - `APP_NAME` — optional, defaults to "Once P2P"
3. **Register the webhook** so Telegram delivers messages to this server (needs to be reachable over HTTPS):
   ```bash
   curl "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook?url=<APP_URL>/api/telegram/webhook"
   ```
4. **`/start` just works.** As soon as someone opens the bot and taps Telegram's own "Start" button (or types `/start`), they get a welcome message with a "🚀 Start Trading" button that opens `APP_URL` directly — no account linking required for this. If `APP_URL` is `https://`, it opens as a Telegram in-app webview (`web_app` button); otherwise it falls back to a plain link button.
5. **Users link their account** from the app: open the notifications panel and tap "Get these as Telegram notifications". That calls `POST /api/telegram/link-code`, which returns a one-time `https://t.me/<bot>?start=<code>` link; tapping it and hitting "Start" in Telegram links that chat to their account (handled by `POST /api/telegram/webhook`).

Every call to `addNotification()` on the server automatically sends the matching Telegram message to any user who has linked their chat — no per-event wiring needed for new notification types beyond adding a template in `telegram.js` if you want a richer layout than the generic title/body fallback.

## Important

This is a development build. Do not use real identity documents or real money until production authentication, database storage, secure document storage, audit logging, rate limiting, and a suitable regulated payment provider are implemented and reviewed.
