# PayPrompt (Cloudflare)

One Cloudflare Worker serves the app (public/) and the API (src/worker.js). D1 stores users, sessions and transactions. Free, no ads.

## Deploy
1. `npm i -g wrangler && wrangler login`
2. `wrangler d1 create mpesa-prompt` and paste the `database_id` into `wrangler.toml`
3. `wrangler d1 execute mpesa-prompt --remote --file=schema.sql`
4. Telegram: message @BotFather, `/newbot`, copy the token and the bot username. Put the username in `BOT_USERNAME` in `wrangler.toml`.
5. Secrets (run each, paste a value when asked):
   - `wrangler secret put ENC_KEY` (any long random string; encrypts Daraja keys. Never change it later)
   - `wrangler secret put TELEGRAM_TOKEN` (token from BotFather)
   - `wrangler secret put TG_SECRET` (any random string, letters and numbers only)
6. `wrangler deploy` (note your `https://mpesa-prompt.<you>.workers.dev` address)
7. Connect Telegram to the Worker (open this once in a browser):
   `https://api.telegram.org/bot<TELEGRAM_TOKEN>/setWebhook?url=https://<your-worker-address>/telegram/webhook/<TG_SECRET>`

Optional: push the folder to GitHub and use Workers Builds (Cloudflare dashboard > Workers > your Worker > Settings > Builds) for auto-deploy.

## Using it
Sign up, open Profile, choose Sandbox or Live, Paybill or Till, enter your details, tap Save and verify.
- Paybill: Paybill number + Account number.
- Till: Store (Head Office) number + Till number.
- Sandbox: Daraja test shortcode 174379 and the test passkey from the Daraja portal.
Live needs Safaricom go-live approval. Callbacks go to your Worker address automatically.

Telegram: tap Connect Telegram in Profile, press Start in the bot, then send `0712345678 500` (paybill with account: `0712345678 500 ACC123`).
