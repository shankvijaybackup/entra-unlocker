# Entra Unlocker — Sign-In Monitor

Real-time Azure AD (Entra ID) sign-in failure detection and auto-remediation platform for Atom Banking.

## What It Does

Monitors Azure AD sign-in events in real time via Event Hub. When it detects account lockouts, disabled accounts, expired passwords, or repeated bad password attempts, it automatically:

1. **Looks up** the user in Atomicwork (name, phone, requester ID)
2. **Resets** their password via Microsoft Graph API and re-enables the account
3. **Sends SMS** with the temporary password via Twilio
4. **Creates** an incident ticket in Atomicwork
5. **Resolves** the ticket automatically (full audit trail)

No human intervention required. Average remediation time: under 30 seconds.

## Architecture

```
Azure AD Sign-In Logs
        │
        ▼
   Azure Event Hub  ──WebSocket──▶  Sign-In Monitor (FastAPI + React)
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    ▼                     ▼                     ▼
            Graph API              Twilio SMS            Atomicwork
        (Password Reset)      (User Notification)    (Ticket + Resolve)
```

## Tech Stack

- **Backend:** Python 3.11, FastAPI, Gunicorn + Uvicorn
- **Frontend:** React 18 (single HTML file), Tailwind CSS
- **Auth:** MSAL Confidential Client (client credentials flow)
- **Encryption:** Fernet (AES-128-CBC) for credential storage
- **Streaming:** Azure Event Hub consumer + WebSocket push
- **Deployment:** Azure App Service (B1 Linux)

## Quick Start (Local)

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:8550
```

Go to **Settings**, enter your credentials, and test each connection.

## Deploy to Azure

```bash
chmod +x deploy.sh
./deploy.sh
```

This creates the Resource Group, App Service Plan, Web App, deploys code, and sets the startup command.

## Required Credentials

| Service | Fields | Purpose |
|---------|--------|---------|
| **Azure AD** | Tenant ID, Client ID, Client Secret | Graph API access (sign-in logs, password reset) |
| **Event Hub** | Connection String, Hub Name | Real-time sign-in event stream |
| **Atomicwork** | Base URL, API Key | User lookup, ticket creation |
| **Twilio** | Account SID, Auth Token, From Number | SMS notifications |

### Azure AD App Registration Permissions

- `AuditLog.Read.All` — Read sign-in logs
- `Directory.Read.All` — List users
- `User.ReadWrite.All` — Reset passwords, enable accounts

## Project Structure

```
signin-monitor-ui/
├── app.py              # FastAPI backend (APIs, WebSocket, Event Hub consumer, remediation)
├── static/
│   └── index.html      # React SPA (Dashboard, Live Feed, Users, Remediation, Settings)
├── requirements.txt    # Python dependencies
├── deploy.sh           # Azure App Service deployment script
├── Dockerfile          # Container option
├── architecture.html   # Visual architecture document
└── README.md           # This file
```

## Trigger Conditions

- **Instant:** Error codes 50053 (Locked), 50057 (Disabled), 50055 (Password Expired)
- **Threshold:** 5+ bad password attempts (50126) within 30 minutes

## License

Internal — Atom Banking
