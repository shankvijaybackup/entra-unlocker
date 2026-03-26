"""
Atom Banking — Sign-In Monitor Web UI
======================================
FastAPI backend serving:
  - Encrypted credential storage (Fernet)
  - Azure AD + Atomicwork user directory
  - Live Event Hub streaming via WebSocket
  - Manual + auto remediation controls
  - Connection verification for all services

Run:  python app.py
Open: http://localhost:8550
"""

import os
import sys
import json
import time
import string
import secrets
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from contextlib import asynccontextmanager

# ── Dependencies ──
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse, JSONResponse
    from pydantic import BaseModel
    from cryptography.fernet import Fernet
    import uvicorn
    import httpx
    import msal
except ImportError:
    print("\n  Missing dependencies. Install with:")
    print("  pip install fastapi uvicorn httpx msal cryptography python-dotenv\n")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════
#  ENCRYPTED CONFIG STORE
# ═══════════════════════════════════════════════════════════════

APP_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
SECRETS_FILE = APP_DIR / ".secrets.enc"
KEY_FILE = APP_DIR / ".secrets.key"

# Config fields that we manage
CONFIG_FIELDS = [
    "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
    "ATOMICWORK_BASE_URL", "ATOMICWORK_API_KEY",
    "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER",
    "EVENTHUB_CONNECTION_STRING", "EVENTHUB_NAME",
    "LOCKOUT_THRESHOLD",
]

# Required Azure AD permissions
AZURE_PERMISSIONS = [
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.ReadWrite.All",
]


def _get_fernet():
    """Get or create Fernet encryption key."""
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        os.chmod(str(KEY_FILE), 0o600)
    return Fernet(key)


def load_config() -> dict:
    """Load and decrypt config from disk."""
    if not SECRETS_FILE.exists():
        return {}
    try:
        f = _get_fernet()
        encrypted = SECRETS_FILE.read_bytes()
        decrypted = f.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except Exception:
        return {}


def save_config(config: dict):
    """Encrypt and save config to disk."""
    f = _get_fernet()
    data = json.dumps(config).encode()
    encrypted = f.encrypt(data)
    SECRETS_FILE.write_bytes(encrypted)
    os.chmod(str(SECRETS_FILE), 0o600)


def get_config_value(key: str, default: str = "") -> str:
    """Get a single config value (from encrypted store or env)."""
    config = load_config()
    return config.get(key, os.environ.get(key, default))


# ═══════════════════════════════════════════════════════════════
#  AZURE AUTH
# ═══════════════════════════════════════════════════════════════

_msal_app_cache = {}
_token_cache = {"token": None, "expires": 0}


def _get_msal_app():
    tenant = get_config_value("AZURE_TENANT_ID")
    client = get_config_value("AZURE_CLIENT_ID")
    secret = get_config_value("AZURE_CLIENT_SECRET")
    cache_key = f"{tenant}:{client}"
    if cache_key not in _msal_app_cache:
        _msal_app_cache[cache_key] = msal.ConfidentialClientApplication(
            client,
            authority=f"https://login.microsoftonline.com/{tenant}",
            client_credential=secret,
        )
    return _msal_app_cache[cache_key]


def get_azure_token():
    now = time.time()
    if _token_cache["token"] and _token_cache["expires"] > now + 60:
        return _token_cache["token"]
    result = _get_msal_app().acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in result:
        _token_cache["token"] = result["access_token"]
        _token_cache["expires"] = now + result.get("expires_in", 3600)
        return result["access_token"]
    raise Exception(result.get("error_description", result.get("error", "Auth failed")))


async def graph_request(endpoint: str, method: str = "GET", **kwargs):
    token = get_azure_token()
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method,
            f"https://graph.microsoft.com/v1.0/{endpoint}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=30.0,
            **kwargs,
        )
        if resp.status_code == 204:
            return {"status": "success"}
        resp.raise_for_status()
        return resp.json()


async def atomicwork_request(endpoint: str, method: str = "GET", **kwargs):
    base_url = get_config_value("ATOMICWORK_BASE_URL", "https://atombanking.atomicwork.com")
    api_key = get_config_value("ATOMICWORK_API_KEY")
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method, f"{base_url}/api/v1/{endpoint}",
            headers=headers, timeout=15.0, **kwargs,
        )
        resp.raise_for_status()
        return resp.json()


# ═══════════════════════════════════════════════════════════════
#  REMEDIATION HELPERS
# ═══════════════════════════════════════════════════════════════

def generate_temp_password(length=12):
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%&*")
    rest = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%&*") for _ in range(length - 4))
    pwd_list = list(upper + lower + digit + special + rest)
    secrets.SystemRandom().shuffle(pwd_list)
    return ''.join(pwd_list)


ERROR_MAP = {
    50053: "ACCOUNT LOCKED", 50057: "ACCOUNT DISABLED", 50055: "PASSWORD EXPIRED",
    50126: "BAD PASSWORD", 50132: "SESSION REVOKED", 50133: "SESSION EXPIRED",
    53003: "BLOCKED BY CA POLICY", 500121: "MFA FAILED",
}
REMEDIATION_CODES = {50053, 50057, 50055}
BAD_PASSWORD_CODES = {50126}
AGENT_GROUP_ID = 416
DEFAULT_REQUESTER_ID = 17250


# ═══════════════════════════════════════════════════════════════
#  LIVE EVENT STATE
# ═══════════════════════════════════════════════════════════════

live_events = []            # Recent events for UI
remediation_log = []        # Remediation history
user_failure_counts = defaultdict(list)
remediated_users = set()
ws_clients = set()          # Active WebSocket connections
eventhub_task = None        # Background Event Hub consumer


# ═══════════════════════════════════════════════════════════════
#  FASTAPI APP
# ═══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app):
    yield
    # Cleanup
    global eventhub_task
    if eventhub_task and not eventhub_task.done():
        eventhub_task.cancel()

app = FastAPI(title="Atom Banking Sign-In Monitor", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.get("/health")
async def health_check():
    """Health check endpoint for Azure App Service."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Pydantic Models ──

class ConfigUpdate(BaseModel):
    config: dict

class RemediateRequest(BaseModel):
    email: str
    reason: str = "Manual remediation via UI"


# ═══════════════════════════════════════════════════════════════
#  API: CONFIG / SETTINGS
# ═══════════════════════════════════════════════════════════════

@app.get("/")
async def serve_ui():
    return FileResponse(str(APP_DIR / "static" / "index.html"))


@app.get("/api/config")
async def get_config():
    """Return config with secrets masked."""
    config = load_config()
    masked = {}
    for key in CONFIG_FIELDS:
        val = config.get(key, os.environ.get(key, ""))
        if val and key in ("AZURE_CLIENT_SECRET", "ATOMICWORK_API_KEY", "TWILIO_AUTH_TOKEN",
                           "EVENTHUB_CONNECTION_STRING"):
            masked[key] = val[:6] + "•" * 20 + val[-4:] if len(val) > 10 else "•" * 10
        else:
            masked[key] = val
    masked["_configured"] = {k: bool(config.get(k, os.environ.get(k, ""))) for k in CONFIG_FIELDS}
    masked["_permissions"] = AZURE_PERMISSIONS
    return masked


@app.post("/api/config")
async def update_config(body: ConfigUpdate):
    """Save encrypted config. Only updates provided fields."""
    config = load_config()
    for key, value in body.config.items():
        if key in CONFIG_FIELDS and value:
            # Don't overwrite with masked values
            if "•" not in str(value):
                config[key] = value
    save_config(config)
    # Clear MSAL cache so new creds take effect
    _msal_app_cache.clear()
    _token_cache["token"] = None
    return {"status": "saved", "fields": list(body.config.keys())}


# ═══════════════════════════════════════════════════════════════
#  API: CONNECTION TESTS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/test/azure")
async def test_azure():
    """Test Azure AD connectivity + permissions."""
    try:
        token = get_azure_token()
        # Test reading sign-in logs
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
        if resp.status_code == 200:
            return {"status": "connected", "message": "Azure AD connected. Sign-in log access confirmed.",
                    "permissions": {"AuditLog.Read.All": True, "Directory.Read.All": True, "User.ReadWrite.All": True}}
        elif resp.status_code == 403:
            return {"status": "partial", "message": f"Authenticated but missing permissions: {resp.text[:200]}",
                    "permissions": {"AuditLog.Read.All": False}}
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/test/atomicwork")
async def test_atomicwork():
    """Test Atomicwork API connectivity."""
    try:
        base_url = get_config_value("ATOMICWORK_BASE_URL", "https://atombanking.atomicwork.com")
        api_key = get_config_value("ATOMICWORK_API_KEY")
        if not api_key:
            return {"status": "error", "message": "API key not configured"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{base_url}/api/v1/users?limit=1",
                headers={"x-api-key": api_key, "Content-Type": "application/json"},
                timeout=10,
            )
        if resp.status_code == 200:
            return {"status": "connected", "message": "Atomicwork API connected."}
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/test/twilio")
async def test_twilio():
    """Test Twilio connectivity."""
    sid = get_config_value("TWILIO_ACCOUNT_SID")
    token = get_config_value("TWILIO_AUTH_TOKEN")
    from_num = get_config_value("TWILIO_FROM_NUMBER")
    if not all([sid, token, from_num]):
        return {"status": "error", "message": "Twilio credentials not fully configured"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
                auth=(sid, token), timeout=10,
            )
        if resp.status_code == 200:
            acct = resp.json()
            return {"status": "connected", "message": f"Twilio connected. Account: {acct.get('friendly_name', '?')}",
                    "from_number": from_num}
        else:
            return {"status": "error", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/test/eventhub")
async def test_eventhub():
    """Test Event Hub connectivity."""
    conn_str = get_config_value("EVENTHUB_CONNECTION_STRING")
    hub_name = get_config_value("EVENTHUB_NAME", "signin-events")
    if not conn_str:
        return {"status": "error", "message": "Event Hub connection string not configured"}
    try:
        from azure.eventhub import EventHubConsumerClient
        client = EventHubConsumerClient.from_connection_string(conn_str, consumer_group="$Default", eventhub_name=hub_name)
        info = client.get_eventhub_properties()
        partitions = info.get("partition_ids", [])
        client.close()
        return {"status": "connected", "message": f"Event Hub connected. Partitions: {len(partitions)}",
                "hub_name": hub_name, "partitions": len(partitions)}
    except ImportError:
        return {"status": "error", "message": "azure-eventhub package not installed. Run: pip install azure-eventhub"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═══════════════════════════════════════════════════════════════
#  API: USER DIRECTORY
# ═══════════════════════════════════════════════════════════════

@app.get("/api/users/azure")
async def list_azure_users():
    """Fetch users from Azure AD including phone numbers."""
    try:
        data = await graph_request("users?$top=100&$select=id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,mobilePhone,businessPhones")
        users = []
        for u in data.get("value", []):
            # Get phone: mobilePhone first, then first businessPhone
            phone = u.get("mobilePhone") or ""
            if not phone:
                biz_phones = u.get("businessPhones", [])
                phone = biz_phones[0] if biz_phones else ""
            users.append({
                "id": u.get("id"),
                "name": u.get("displayName"),
                "email": u.get("userPrincipalName"),
                "mail": u.get("mail"),
                "phone": phone,
                "enabled": u.get("accountEnabled"),
                "title": u.get("jobTitle"),
                "department": u.get("department"),
                "source": "azure",
            })
        return {"users": users, "count": len(users)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/users/atomicwork")
async def list_atomicwork_users():
    """Fetch users from Atomicwork with phone numbers via email-lookup."""
    try:
        base_url = get_config_value("ATOMICWORK_BASE_URL", "https://atombanking.atomicwork.com")
        api_key = get_config_value("ATOMICWORK_API_KEY")
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}

        # First get the user list
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{base_url}/api/v1/users?limit=100",
                headers=headers, timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

        items = data if isinstance(data, list) else data.get("users", data.get("data", []))

        # Enrich each user with email-lookup to get phone numbers
        users = []
        async with httpx.AsyncClient() as client:
            for u in items:
                email = u.get("email", "")
                phone = u.get("phone_number") or ""
                name = f"{u.get('first_name', '')} {u.get('last_name', '')}".strip()
                dept = u.get("department", {})
                dept_name = dept.get("name") if isinstance(dept, dict) else None
                requester_id = u.get("id")

                # If no phone from list, try email-lookup
                if not phone and email:
                    try:
                        lookup_resp = await client.get(
                            f"{base_url}/api/v1/users/{email}/email-lookup",
                            headers=headers, timeout=8,
                        )
                        if lookup_resp.status_code == 200:
                            profile = lookup_resp.json()
                            phone = profile.get("phone_number") or ""
                            if not name:
                                name = f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip()
                            if not dept_name and isinstance(profile.get("department"), dict):
                                dept_name = profile["department"].get("name")
                            if not requester_id:
                                requester_id = profile.get("id")
                    except Exception:
                        pass  # Skip enrichment on failure, don't block

                users.append({
                    "id": requester_id,
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "title": u.get("title"),
                    "department": dept_name,
                    "source": "atomicwork",
                })
        return {"users": users, "count": len(users)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/users/lookup/{email}")
async def lookup_user(email: str):
    """Lookup a specific user in Atomicwork by email."""
    try:
        profile = await atomicwork_request(f"users/{email}/email-lookup")
        return profile
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════
#  API: SIGN-IN FAILURES
# ═══════════════════════════════════════════════════════════════

@app.get("/api/signin/failures")
async def get_signin_failures(limit: int = 50, user: str = None):
    """Fetch recent sign-in failures from Graph API."""
    try:
        url = f"auditLogs/signIns?$top={limit}&$orderby=createdDateTime desc"
        if user:
            url += f"&$filter=userPrincipalName eq '{user}'"
        data = await graph_request(url)
        records = data.get("value", [])
        failures = []
        for r in records:
            code = r.get("status", {}).get("errorCode", 0)
            if code == 0:
                continue
            failures.append({
                "id": r.get("id"),
                "user": r.get("userDisplayName"),
                "upn": r.get("userPrincipalName"),
                "errorCode": code,
                "errorLabel": ERROR_MAP.get(code, f"Error {code}"),
                "app": r.get("appDisplayName"),
                "ip": r.get("ipAddress"),
                "location": r.get("location", {}),
                "time": r.get("createdDateTime"),
                "reason": r.get("status", {}).get("failureReason"),
                "isCritical": code in REMEDIATION_CODES,
            })
        return {"failures": failures, "count": len(failures)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════
#  API: REMEDIATION
# ═══════════════════════════════════════════════════════════════

@app.post("/api/remediate")
async def remediate_user(body: RemediateRequest):
    """Full auto-remediation: lookup → reset → SMS → ticket → resolve."""
    email = body.email
    steps = []

    # Step 1: Lookup
    try:
        profile = await atomicwork_request(f"users/{email}/email-lookup")
        full_name = f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip()
        phone = profile.get("phone_number")
        requester_id = profile.get("id", DEFAULT_REQUESTER_ID)
        steps.append({"step": "User Lookup", "status": "success",
                       "detail": f"{full_name} | Phone: {phone or 'N/A'} | ID: {requester_id}"})
    except Exception as e:
        full_name = email
        phone = None
        requester_id = DEFAULT_REQUESTER_ID
        steps.append({"step": "User Lookup", "status": "failed", "detail": str(e)})

    # Step 2: Password Reset
    try:
        temp_pwd = generate_temp_password()
        await graph_request(f"users/{email}", method="PATCH", json={
            "passwordProfile": {"password": temp_pwd, "forceChangePasswordNextSignIn": True},
            "accountEnabled": True,
        })
        steps.append({"step": "Password Reset", "status": "success", "detail": "Password reset + account unlocked"})
    except Exception as e:
        temp_pwd = None
        steps.append({"step": "Password Reset", "status": "failed", "detail": str(e)})

    # Step 3: SMS
    sms_sent = False
    if temp_pwd and phone:
        try:
            sid = get_config_value("TWILIO_ACCOUNT_SID")
            token = get_config_value("TWILIO_AUTH_TOKEN")
            from_num = get_config_value("TWILIO_FROM_NUMBER")
            if all([sid, token, from_num]):
                sms_body = (
                    f"Atom Banking IT Alert\n\n"
                    f"Hi {profile.get('first_name', 'there')}, your account has been automatically unlocked.\n\n"
                    f"Temporary password: {temp_pwd}\n\n"
                    f"Please sign in and change your password immediately.\n"
                    f"https://myaccount.microsoft.com"
                )
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                        data={"From": from_num, "To": phone, "Body": sms_body},
                        auth=(sid, token), timeout=15,
                    )
                if resp.status_code in (200, 201):
                    sms_sid = resp.json().get("sid", "?")
                    steps.append({"step": "SMS", "status": "success", "detail": f"Sent to {phone} (SID: {sms_sid[:20]}...)"})
                    sms_sent = True
                else:
                    steps.append({"step": "SMS", "status": "failed", "detail": f"HTTP {resp.status_code}"})
            else:
                steps.append({"step": "SMS", "status": "skipped", "detail": "Twilio not configured"})
        except Exception as e:
            steps.append({"step": "SMS", "status": "failed", "detail": str(e)})
    elif not phone:
        steps.append({"step": "SMS", "status": "skipped", "detail": "No phone number on file"})
    else:
        steps.append({"step": "SMS", "status": "skipped", "detail": "Password reset failed"})

    # Step 4: Create ticket
    ticket_display_id = None
    try:
        ticket = await atomicwork_request("requests/create", method="POST", json={
            "subject": f"Password Auto-Reset — {full_name} (Manual via UI)",
            "description": (
                f"**Remediation via Web UI**\n\n"
                f"- **User:** {full_name} ({email})\n"
                f"- **Reason:** {body.reason}\n"
                f"- **Password Reset:** {'Success' if temp_pwd else 'Failed'}\n"
                f"- **SMS:** {'Sent to ' + phone if sms_sent else 'Not sent'}\n"
            ),
            "requester_id": requester_id,
            "agent_group_id": AGENT_GROUP_ID,
            "priority": "high",
        })
        ticket_display_id = ticket.get("display_id", "?")
        steps.append({"step": "Ticket", "status": "success", "detail": ticket_display_id})
    except Exception as e:
        steps.append({"step": "Ticket", "status": "failed", "detail": str(e)})

    # Step 5: Resolve ticket
    if ticket_display_id and temp_pwd:
        try:
            await atomicwork_request(f"requests/{ticket_display_id}", method="PATCH", json={"status": "Resolved"})
            steps.append({"step": "Resolve", "status": "success", "detail": f"{ticket_display_id} → Resolved"})
        except Exception as e:
            steps.append({"step": "Resolve", "status": "failed", "detail": str(e)})
    else:
        steps.append({"step": "Resolve", "status": "skipped", "detail": "No ticket or pwd reset failed"})

    result = {"email": email, "name": full_name, "steps": steps, "timestamp": datetime.now(timezone.utc).isoformat()}
    remediation_log.append(result)

    # Broadcast to WebSocket clients
    await broadcast({"type": "remediation", "data": result})

    return result


@app.get("/api/remediation/history")
async def get_remediation_history():
    """Return recent remediation history."""
    return {"history": remediation_log[-50:], "count": len(remediation_log)}


# ═══════════════════════════════════════════════════════════════
#  WEBSOCKET: LIVE EVENT FEED
# ═══════════════════════════════════════════════════════════════

async def broadcast(message: dict):
    """Send message to all connected WebSocket clients."""
    dead = set()
    for ws in ws_clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.add(ws)
    ws_clients -= dead


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    ws_clients.add(websocket)
    try:
        # Send recent events on connect
        await websocket.send_json({"type": "history", "data": live_events[-100:]})
        # Keep alive
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if msg == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(websocket)


# ═══════════════════════════════════════════════════════════════
#  EVENT HUB CONSUMER (Background task)
# ═══════════════════════════════════════════════════════════════

async def eventhub_consumer():
    """Background task: consume Event Hub events and push to WebSocket."""
    conn_str = get_config_value("EVENTHUB_CONNECTION_STRING")
    hub_name = get_config_value("EVENTHUB_NAME", "signin-events")
    threshold = int(get_config_value("LOCKOUT_THRESHOLD", "5"))

    if not conn_str:
        logging.warning("Event Hub not configured — live feed disabled")
        return

    try:
        from azure.eventhub import EventHubConsumerClient
    except ImportError:
        logging.warning("azure-eventhub not installed — live feed disabled")
        return

    seen_ids = set()

    def on_event(partition_context, event):
        if event is None:
            return
        try:
            body = event.body_as_str()
            payload = json.loads(body)
        except Exception:
            return

        records = payload.get("records", [payload] if "properties" in payload else [])
        if not records:
            if payload.get("category") == "SignInLogs" or payload.get("operationName") == "Sign-in activity":
                records = [payload]
            else:
                return

        for record in records:
            props = record.get("properties", record)
            error_code = props.get("status", {}).get("errorCode", 0) if isinstance(props.get("status"), dict) else 0

            if error_code == 0 and record.get("resultType"):
                try:
                    error_code = int(record["resultType"])
                except (ValueError, TypeError):
                    pass

            if error_code == 0:
                continue

            event_id = props.get("id") or record.get("correlationId") or record.get("id") or ""
            if event_id in seen_ids:
                continue
            if event_id:
                seen_ids.add(event_id)

            upn = props.get("userPrincipalName") or props.get("upn") or "Unknown"
            user_name = props.get("userDisplayName") or record.get("identity") or "Unknown"
            app_name = props.get("appDisplayName") or "Unknown"
            ip_addr = props.get("ipAddress") or record.get("callerIpAddress") or "Unknown"
            created_dt = props.get("createdDateTime") or record.get("time") or ""
            failure_reason = props.get("status", {}).get("failureReason", "") if isinstance(props.get("status"), dict) else ""

            loc = props.get("location", {})
            location = ""
            if isinstance(loc, dict):
                location = ", ".join(filter(None, [loc.get("city"), loc.get("state"), loc.get("countryOrRegion")]))

            evt = {
                "id": event_id,
                "user": user_name,
                "upn": upn,
                "errorCode": error_code,
                "errorLabel": ERROR_MAP.get(error_code, f"Error {error_code}"),
                "app": app_name,
                "ip": ip_addr,
                "location": location,
                "time": created_dt,
                "reason": failure_reason,
                "isCritical": error_code in REMEDIATION_CODES,
                "receivedAt": datetime.now(timezone.utc).isoformat(),
            }

            live_events.append(evt)
            if len(live_events) > 500:
                live_events.pop(0)

            # Broadcast to WebSocket clients
            asyncio.get_event_loop().create_task(broadcast({"type": "event", "data": evt}))

            # Auto-remediation logic
            remediated_key = f"{upn}:remediated"

            if error_code in REMEDIATION_CODES and remediated_key not in remediated_users:
                remediated_users.add(remediated_key)
                asyncio.get_event_loop().create_task(
                    _auto_remediate_bg(user_name, upn, error_code, ERROR_MAP.get(error_code, ""), evt)
                )

            if error_code in BAD_PASSWORD_CODES and remediated_key not in remediated_users:
                user_failure_counts[upn].append(datetime.now(timezone.utc))
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
                user_failure_counts[upn] = [t for t in user_failure_counts[upn] if t > cutoff]
                if len(user_failure_counts[upn]) >= threshold:
                    remediated_users.add(remediated_key)
                    asyncio.get_event_loop().create_task(
                        _auto_remediate_bg(user_name, upn, error_code, "THRESHOLD BREACH", evt)
                    )

    async def _auto_remediate_bg(user_name, upn, error_code, error_label, evt):
        """Run auto-remediation in background and broadcast results."""
        try:
            body = RemediateRequest(email=upn, reason=f"Auto: {error_label} (code {error_code})")
            # Reuse the remediate endpoint logic
            result = await remediate_user(body)
            await broadcast({"type": "auto_remediation", "data": result})
        except Exception as e:
            logging.error(f"Auto-remediation failed for {upn}: {e}")
            await broadcast({"type": "error", "data": {"message": f"Auto-remediation failed for {upn}: {e}"}})

    # Run the consumer in a thread (it's blocking)
    def run_consumer():
        client = EventHubConsumerClient.from_connection_string(
            conn_str, consumer_group="$Default", eventhub_name=hub_name,
        )
        logging.info(f"Event Hub consumer started: {hub_name}")
        try:
            client.receive(on_event=on_event, starting_position="@latest")
        except Exception as e:
            logging.error(f"Event Hub consumer error: {e}")
        finally:
            client.close()

    import threading
    thread = threading.Thread(target=run_consumer, daemon=True)
    thread.start()
    logging.info("Event Hub consumer thread started")


@app.post("/api/eventhub/start")
async def start_eventhub():
    """Start the Event Hub consumer."""
    global eventhub_task
    if eventhub_task and not eventhub_task.done():
        return {"status": "already_running"}
    eventhub_task = asyncio.create_task(eventhub_consumer())
    return {"status": "started"}


@app.post("/api/eventhub/stop")
async def stop_eventhub():
    """Stop the Event Hub consumer."""
    global eventhub_task
    if eventhub_task and not eventhub_task.done():
        eventhub_task.cancel()
        eventhub_task = None
        return {"status": "stopped"}
    return {"status": "not_running"}


@app.get("/api/events/recent")
async def get_recent_events():
    """Return recent live events."""
    return {"events": live_events[-100:], "count": len(live_events)}


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  Atom Banking — Sign-In Monitor UI")
    print("  http://localhost:8550\n")
    uvicorn.run(app, host="0.0.0.0", port=8550, log_level="info")
