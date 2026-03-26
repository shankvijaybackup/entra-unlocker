#!/bin/bash
set -e

# ══════════════════════════════════════════════════════════
#  Atom Banking — Sign-In Monitor: Azure Deployment
# ══════════════════════════════════════════════════════════
#
#  Deploys as Python code directly (no Docker needed).
#  Creates: Resource Group → App Service → deploys code → sets port
#
#  Usage:
#    chmod +x deploy.sh
#    ./deploy.sh
#
#  Prerequisites:
#    - Azure CLI (az) installed and logged in
# ══════════════════════════════════════════════════════════

# ── Configuration ──
RESOURCE_GROUP="rg-atombank-signin"
LOCATION="australiaeast"
APP_NAME="atombank-signin-monitor-app"
APP_PLAN="plan-atombank-signin"

echo ""
echo "  ══════════════════════════════════════════════════════"
echo "  Atom Banking — Sign-In Monitor Deployment"
echo "  ══════════════════════════════════════════════════════"
echo ""
echo "  Resource Group:  $RESOURCE_GROUP"
echo "  Location:        $LOCATION"
echo "  App Name:        $APP_NAME"
echo ""

# ── Check prerequisites ──
echo "▸ Checking prerequisites..."
command -v az >/dev/null 2>&1 || { echo "  ✗ Azure CLI not found. Install: https://aka.ms/installazurecli"; exit 1; }
az account show >/dev/null 2>&1 || { echo "  ✗ Not logged in. Run: az login"; exit 1; }
SUBSCRIPTION=$(az account show --query name -o tsv)
echo "  ✓ Azure CLI ready (Subscription: $SUBSCRIPTION)"
echo ""

# ── Step 1: Resource Group ──
echo "▸ Step 1: Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
echo "  ✓ $RESOURCE_GROUP ($LOCATION)"

# ── Step 2: App Service Plan ──
echo "▸ Step 2: Creating App Service Plan (B1 Linux)..."
az appservice plan create \
  --resource-group $RESOURCE_GROUP \
  --name $APP_PLAN \
  --is-linux \
  --sku B1 \
  --location $LOCATION \
  --output none
echo "  ✓ $APP_PLAN"

# ── Step 3: Create Web App ──
echo "▸ Step 3: Creating Web App (Python 3.11)..."
az webapp create \
  --resource-group $RESOURCE_GROUP \
  --plan $APP_PLAN \
  --name $APP_NAME \
  --runtime "PYTHON:3.11" \
  --output none
echo "  ✓ $APP_NAME"

# ── Step 4: Set build-on-deploy BEFORE deploying ──
echo "▸ Step 4: Enabling build-on-deploy..."
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --settings \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true \
    WEBSITES_PORT=8000 \
  --output none
echo "  ✓ Build-on-deploy enabled"

# ── Step 5: Deploy code (az webapp up triggers pip install) ──
echo "▸ Step 5: Deploying code + installing dependencies (takes ~3 min)..."

az webapp up \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --runtime "PYTHON:3.11" \
  --sku B1

echo "  ✓ Code deployed + dependencies installed"

# ── Step 6: Set startup command AFTER deploy (az webapp up can reset it) ──
echo "▸ Step 6: Setting startup command..."
az webapp config set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --startup-file "gunicorn app:app -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 --timeout 120" \
  --output none
echo "  ✓ Startup command set"

# ── Step 7: Restart to pick up the startup command ──
echo "▸ Step 7: Restarting app..."
az webapp restart \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME
echo "  ✓ App restarted"

echo ""
echo "  ══════════════════════════════════════════════════════"
echo "  ✓ DEPLOYMENT COMPLETE"
echo "  ══════════════════════════════════════════════════════"
echo ""
echo "  App URL:  https://$APP_NAME.azurewebsites.net"
echo ""
echo "  Next steps:"
echo "    1. Open the URL above"
echo "    2. Go to Settings page"
echo "    3. Enter your Azure, Atomicwork, Twilio, Event Hub credentials"
echo "    4. Click 'Save & Encrypt'"
echo "    5. Test each connection"
echo "    6. Go to Live Feed → Start Stream"
echo ""
echo "  To restrict access to your network only:"
echo "    az webapp config access-restriction add \\"
echo "      --resource-group $RESOURCE_GROUP --name $APP_NAME \\"
echo "      --rule-name 'AllowMyIP' --action Allow --priority 50 \\"
echo "      --ip-address '<your-ip>/32'"
echo ""
echo "  To redeploy after code changes:"
echo "    zip -j /tmp/deploy.zip app.py requirements.txt && zip -r /tmp/deploy.zip static/"
echo "    az webapp deploy --resource-group $RESOURCE_GROUP --name $APP_NAME --src-path /tmp/deploy.zip --type zip"
echo ""
