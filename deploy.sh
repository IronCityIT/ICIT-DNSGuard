#!/bin/bash
# DNS Guard Complete Deployment Script
# Run this in Google Cloud Shell

set -e

echo "🚀 DNS Guard Deployment"
echo "======================="

# Variables - UPDATE THESE
HUBSPOT_API_KEY="${HUBSPOT_API_KEY:-pat-na2-65386d82-e63f-4a12-be97-aa6e715f6308}"
GITHUB_PAT="${GITHUB_PAT:-YOUR_GITHUB_PAT_HERE}"
GCP_PROJECT="icit-dnsguard"
REGION="us-east5"

echo ""
echo "📋 Configuration:"
echo "   GCP Project: $GCP_PROJECT"
echo "   Region: $REGION"
echo "   HubSpot API Key: ${HUBSPOT_API_KEY:0:20}..."
echo "   GitHub PAT: ${GITHUB_PAT:0:10}..."
echo ""

# Set project
gcloud config set project $GCP_PROJECT

# ============================================
# STEP 1: Deploy Cloud Functions
# ============================================
echo "📦 Step 1: Deploying Cloud Functions..."

cd cloud-function

# Deploy triggerDNSScan function
echo "   Deploying triggerDNSScan..."
gcloud functions deploy triggerDNSScan \
  --gen2 \
  --runtime=nodejs20 \
  --region=$REGION \
  --trigger-http \
  --no-allow-unauthenticated \
  --set-env-vars="HUBSPOT_API_KEY=$HUBSPOT_API_KEY,GITHUB_PAT=$GITHUB_PAT" \
  --project=$GCP_PROJECT

# Deploy storeScanResults function
echo "   Deploying storeScanResults..."
gcloud functions deploy storeScanResults \
  --gen2 \
  --runtime=nodejs20 \
  --region=$REGION \
  --trigger-http \
  --no-allow-unauthenticated \
  --project=$GCP_PROJECT

# Deploy getScanStatus function
echo "   Deploying getScanStatus..."
gcloud functions deploy getScanStatus \
  --gen2 \
  --runtime=nodejs20 \
  --region=$REGION \
  --trigger-http \
  --no-allow-unauthenticated \
  --project=$GCP_PROJECT

cd ..

# ============================================
# STEP 2: Enable Public Access via Console
# ============================================
echo ""
echo "⚠️  Step 2: Enable Public Access"
echo "   Due to org policy, you need to enable public access manually."
echo ""
echo "   Open these URLs and set 'Allow unauthenticated invocations':"
echo ""
echo "   1. https://console.cloud.google.com/run/detail/$REGION/triggerdnsscan/security?project=$GCP_PROJECT"
echo "   2. https://console.cloud.google.com/run/detail/$REGION/storescanresults/security?project=$GCP_PROJECT"
echo "   3. https://console.cloud.google.com/run/detail/$REGION/getscanstatus/security?project=$GCP_PROJECT"
echo ""
read -p "Press Enter after enabling public access for all 3 functions..."

# ============================================
# STEP 3: Update Dashboard with correct URLs
# ============================================
echo ""
echo "📝 Step 3: Getting function URLs..."

TRIGGER_URL=$(gcloud functions describe triggerDNSScan --region=$REGION --project=$GCP_PROJECT --format='value(serviceConfig.uri)')
STORE_URL=$(gcloud functions describe storeScanResults --region=$REGION --project=$GCP_PROJECT --format='value(serviceConfig.uri)')

echo "   Trigger URL: $TRIGGER_URL"
echo "   Store URL: $STORE_URL"

# Update dashboard with correct trigger URL
sed -i "s|https://triggerdnsscan-43248247502.us-east5.run.app|$TRIGGER_URL|g" dashboard/public/index.html

echo "   ✅ Dashboard updated with function URLs"

# ============================================
# STEP 4: Deploy Firebase Hosting
# ============================================
echo ""
echo "🌐 Step 4: Deploying Firebase Hosting..."

firebase deploy --only hosting --project $GCP_PROJECT

# ============================================
# STEP 5: Update GitHub Repo
# ============================================
echo ""
echo "📤 Step 5: Pushing to GitHub..."

# Check if git is initialized
if [ ! -d ".git" ]; then
    git init
    git remote add origin https://github.com/IronCityIT/ICIT-DNSGuard.git
fi

git add -A
git commit -m "DNS Guard Complete: Self-service scan, AI Consensus Engine, HubSpot integration" || true
git branch -M main
git push -u origin main --force

# ============================================
# STEP 6: Add GitHub Secret for Cloud Function URL
# ============================================
echo ""
echo "🔐 Step 6: Setting GitHub Secrets..."
echo "   Add this secret to your GitHub repo:"
echo ""
echo "   DNSGUARD_CLOUD_FUNCTION_URL=$STORE_URL"
echo ""
echo "   Go to: https://github.com/IronCityIT/ICIT-DNSGuard/settings/secrets/actions"
echo ""

# ============================================
# DONE
# ============================================
echo ""
echo "✅ Deployment Complete!"
echo ""
echo "📋 Summary:"
echo "   Dashboard: https://icit-dnsguard.web.app"
echo "   Trigger API: $TRIGGER_URL"
echo "   Store API: $STORE_URL"
echo ""
echo "🧪 Test it:"
echo "   1. Go to https://icit-dnsguard.web.app"
echo "   2. Enter your work email"
echo "   3. Click 'Run Free Assessment'"
echo "   4. Wait ~60-90 seconds for results"
echo ""
