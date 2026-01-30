const functions = require('@google-cloud/functions-framework');
const { Firestore } = require('@google-cloud/firestore');

const firestore = new Firestore();

// Environment variables (set during deployment)
const HUBSPOT_API_KEY = process.env.HUBSPOT_API_KEY;
const GITHUB_PAT = process.env.GITHUB_PAT;
const GITHUB_REPO = 'IronCityIT/ICIT-DNSGuard';
const GITHUB_WORKFLOW = 'dns-analysis.yml';
const STORE_RESULTS_URL = process.env.STORE_RESULTS_URL || 'https://storescanresults-43248247502.us-east5.run.app';

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

/**
 * Main function: Trigger DNS Scan
 * 1. Validate input
 * 2. Create HubSpot contact
 * 3. Generate scan_id
 * 4. Store initial scan record in Firestore
 * 5. Trigger GitHub workflow
 * 6. Return scan_id for polling
 */
functions.http('triggerDNSScan', async (req, res) => {
  // Set CORS headers
  Object.entries(corsHeaders).forEach(([key, value]) => res.set(key, value));
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).send('');
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, domain } = req.body;
    
    // Validate input
    if (!email || !domain) {
      return res.status(400).json({ error: 'Email and domain are required' });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Block free email providers
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'mail.com', 'protonmail.com'];
    const emailDomain = email.split('@')[1].toLowerCase();
    if (freeProviders.includes(emailDomain)) {
      return res.status(400).json({ error: 'Please use your work email address' });
    }
    
    // Clean domain
    const cleanDomain = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    
    // Generate unique scan ID
    const scanId = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // 1. Create HubSpot contact (async, don't block on failure)
    createHubSpotContact(email, cleanDomain).catch(err => {
      console.error('HubSpot error (non-blocking):', err.message);
    });
    
    // 2. Store initial scan record in Firestore
    const scanDoc = {
      domain: cleanDomain,
      email: email,
      status: 'queued',
      created_at: new Date().toISOString(),
      source: 'free-scan',
      client_name: 'Free Scan User'
    };
    
    await firestore.collection('scans').doc(scanId).set(scanDoc);
    console.log(`Created scan record: ${scanId}`);
    
    // 3. Trigger GitHub workflow
    const workflowTriggered = await triggerGitHubWorkflow(cleanDomain, scanId);
    
    if (!workflowTriggered) {
      // Update scan status to failed
      await firestore.collection('scans').doc(scanId).update({
        status: 'failed',
        error: 'Failed to trigger scan workflow'
      });
      return res.status(500).json({ error: 'Failed to start scan. Please try again.' });
    }
    
    // Update status to running
    await firestore.collection('scans').doc(scanId).update({
      status: 'running',
      started_at: new Date().toISOString()
    });
    
    // Return scan ID for polling
    return res.status(200).json({
      success: true,
      domain: cleanDomain,
      message: 'Scan started successfully',
      poll_url: `https://icit-dnsguard.web.app/?scan=${scanId}`
    });
    
  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Store scan results (called by GitHub workflow)
 */
functions.http('storeScanResults', async (req, res) => {
  Object.entries(corsHeaders).forEach(([key, value]) => res.set(key, value));
  
  if (req.method === 'OPTIONS') {
    return res.status(204).send('');
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const scanData = req.body;
    const scanId = scanData.scan_id;
    
    scanData.status = 'complete';
    scanData.completed_at = new Date().toISOString();
    
    if (scanId) {
      // Update existing scan document
      await firestore.collection('scans').doc(scanId).set(scanData, { merge: true });
      console.log(`Updated scan: ${scanId}`);
    } else {
      // Create new document (fallback for manual runs)
      const docRef = await firestore.collection('scans').add({
        ...scanData,
        timestamp: new Date().toISOString()
      });
      console.log(`Created scan: ${docRef.id}`);
      return res.status(200).json({ success: true, id: docRef.id });
    }
    
    return res.status(200).json({ success: true, id: scanId });
    
  } catch (error) {
    console.error('Error storing results:', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Get scan status (for polling)
 */
functions.http('getScanStatus', async (req, res) => {
  Object.entries(corsHeaders).forEach(([key, value]) => res.set(key, value));
  
  if (req.method === 'OPTIONS') {
    return res.status(204).send('');
  }

  const scanId = req.query.scan_id || req.body?.scan_id;
  
  if (!scanId) {
    return res.status(400).json({ error: 'scan_id required' });
  }

  try {
    const doc = await firestore.collection('scans').doc(scanId).get();
    
    if (!doc.exists) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    return res.status(200).json(doc.data());
    
  } catch (error) {
    console.error('Error getting scan:', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Create HubSpot contact
 */
async function createHubSpotContact(email, domain) {
  if (!HUBSPOT_API_KEY) {
    console.log('HubSpot API key not configured, skipping');
    return;
  }

  const response = await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${HUBSPOT_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      properties: {
        email: email,
        company: domain,
        website: `https://${domain}`,
        hs_lead_status: 'NEW',
        lifecyclestage: 'lead',
        hs_analytics_source: 'DIRECT_TRAFFIC',
        hs_analytics_source_data_1: 'dns-guard-free-scan'
      }
    })
  });

  if (response.ok) {
    const data = await response.json();
    console.log(`HubSpot contact created: ${data.id}`);
    return data;
  } else if (response.status === 409) {
    console.log('HubSpot contact already exists');
    return { existing: true };
  } else {
    const error = await response.text();
    throw new Error(`HubSpot error: ${error}`);
  }
}

/**
 * Trigger GitHub Actions workflow
 */
async function triggerGitHubWorkflow(domain, scanId) {
  if (!GITHUB_PAT) {
    console.error('GitHub PAT not configured');
    return false;
  }

  try {
    const response = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/actions/workflows/${GITHUB_WORKFLOW}/dispatches`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${GITHUB_PAT}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ref: 'main',
          inputs: {
            domain: domain,
            client_name: 'Free Scan User',
            enable_subdomains: 'true',
            enable_threat_intel: 'true'
          }
        })
      }
    );

    if (response.status === 204 || response.ok) {
      console.log(`GitHub workflow triggered for ${domain}, scan_id: ${scanId}`);
      return true;
    } else {
      const error = await response.text();
      console.error(`GitHub API error: ${response.status} - ${error}`);
      return false;
    }
  } catch (error) {
    console.error('GitHub workflow trigger error:', error);
    return false;
  }
}
