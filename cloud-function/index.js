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
    
    // Clean domain, then PROVE it is a hostname. This endpoint is public and
    // unauthenticated, and its output reaches a command line in CI — stripping
    // the scheme is not validation. Anything that is not a plain hostname is
    // rejected here as well as in the workflow.
    const cleanDomain = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();
    const hostnameRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
    if (!hostnameRe.test(cleanDomain) || cleanDomain.length > 253) {
      return res.status(400).json({ error: 'Please enter a valid domain name' });
    }
    
    // Generate unique scan ID
    const scanId = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // 1. Create HubSpot contact (async, don't block on failure)
    createHubSpotContact(email, cleanDomain).catch(err => {
      console.error('HubSpot error (non-blocking):', err.message);
    });
    
    // 2. Store initial scan record in Firestore
    // The dashboard queries `where('scan_id','==',id)`, so scan_id must exist as
    // a FIELD, not only as the document id. Without it every poll returned empty
    // and the free scan span forever. `timestamp` is written for the same reason:
    // the dashboard's fallback query orders by it, and a document missing the
    // field is excluded from an orderBy result entirely.
    const nowIso = new Date().toISOString();
    const scanDoc = {
      scan_id: scanId,
      domain: cleanDomain,
      target: cleanDomain,
      email: email,
      status: 'queued',
      created_at: nowIso,
      timestamp: nowIso,
      source: 'free-scan',
      client_name: 'Free Scan User',
      client_id: 'free-scan'
    };
    
    await firestore.collection('scans').doc(scanId).set(scanDoc);
    console.log(`Created scan record: ${scanId}`);
    
    // 3. Trigger GitHub workflow
    const workflowTriggered = await triggerGitHubWorkflow(cleanDomain, scanId);
    // NOTE: scanId is now forwarded as a workflow input (see below). Previously
    // it was not, so the workflow minted its own id and the queued document was
    // never updated by anything.
    
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
    // scan_id is what the dashboard polls on. Omitting it made the caller poll
    // for `undefined`, which never matched anything.
    return res.status(200).json({
      success: true,
      scan_id: scanId,
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

    // The workflow reports its own outcome. Forcing 'complete' here used to make
    // a failed scan indistinguishable from a successful one in the dashboard.
    const reported = scanData.status === 'failed' ? 'failed' : 'complete';
    scanData.status = reported;
    scanData.completed_at = new Date().toISOString();

    if (scanId) {
      const ref = firestore.collection('scans').doc(scanId);

      // Status is monotonic. The workflow reports a failure whenever ANY job in
      // the run failed, which includes a run whose scan succeeded and whose
      // analysis did not — that run has already stored real findings here, and
      // overwriting them with an empty failure record would lose them.
      if (reported === 'failed') {
        const existing = await ref.get();
        if (existing.exists && existing.get('status') === 'complete') {
          await ref.set({ error: scanData.error || { message: 'a stage of this run failed' } },
                        { merge: true });
          console.log(`Failure report ignored — scan already complete: ${scanId}`);
          return res.status(200).json({ success: true, id: scanId, status: 'already_complete' });
        }
      }

      // Update existing scan document
      await ref.set(scanData, { merge: true });
      console.log(`Updated scan: ${scanId} (${reported})`);
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
    
    // This endpoint is public (CORS *) and unauthenticated. Returning the raw
    // document handed out the submitter's email address to anyone holding a
    // scan id, so the response is now field-limited to the scan itself.
    const { email, ...safe } = doc.data();
    return res.status(200).json(safe);
    
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
            scan_id: scanId,
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
