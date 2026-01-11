const functions = require('@google-cloud/functions-framework');
const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();

functions.http('storeScanResults', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST') { res.status(405).send('Method Not Allowed'); return; }
  
  try {
    const scanData = req.body;
    scanData.timestamp = admin.firestore.FieldValue.serverTimestamp();
    const docRef = await db.collection('scans').add(scanData);
    console.log('Scan stored:', docRef.id);
    res.status(200).send({ success: true, scan_id: docRef.id });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send({ error: error.message });
  }
});
