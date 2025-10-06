// server.js
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();

// ✅ Middleware
app.use(cors()); // Enables CORS for all origins
app.use(express.json()); // Parses JSON request bodies

// ✅ Config
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tilleddb';
const PORT = process.env.PORT || 10000;
const crypto = require('crypto');

// Replace with your Tilled webhook secret
const TILLED_WEBHOOK_SECRET = 'whsec_qiOUGoq5JwBBOp1UmL4iuOV2uIH6rJjc';

let tilledCollection;

// ✅ Connect to MongoDB
async function connectToDB() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(); // uses default db from URI
    tilledCollection = db.collection('tilled_details');

    // Create unique compound index for duplicate checking
    await tilledCollection.createIndex(
      { tenantId: 1, email: 1 },
      { unique: true, name: 'unique_tenant_email' }
    );

    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error);
    process.exit(1);
  }
}

// ✅ Validate payload
function validateTilled(data) {
  if (!data || typeof data !== 'object') return 'Payload must be an object';

  const required = ['tenantId', 'name', 'email'];
  for (const field of required) {
    if (
      !data[field] ||
      typeof data[field] !== 'string' ||
      !data[field].trim()
    ) {
      return `${field} is required and must be a non-empty string`;
    }
  }

  // Optional fields
  const optional = [
    'phone',
    'address',
    'gstNumber',
    'companyName',
    'status',
    'remark',
  ];
  for (const field of optional) {
    if (
      field in data &&
      data[field] != null &&
      typeof data[field] !== 'string'
    ) {
      return `${field} must be a string`;
    }
  }

  return null;
}

// ✅ POST /tilled — create record
app.post('/tilled', async (req, res) => {
  try {
    const payload = req.body;

    const findTenant = await tilledCollection.findOne({
      tenantId: payload.tenantId,
    });

    if (findTenant) {
      return res.status(422).json({ success: false, message: 'Alreay exists' });
    }

    const doc = {
      ...payload,
      createdAt: new Date(),
      updatedAt: new Date(),
      status: 'created',
    };

    const result = await tilledCollection.insertOne(doc);
    const created = await tilledCollection.findOne({ _id: result.insertedId });

    res.status(201).json({ success: true, data: created });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'Duplicate tilled detail for this tenant and email',
      });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ GET /tilled — list all or filter by tenant/email
app.get('/tilled', async (req, res) => {
  try {
    const { tenantId, email, limit = 50, skip = 0 } = req.query;
    const query = {};

    if (tenantId) query.tenantId = String(tenantId);
    if (email) query.email = String(email).toLowerCase();

    const docs = await tilledCollection
      .find(query)
      .skip(Number(skip))
      .limit(Number(limit))
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ success: true, data: docs });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ GET /tilled/:id — fetch one by id
app.get('/tilled/:id', async (req, res) => {
  try {
    const id = req.params.id;

    const doc = await tilledCollection.findOne({ tenantId: id });
    if (!doc) {
      return res.status(404).json({ success: false, message: 'Not found' });
    }

    res.json({ success: true, data: doc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

const SCHEME = 'v1'; // Only valid scheme

// Parse tilled-signature header
function parseHeader(header, scheme) {
  if (typeof header !== 'string') return null;

  return header.split(',').reduce(
    (accum, item) => {acct_yQNt8gFvN1UxOMxJ3mc1L
      const kv = item.split('=');
      if (kv[0] === 't') accum.timestamp = kv[1];
      if (kv[0] === scheme) accum.signature = kv[1];
      return accum;
    },
    { timestamp: -1, signature: -1 }
  );
}

// Verify Tilled webhook
function verifyTilledWebhook(req, tolerance = 5 * 60) {
  // tolerance in seconds (default 5 min)
  const tilledSignature = req.headers['tilled-signature'];
  if (!tilledSignature) return false;

  const details = parseHeader(tilledSignature, SCHEME);
  if (!details || details.timestamp === -1 || details.signature === -1)
    return false;

  // Check timestamp for replay attacks
  const now = Math.floor(Date.now() / 1000); // current time in seconds
  const timestamp = parseInt(details.timestamp, 10) / 1000;
  if (Math.abs(now - timestamp) > tolerance) {
    console.warn('Webhook timestamp outside tolerance');
    return false;
  }

  // Create signed payload
  const payload = `${details.timestamp}.${JSON.stringify(req.body)}`;

  // Compute HMAC SHA256
  const expectedSignature = crypto
    .createHmac('sha256', TILLED_WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');

  // Constant-time comparison
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature, 'hex'),
    Buffer.from(details.signature, 'hex')
  );
}

// Webhook endpoint
app.post('/webhook/merchant/status', async (req, res) => {
  try {
    console.log(
      req.header,
      '==========================Webhook Header============================'
    );
    if (!verifyTilledWebhook(req)) {
      console.warn('Webhook signature verification failed!');
      return res
        .status(401)
        .json({ success: false, message: 'Unauthorized webhook' });
    }

    const {
      data: { status, id },
    } = req.body;

    console.log(
      '============================================Webhook Body========================',
      req.body
    );

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'Missing id in webhook payload',
      });
    }

    // Find and update merchant in MongoDB
    const updatedDoc = await tilledCollection.findOneAndUpdate(
      { id },
      { $set: { status, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    console.log(`Merchant updated: status=${status}, accountId=${id}`);

    res.status(200).json({ success: true, data: updatedDoc.value });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ Start server after DB connects
connectToDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
});
