// server.js
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const axios = require('axios');

const app = express();

// ✅ Middleware
app.use(cors()); // Enables CORS for all origins
app.use(express.json()); // Parses JSON request bodies

// ✅ Config
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tilleddb';
const PORT = process.env.PORT || 10000;
const crypto = require('crypto');
const TILLED_SECRET_KEY =
  'sk_OizrUDeyfqpGoa0rhOjOgfn8mq97e3bdRMFDeLG1ZT0embtHQGpwRq3Sas6msFs4VhiqWH3odQ1vyt5gzhc05rS889bs0s55HkQm';
const TILLED_ACCOUNT_ID = 'acct_yQNt8gFvN1UxOMxJ3mc1L';

// Replace with your Tilled webhook secret
// const TILLED_WEBHOOK_SECRET = 'whsec_qiOUGoq5JwBBOp1UmL4iuOV2uIH6rJjc';

let tilledCollection;
let transactionsCollections;
let upsCollection;

// ✅ Connect to MongoDB
async function connectToDB() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(); // uses default db from URI
    tilledCollection = db.collection('tilled_details');
    transactionsCollections = db.collection('transactions');
    upsCollection = db.collection('ups');

    // Create unique compound index for duplicate checking
    await tilledCollection.createIndex(
      { tenantId: 1, email: 1 },
      { unique: true, name: 'unique_tenant_email' },
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
    (accum, item) => {
      // acct_yQNt8gFvN1UxOMxJ3mc1L;
      const kv = item.split('=');
      if (kv[0] === 't') accum.timestamp = kv[1];
      if (kv[0] === scheme) accum.signature = kv[1];
      return accum;
    },
    { timestamp: -1, signature: -1 },
  );
}

// Verify Tilled webhook
function verifyTilledWebhook(req, webhookSecret, tolerance = 5 * 60) {
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
    .createHmac('sha256', webhookSecret)
    .update(payload)
    .digest('hex');

  // Constant-time comparison
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature, 'hex'),
    Buffer.from(details.signature, 'hex'),
  );
}

// Webhook endpoint
app.post('/tilled/webhook/merchant/status', async (req, res) => {
  try {
    console.log(
      req.header,
      '==========================Webhook Header============================',
    );
    const TILLED_WEBHOOK_SECRET = 'whsec_qiOUGoq5JwBBOp1UmL4iuOV2uIH6rJjc';
    if (!verifyTilledWebhook(req, TILLED_WEBHOOK_SECRET)) {
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
      req.body,
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
      { returnDocument: 'after' },
    );

    console.log(`Merchant updated: status=${status}, accountId=${id}`);

    res.status(200).json({ success: true, data: updatedDoc.value });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/tilled/webhook/payment_intent', async (req, res) => {
  try {
    console.log(
      req.header,
      '==========================Webhook Header============================',
    );
    const TILLED_WEBHOOK_SECRET = 'whsec_k1dtxzwgyDDk9UtXhkW9oG0PiDYPHDMz';
    if (!verifyTilledWebhook(req, TILLED_WEBHOOK_SECRET)) {
      console.warn('Webhook signature verification failed!');
      return res
        .status(401)
        .json({ success: false, message: 'Unauthorized webhook' });
    }

    const {
      data: { status, id },
    } = req.body;

    console.log(
      '============================================Payment Intent Webhook====================================',
      req.body,
    );

    // if (!id) {
    //   return res.status(400).json({
    //     success: false,
    //     message: 'Missing id in webhook payload',
    //   });
    // }

    // // Find and update merchant in MongoDB
    // const updatedDoc = await tilledCollection.findOneAndUpdate(
    //   { id },
    //   { $set: { status, updatedAt: new Date() } },
    //   { returnDocument: 'after' }
    // );

    // console.log(`Merchant updated: status=${status}, accountId=${id}`);

    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * POST /create-payment-intent
 * Body: { payment_method_id, amount, currency }
 */
app.post('/tilled/create-payment-intent', async (req, res) => {
  const {
    payment_method_id,
    amount,
    currency = 'usd',
    paymentMethod,
  } = req.body;

  if (!amount) {
    return res
      .status(400)
      .json({ success: false, error: 'Missing required parameters' });
  }

  try {
    const response = await fetch(
      'https://sandbox-api.tilled.com/v1/payment-intents',
      {
        method: 'POST',
        headers: {
          'Tilled-Api-Key':
            'sk_OizrUDeyfqpGoa0rhOjOgfn8mq97e3bdRMFDeLG1ZT0embtHQGpwRq3Sas6msFs4VhiqWH3odQ1vyt5gzhc05rS889bs0s55HkQm',
          'Content-Type': 'application/json',
          'Tilled-Account': 'acct_yQNt8gFvN1UxOMxJ3mc1L',
        },
        body: JSON.stringify({
          amount,
          currency,
          payment_method_id,
          // confirm: true,
          platform_fee_amount: 100,
          payment_method_types: [paymentMethod],
          metadata: {
            tenantId: 'development',
          },
        }),
      },
    );

    const data = await response.json();
    console.log(data, '=============data=============');
    // const transactions = db.collection('transactions');
    await transactionsCollections.insertOne(data);

    if (!response.ok) {
      return res.status(response.status).json({ success: false, error: data });
    }

    res.json({ success: true, paymentIntent: data });
  } catch (err) {
    console.error('Tilled API error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create a Checkout Session
app.post('/tilled/create-checkout-session', async (req, res) => {
  try {
    const {
      amount,
      currency = 'usd',
      cancel_url,
      success_url,
      customer_email,
      customer_id,
      line_items,
      metadata,
    } = req.body;

    if (!amount || !line_items) {
      return res.status(400).json({
        success: false,
        error:
          'Missing required parameters: amount and line_items are required',
      });
    }

    const response = await fetch(
      'https://sandbox-api.tilled.com/v1/checkout/sessions',
      {
        method: 'POST',
        headers: {
          'Tilled-Api-Key': process.env.TILLED_SECRET_KEY, // use env var
          'Tilled-Account': process.env.TILLED_ACCOUNT_ID, // acct_xxx
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cancel_url: cancel_url || 'https://yourdomain.com/cancel',
          success_url: success_url || 'https://yourdomain.com/success',
          customer_email,
          customer_id,
          line_items: line_items || [
            {
              name: 'Sample Product',
              amount: amount, // in cents
              currency: currency,
              quantity: 1,
            },
          ],
          metadata: metadata || { order_id: '12345' },
          payment_intent_data: {
            capture_method: 'automatic', // could also be 'manual'
            statement_descriptor: 'Your Business',
          },
        }),
      },
    );

    const data = await response.json();
    console.log('Checkout Session Created:', data);

    if (!response.ok) {
      return res.status(response.status).json({ success: false, error: data });
    }

    res.json({ success: true, session: data });
  } catch (err) {
    console.error('Error creating checkout session:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ================= UPS CONFIG =================

const UPS_CLIENT_ID = 'bsxaAsLLPSY0xPQnckJKU0QtRefs0aXXGfxDI9B9G5rbJuWG';
const UPS_CLIENT_SECRET =
  'I2oqmOMGG4T0MP680JxClRUB4ER5FcytrpFMyNxDdU81zlOKfqzlLPrNRvTwThCj';

// Sandbox
const UPS_BASE_URL = 'https://wwwcie.ups.com';

let upsTokenCache = {
  token: null,
  expiresAt: 0,
};

async function getUPSToken() {
  try {
    const now = Date.now();

    // Return cached token if still valid
    if (upsTokenCache.token && upsTokenCache.expiresAt > now) {
      return upsTokenCache.token;
    }

    const auth = Buffer.from(`${UPS_CLIENT_ID}:${UPS_CLIENT_SECRET}`).toString(
      'base64',
    );

    // Match original curl body
    const body = new URLSearchParams({
      client_id: UPS_CLIENT_ID,
      client_secret: UPS_CLIENT_SECRET,
      grant_type: 'client_credentials',
    }).toString();

    const response = await axios.post(
      `${UPS_BASE_URL}/security/v1/oauth/token`,
      body,
      {
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          Accept: '*/*',
        },
        timeout: 15000,
      },
    );

    const { access_token, expires_in } = response.data;

    if (!access_token) {
      throw new Error('UPS OAuth did not return access_token');
    }

    // Cache token (subtract 60s safety buffer)
    upsTokenCache = {
      token: access_token,
      expiresAt: now + (expires_in - 60) * 1000,
    };

    console.log('✅ UPS token refreshed', access_token);

    return access_token;
  } catch (err) {
    console.error('❌ UPS OAuth Error:', err.response?.data || err.message);
    throw err;
  }
}

// ================= UPS SHIPPER ACCOUNT =================

app.post('/ups/profile', async (req, res) => {
  try {
    const tenantId = req.headers['x-customer-context'];

    if (!tenantId) {
      return res.status(400).json({
        success: false,
        message: 'Missing X-Customer-Context',
      });
    }

    const token = await getUPSToken();

    const response = await axios.post(
      `${UPS_BASE_URL}/customers/v1/register`,
      req.body,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-Customer-Context': tenantId,
          'Content-Type': 'application/json',
        },
      },
    );
    const result = await upsCollection.insertOne(response.data);
    console.log('UPS Profile Response:', response.data);

    res.json({ success: true, data: response.data });
  } catch (err) {
    console.error('UPS Profile Error:', err);
    console.error('UPS Profile Error:', err.response?.data || err.message);

    res.status(500).json({
      success: false,
      error: err.response?.data || err.message,
    });
  }
});

app.post('/ups/shipper-account', async (req, res) => {
  try {
    const tenantId = req.headers['x-customer-context'];

    if (!tenantId) {
      return res.status(400).json({
        success: false,
        message: 'Missing X-Customer-Context',
      });
    }

    const token = await getUPSToken();

    const response = await axios.post(
      `${UPS_BASE_URL}/api/customers/v1/account`,
      req.body,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'X-Customer-Context': tenantId,
          'Content-Type': 'application/json',
        },
      },
    );

    console.log('UPS Account Response:', response.data);
    const result = await upsCollection.insertOne(response.data);

    res.json({ success: true, data: response.data });
  } catch (err) {
    console.error('UPS Account Error:', err);

    res.status(500).json({
      success: false,
      error: err.response?.data || err.message,
    });
  }
});

// ✅ Start server after DB connects
connectToDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
});

// development-ec.enterprisehub.io/tilled/webhook/payment_intent

// whsec_k1dtxzwgyDDk9UtXhkW9oG0PiDYPHDMz
