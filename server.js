// server.js
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();

// ✅ Middleware
app.use(cors());          // Enables CORS for all origins
app.use(express.json());  // Parses JSON request bodies

// ✅ Config
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tilleddb';
const PORT = process.env.PORT || 10000;

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
    if (!data[field] || typeof data[field] !== 'string' || !data[field].trim()) {
      return `${field} is required and must be a non-empty string`;
    }
  }

  // Optional fields
  const optional = ['phone', 'address', 'gstNumber', 'companyName', 'status', 'remark'];
  for (const field of optional) {
    if (field in data && data[field] != null && typeof data[field] !== 'string') {
      return `${field} must be a string`;
    }
  }

  return null;
}

// ✅ POST /tilled — create record
app.post('/tilled', async (req, res) => {
  try {
    const payload = req.body;
   
   const findTenant = await  tilledCollection.findOne({ tenantId: payload.tenantId });

  if(findTenant){
return res.status(422).json({ success: false, message: 'Alreay exists' });

  }

    const doc = {
      ...payload,
      tenantId: payload.tenantId.trim(),
      email: payload.email.trim().toLowerCase(),
      name: payload.name.trim(),
      createdAt: new Date(),
     status: 'created'
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

// ✅ Start server after DB connects
connectToDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
});
