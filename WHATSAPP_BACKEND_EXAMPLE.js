/**
 * ===================================================================
 *  LEAVE MANAGEMENT SYSTEM - Backend Reference (Node.js + Express + MongoDB)
 *  With Twilio WhatsApp API Integration
 * ===================================================================
 *
 *  This file is a REFERENCE IMPLEMENTATION showing how to build the
 *  backend for the Leave Management Workflow System.
 *
 *  To use this:
 *  1. npm init -y
 *  2. npm install express mongoose dotenv twilio cors bcryptjs jsonwebtoken
 *  3. Create a .env file with your credentials
 *  4. Run: node WHATSAPP_BACKEND_EXAMPLE.js
 *
 * ===================================================================
 */

// ===================== ENVIRONMENT (.env) =====================
// Create a .env file with:
//
// MONGODB_URI=mongodb://localhost:27017/leave_management
// JWT_SECRET=your_jwt_secret_here
// TWILIO_ACCOUNT_SID=your_twilio_account_sid
// TWILIO_AUTH_TOKEN=your_twilio_auth_token
// TWILIO_WHATSAPP_FROM=whatsapp:+14155238886
// PORT=3000

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');

const app = express();
app.use(cors());
app.use(express.json());

// ===================== DATABASE SCHEMAS =====================

/**
 * User Schema
 * Supports all roles: student, tg, cc, hod, parent
 */
const userSchema = new mongoose.Schema({
  name:              { type: String, required: true },
  email:             { type: String, unique: true, sparse: true },
  username:          { type: String, unique: true, sparse: true },
  password:          { type: String, required: true },
  role:              { type: String, enum: ['student', 'tg', 'cc', 'hod', 'parent'], required: true },
  // Student fields
  rollNumber:        { type: String },
  className:         { type: String },
  section:           { type: String },
  year:              { type: String },
  batch:             { type: String },
  department:        { type: String },
  parentPhone:       { type: String },  // WhatsApp number with country code
  // Parent fields
  studentRollNumber: { type: String },  // Links parent to student
  phone:             { type: String },  // Parent's WhatsApp number
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

/**
 * Leave Request Schema
 * Stores leave applications with multi-step approval workflow
 */
const leaveSchema = new mongoose.Schema({
  userId:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName:         { type: String, required: true },
  rollNumber:       { type: String },
  className:        { type: String },
  section:          { type: String },
  parentPhone:      { type: String },
  year:             { type: String },
  batch:            { type: String },
  department:       { type: String },
  startDate:        { type: Date, required: true },
  endDate:          { type: Date, required: true },
  days:             { type: Number, required: true },
  reason:           { type: String, required: true },
  proof:            { type: String },      // Base64 or file URL
  proofName:        { type: String },
  status: {
    type: String,
    enum: [
      'pending_tg',    // Pending Teacher Guardian Approval
      'pending_cc',    // Pending Class Coordinator Approval
      'pending_hod',   // Pending HOD Approval
      'approved',      // Fully Approved by HOD
      'rejected_tg',   // Rejected by Teacher Guardian
      'rejected_cc',   // Rejected by Class Coordinator
      'rejected_hod',  // Rejected by HOD
    ],
    default: 'pending_tg',
  },
  approvalTimeline: [{
    role:   { type: String, enum: ['tg', 'cc', 'hod'] },
    action: { type: String, enum: ['approve', 'reject'] },
    by:     { type: String },
    at:     { type: Date, default: Date.now },
  }],
}, { timestamps: true });

const Leave = mongoose.model('Leave', leaveSchema);


// ===================== WORKFLOW CONFIG =====================

const WORKFLOW = {
  tg:  { pending: 'pending_tg',  approved: 'pending_cc',  rejected: 'rejected_tg' },
  cc:  { pending: 'pending_cc',  approved: 'pending_hod', rejected: 'rejected_cc' },
  hod: { pending: 'pending_hod', approved: 'approved',    rejected: 'rejected_hod' },
};


// ===================== AUTH MIDDLEWARE =====================

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function roleMiddleware(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}


// ===================== AUTH ROUTES =====================

/**
 * POST /api/auth/register
 * Register a new user (any role)
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, username, password, role, ...rest } = req.body;

    // Check for existing user
    if (email) {
      const existing = await User.findOne({ email, role });
      if (existing) return res.status(400).json({ error: 'Email already registered for this role.' });
    }
    if (username) {
      const existing = await User.findOne({ username, role });
      if (existing) return res.status(400).json({ error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, username, password: hashedPassword, role, ...rest });
    await user.save();

    res.status(201).json({ success: true, message: 'Registration successful' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/auth/login
 * Login and receive JWT token
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { credential, password, role } = req.body;
    let user;

    if (role === 'student') {
      user = await User.findOne({ username: credential, role: 'student' });
    } else {
      user = await User.findOne({ email: credential.toLowerCase(), role });
    }

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, name: user.name, role: user.role, department: user.department, year: user.year, batch: user.batch },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { password: _, ...safeUser } = user.toObject();
    res.json({ token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ===================== LEAVE ROUTES =====================

/**
 * POST /api/leaves
 * Student submits a new leave request. Status starts as "pending_tg".
 */
app.post('/api/leaves', authMiddleware, roleMiddleware('student'), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const leave = new Leave({
      userId: user._id,
      userName: user.name,
      rollNumber: user.rollNumber,
      className: user.className,
      section: user.section,
      parentPhone: user.parentPhone,
      year: user.year,
      batch: user.batch,
      department: user.department,
      startDate: req.body.startDate,
      endDate: req.body.endDate,
      days: req.body.days,
      reason: req.body.reason,
      proof: req.body.proof || '',
      proofName: req.body.proofName || '',
      status: 'pending_tg',
      approvalTimeline: [],
    });
    await leave.save();
    res.status(201).json(leave);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/leaves/my
 * Student gets their own leaves
 */
app.get('/api/leaves/my', authMiddleware, roleMiddleware('student'), async (req, res) => {
  const leaves = await Leave.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(leaves);
});

/**
 * GET /api/leaves/parent
 * Parent gets leaves for their linked student
 */
app.get('/api/leaves/parent', authMiddleware, roleMiddleware('parent'), async (req, res) => {
  const parent = await User.findById(req.user.id);
  const leaves = await Leave.find({ rollNumber: parent.studentRollNumber }).sort({ createdAt: -1 });
  res.json(leaves);
});

/**
 * GET /api/leaves/pending
 * Admin gets leaves pending their approval (role-filtered)
 */
app.get('/api/leaves/pending', authMiddleware, roleMiddleware('tg', 'cc', 'hod'), async (req, res) => {
  const wf = WORKFLOW[req.user.role];
  const filter = { status: wf.pending };

  // Scope by academic hierarchy
  if (req.user.role === 'tg') {
    filter.year = req.user.year;
    filter.batch = req.user.batch;
    filter.department = req.user.department;
  } else if (req.user.role === 'cc') {
    filter.year = req.user.year;
    filter.department = req.user.department;
  } else if (req.user.role === 'hod') {
    filter.department = req.user.department;
  }

  const leaves = await Leave.find(filter).sort({ createdAt: -1 });
  res.json(leaves);
});

/**
 * GET /api/leaves/all
 * Admin gets all leaves in their scope (for dashboard/history)
 */
app.get('/api/leaves/all', authMiddleware, roleMiddleware('tg', 'cc', 'hod'), async (req, res) => {
  const filter = {};
  if (req.user.role === 'tg') {
    filter.year = req.user.year;
    filter.batch = req.user.batch;
    filter.department = req.user.department;
  } else if (req.user.role === 'cc') {
    filter.year = req.user.year;
    filter.department = req.user.department;
  } else if (req.user.role === 'hod') {
    filter.department = req.user.department;
  }

  const leaves = await Leave.find(filter).sort({ createdAt: -1 });
  res.json(leaves);
});

/**
 * POST /api/leaves/:id/action
 * Admin approves or rejects a leave request.
 * Workflow transitions happen automatically.
 * WhatsApp notification is triggered when HOD approves.
 */
app.post('/api/leaves/:id/action', authMiddleware, roleMiddleware('tg', 'cc', 'hod'), async (req, res) => {
  try {
    const { action } = req.body; // 'approve' or 'reject'
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action. Must be "approve" or "reject".' });
    }

    const leave = await Leave.findById(req.params.id);
    if (!leave) return res.status(404).json({ error: 'Leave not found' });

    const wf = WORKFLOW[req.user.role];
    if (leave.status !== wf.pending) {
      return res.status(400).json({ error: 'This leave is not pending your approval.' });
    }

    // Record timeline entry
    leave.approvalTimeline.push({
      role: req.user.role,
      action,
      by: req.user.name,
      at: new Date(),
    });

    // Transition status
    leave.status = action === 'approve' ? wf.approved : wf.rejected;
    await leave.save();

    // If HOD approved → trigger WhatsApp notification
    if (req.user.role === 'hod' && action === 'approve' && leave.status === 'approved') {
      await sendWhatsAppNotification(leave);
    }

    res.json({ success: true, leave });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ===================== TWILIO WHATSAPP INTEGRATION =====================

/**
 * Send WhatsApp notification to parent when leave is approved by HOD.
 *
 * Prerequisites:
 * 1. Create a Twilio account: https://www.twilio.com
 * 2. Enable WhatsApp Sandbox: https://www.twilio.com/console/sms/whatsapp/sandbox
 * 3. Set environment variables: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM
 *
 * For production:
 * - Apply for a Twilio WhatsApp Business Profile
 * - Register your WhatsApp number
 * - Use approved message templates
 */
async function sendWhatsAppNotification(leave) {
  try {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_WHATSAPP_FROM; // e.g., 'whatsapp:+14155238886'

    if (!accountSid || !authToken || !fromNumber) {
      console.warn('⚠️  Twilio credentials not configured. Skipping WhatsApp notification.');
      console.log('Message that would be sent:');
      console.log(buildWhatsAppMessage(leave));
      return;
    }

    const client = twilio(accountSid, authToken);
    const toNumber = `whatsapp:+${leave.parentPhone}`;
    const messageBody = buildWhatsAppMessage(leave);

    const message = await client.messages.create({
      body: messageBody,
      from: fromNumber,
      to: toNumber,
    });

    console.log(`✅ WhatsApp message sent! SID: ${message.sid}`);
    return message;
  } catch (err) {
    console.error('❌ Failed to send WhatsApp message:', err.message);
  }
}

/**
 * Build the WhatsApp message body.
 */
function buildWhatsAppMessage(leave) {
  const startDate = new Date(leave.startDate).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const endDate = new Date(leave.endDate).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

  return `Dear Parent,\nYour son/daughter ${leave.userName} (Roll No: ${leave.rollNumber}) has been granted leave from ${startDate} to ${endDate} for ${leave.days} day(s).\nReason: ${leave.reason}.\nApproved by HOD.\nThank you.`;
}


// ===================== START SERVER =====================

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/leave_management')
  .then(() => {
    console.log('✅ Connected to MongoDB');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
  });


// ===================== API SUMMARY =====================
/**
 * AUTH:
 *   POST /api/auth/register    - Register new user
 *   POST /api/auth/login       - Login, get JWT token
 *
 * STUDENT:
 *   POST /api/leaves           - Submit leave request (status = pending_tg)
 *   GET  /api/leaves/my        - Get student's own leaves
 *
 * PARENT:
 *   GET  /api/leaves/parent    - Get linked student's leaves
 *
 * ADMIN (TG / CC / HOD):
 *   GET  /api/leaves/pending   - Get leaves pending this role's approval
 *   GET  /api/leaves/all       - Get all leaves in scope
 *   POST /api/leaves/:id/action - Approve or reject (body: { action: 'approve' | 'reject' })
 *
 * WORKFLOW:
 *   Student submits  → pending_tg
 *   TG approves      → pending_cc       | TG rejects  → rejected_tg
 *   CC approves      → pending_hod      | CC rejects  → rejected_cc
 *   HOD approves     → approved + WhatsApp | HOD rejects → rejected_hod
 */
