// ===== SERVER.JS - COMPLETE BACKEND WITH AUTH =====

// Load environment variables
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json()); // ✅ JSON data read karne ke liye
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use(helmet());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use('/api/', limiter);

// ===== DATABASE CONNECTION =====
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/growthify')
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.log('⚠️ MongoDB not connected:', err.message));

// =============================================
// ===== SCHEMAS =====
// =============================================

// ===== USER SCHEMA (UPDATED with phone) =====
const UserSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true, 
    trim: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    trim: true, 
    lowercase: true 
  },
  phone: { 
    type: String, 
    required: true, 
    trim: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'editor'], 
    default: 'user' 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});
const User = mongoose.model('User', UserSchema);

// Contact/Lead Schema
const ContactSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, minlength: 3 },
  email: { type: String, required: true, trim: true, lowercase: true },
  phone: { type: String, trim: true },
  subject: { type: String, required: true, trim: true },
  message: { type: String, required: true, trim: true, minlength: 10 },
  status: { type: String, enum: ['new', 'read', 'replied'], default: 'new' },
  createdAt: { type: Date, default: Date.now }
});
const Contact = mongoose.model('Contact', ContactSchema);

// Subscriber Schema
const SubscriberSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  isActive: { type: Boolean, default: true },
  subscribedAt: { type: Date, default: Date.now }
});
const Subscriber = mongoose.model('Subscriber', SubscriberSchema);

// Audit Request Schema
const AuditSchema = new mongoose.Schema({
  url: { type: String, required: true },
  email: { type: String, required: true },
  status: { type: String, enum: ['pending', 'processing', 'completed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const Audit = mongoose.model('Audit', AuditSchema);

// Blog Schema
const BlogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  excerpt: { type: String, required: true },
  content: { type: String, required: true },
  image: { type: String },
  tags: [String],
  author: { type: String, default: 'Admin' },
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Blog = mongoose.model('Blog', BlogSchema);

// =============================================
// ===== EMAIL SETUP =====
// =============================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-password'
  }
});

// =============================================
// ===== AUTH MIDDLEWARE =====
// =============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access denied. No token provided.' 
    });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token.' 
      });
    }
    req.user = user;
    next();
  });
};

// =============================================
// ===== USER AUTHENTICATION API =====
// =============================================

// ===== 1. SIGNUP API =====
app.post('/api/signup', [
  body('name').notEmpty().withMessage('Name is required').isLength({ min: 2 }),
  body('email').isEmail().withMessage('Valid email is required'),
  body('phone').isLength({ min: 10 }).withMessage('Valid phone number is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const { name, email, phone, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { phone }] 
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or phone already exists.'
      });
    }

    // Hash the password using bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role: 'user'
    });

    await user.save();

    // Generate JWT Token
    const token = jwt.sign(
      { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    // Send welcome email
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER || 'your-email@gmail.com',
        to: email,
        subject: '🎉 Welcome to Growthify!',
        html: `
          <h2>Welcome to Growthify, ${name}! 🚀</h2>
          <p>Your account has been created successfully.</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone:</strong> ${phone}</p>
          <br>
          <p>Start exploring our services today!</p>
          <p>Team Growthify</p>
        `
      };
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.log('⚠️ Welcome email not sent:', emailError.message);
    }

    res.status(201).json({
      success: true,
      message: 'User registered successfully!',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Signup Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// ===== 2. LOGIN API =====
app.post('/api/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    // Check password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    // Generate JWT Token
    const token = jwt.sign(
      { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful!',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// ===== 3. UPDATE USER PROFILE API =====
app.put('/api/update', authenticateToken, [
  body('email').optional().isEmail().withMessage('Valid email is required'),
  body('phone').optional().isLength({ min: 10 }).withMessage('Valid phone number is required'),
  body('name').optional().isLength({ min: 2 }).withMessage('Name must be at least 2 characters')
], async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false, 
        errors: errors.array() 
      });
    }

    const userId = req.user.id;
    const { name, email, phone, password } = req.body;

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    // Check if email or phone already exists (if updating)
    if (email || phone) {
      const existingUser = await User.findOne({
        _id: { $ne: userId },
        $or: [
          ...(email ? [{ email }] : []),
          ...(phone ? [{ phone }] : [])
        ]
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email or phone already in use by another account.'
        });
      }
    }

    // Update fields
    if (name) user.name = name;
    if (email) user.email = email;
    if (phone) user.phone = phone;

    // Update password if provided
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 6 characters.'
        });
      }
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
    }

    await user.save();

    // Send update confirmation email
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER || 'your-email@gmail.com',
        to: user.email,
        subject: '📝 Profile Updated - Growthify',
        html: `
          <h2>Your Profile Has Been Updated</h2>
          <p>Hello ${user.name},</p>
          <p>Your account information has been successfully updated.</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Phone:</strong> ${user.phone}</p>
          ${password ? '<p><strong>Password:</strong> Changed successfully</p>' : ''}
          <br>
          <p>If you didn\'t make these changes, please contact us immediately.</p>
          <p>Team Growthify</p>
        `
      };
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.log('⚠️ Update email not sent:', emailError.message);
    }

    // Generate new token
    const token = jwt.sign(
      { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Profile updated successfully!',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Update Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// ===== 4. GET USER PROFILE =====
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    res.json({
      success: true,
      user
    });

  } catch (error) {
    console.error('Profile Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// ===== 5. DELETE USER ACCOUNT =====
app.delete('/api/delete-account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.'
      });
    }

    res.json({
      success: true,
      message: 'Account deleted successfully.'
    });

  } catch (error) {
    console.error('Delete Account Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// =============================================
// ===== CONTACT API (UPDATED with phone) =====
// =============================================
app.post('/api/contact', [
  body('name').isLength({ min: 3 }).withMessage('Name must be at least 3 characters'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('phone').optional().isLength({ min: 10 }).withMessage('Valid phone number is required'),
  body('subject').notEmpty().withMessage('Subject is required'),
  body('message').isLength({ min: 10 }).withMessage('Message must be at least 10 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { name, email, phone, subject, message } = req.body;
    
    // Save to database
    const contact = new Contact({ name, email, phone, subject, message });
    await contact.save();

    // Send email notification to admin
    const adminMailOptions = {
      from: process.env.EMAIL_USER || 'your-email@gmail.com',
      to: process.env.ADMIN_EMAIL || 'admin@growthify.com',
      subject: `📩 New Contact: ${subject}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        ${phone ? `<p><strong>Phone:</strong> ${phone}</p>` : ''}
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong><br>${message}</p>
        <hr>
        <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
      `
    };
    await transporter.sendMail(adminMailOptions).catch(() => console.log('⚠️ Email not sent (no config)'));

    // Send confirmation email to client
    const clientMailOptions = {
      from: process.env.EMAIL_USER || 'your-email@gmail.com',
      to: email,
      subject: '✅ We Received Your Message - Growthify',
      html: `
        <h2>Thank You for Contacting Growthify! 🚀</h2>
        <p>Dear ${name},</p>
        <p>We have received your message and our team will get back to you within 24 hours.</p>
        ${phone ? `<p><strong>Your Phone:</strong> ${phone}</p>` : ''}
        <p><strong>Your Message:</strong><br>${message}</p>
        <br>
        <p>Best regards,<br><strong>Growthify Team</strong></p>
      `
    };
    await transporter.sendMail(clientMailOptions).catch(() => console.log('⚠️ Client email not sent (no config)'));

    res.status(201).json({
      success: true,
      message: '✅ Message sent successfully! We\'ll get back to you soon.'
    });

  } catch (error) {
    console.error('Contact Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// =============================================
// ===== NEWSLETTER API =====
// =============================================
app.post('/api/newsletter', [
  body('email').isEmail().withMessage('Valid email is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email } = req.body;
    
    let subscriber = await Subscriber.findOne({ email });
    
    if (subscriber) {
      if (subscriber.isActive) {
        return res.status(400).json({
          success: false,
          message: 'This email is already subscribed!'
        });
      } else {
        subscriber.isActive = true;
        await subscriber.save();
        return res.json({
          success: true,
          message: '✅ Subscription reactivated!'
        });
      }
    }

    subscriber = new Subscriber({ email });
    await subscriber.save();

    // Send welcome email
    const mailOptions = {
      from: process.env.EMAIL_USER || 'your-email@gmail.com',
      to: email,
      subject: '🎉 Welcome to Growthify Newsletter!',
      html: `
        <h2>Welcome to Growthify Newsletter! 🚀</h2>
        <p>Thank you for subscribing to our newsletter.</p>
        <p>You'll receive marketing tips, industry updates, and exclusive offers.</p>
        <br>
        <p>Team Growthify</p>
      `
    };
    await transporter.sendMail(mailOptions).catch(() => console.log('⚠️ Welcome email not sent (no config)'));

    res.status(201).json({
      success: true,
      message: '✅ Subscribed successfully! Check your email.'
    });

  } catch (error) {
    console.error('Newsletter Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// =============================================
// ===== AUDIT API =====
// =============================================
app.post('/api/audit', [
  body('url').isURL().withMessage('Valid URL is required'),
  body('email').isEmail().withMessage('Valid email is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { url, email } = req.body;
    
    const audit = new Audit({ url, email });
    await audit.save();

    // Send confirmation
    const mailOptions = {
      from: process.env.EMAIL_USER || 'your-email@gmail.com',
      to: email,
      subject: '🔍 Your SEO Audit Request - Growthify',
      html: `
        <h2>🔍 SEO Audit Request Received</h2>
        <p>We received your audit request for: <strong>${url}</strong></p>
        <p>Our team will analyze your website and send the complete report within 24 hours.</p>
        <br>
        <p>Team Growthify</p>
      `
    };
    await transporter.sendMail(mailOptions).catch(() => console.log('⚠️ Audit email not sent (no config)'));

    res.json({
      success: true,
      message: '✅ Audit request received! We\'ll send the report to your email.'
    });

  } catch (error) {
    console.error('Audit Error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// =============================================
// ===== ADMIN APIs =====
// =============================================

// ===== GET ALL CONTACTS (Admin) =====
app.get('/api/admin/contacts', async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== GET ALL SUBSCRIBERS (Admin) =====
app.get('/api/admin/subscribers', async (req, res) => {
  try {
    const subscribers = await Subscriber.find({ isActive: true });
    res.json(subscribers);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== GET ALL AUDITS (Admin) =====
app.get('/api/admin/audits', async (req, res) => {
  try {
    const audits = await Audit.find().sort({ createdAt: -1 });
    res.json(audits);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== GET ALL USERS (Admin) =====
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== UPDATE CONTACT STATUS =====
app.put('/api/admin/contact/:id', async (req, res) => {
  try {
    const { status } = req.body;
    await Contact.findByIdAndUpdate(req.params.id, { status });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== DELETE CONTACT =====
app.delete('/api/admin/contact/:id', async (req, res) => {
  try {
    await Contact.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// =============================================
// ===== BLOG API =====
// =============================================
app.get('/api/blogs', async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ createdAt: -1 });
    res.json(blogs);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/blog/:slug', async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).json({ error: 'Blog not found' });
    
    blog.views += 1;
    await blog.save();
    res.json(blog);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/blog', [
  body('title').notEmpty(),
  body('content').notEmpty()
], async (req, res) => {
  try {
    const { title, content, excerpt, image, tags } = req.body;
    const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    
    const blog = new Blog({ title, slug, content, excerpt, image, tags });
    await blog.save();
    res.status(201).json({ success: true, blog });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// =============================================
// ===== ADMIN AUTH (Previous Admin Setup) =====
// =============================================
app.post('/api/admin/setup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existing = await User.findOne({ $or: [{ username }, { email }] });
    if (existing) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ 
      name: username, 
      username, 
      email, 
      phone: '0000000000',
      password: hashedPassword, 
      role: 'admin' 
    });
    await user.save();
    
    res.json({ success: true, message: 'Admin created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user._id, username: user.username, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: { 
        id: user._id, 
        username: user.username, 
        name: user.name,
        email: user.email, 
        phone: user.phone,
        role: user.role 
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// =============================================
// ===== ANALYTICS API =====
// =============================================
app.get('/api/analytics', async (req, res) => {
  try {
    const totalContacts = await Contact.countDocuments();
    const totalSubscribers = await Subscriber.countDocuments({ isActive: true });
    const totalAudits = await Audit.countDocuments();
    const totalBlogs = await Blog.countDocuments();
    const totalUsers = await User.countDocuments();
    
    res.json({
      totalContacts,
      totalSubscribers,
      totalAudits,
      totalBlogs,
      totalUsers
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// =============================================
// ===== HEALTH CHECK =====
// =============================================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Growthify API is running',
    timestamp: new Date().toISOString()
  });
});

// =============================================
// ===== ERROR HANDLER =====
// =============================================
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({ 
    success: false,
    error: 'Something went wrong! Please try again later.' 
  });
});

// =============================================
// ===== START SERVER =====
// =============================================
app.listen(PORT, () => {
  console.log(`\n🚀 Growthify Server Running`);
  console.log(`📍 http://localhost:${PORT}`);
  console.log(`📧 API: http://localhost:${PORT}/api/contact`);
  console.log(`📰 API: http://localhost:${PORT}/api/newsletter`);
  console.log(`🔍 API: http://localhost:${PORT}/api/audit`);
  console.log(`📊 API: http://localhost:${PORT}/api/analytics`);
  console.log(`🔐 Signup: http://localhost:${PORT}/api/signup`);
  console.log(`🔐 Login: http://localhost:${PORT}/api/login`);
  console.log(`🔐 Update: http://localhost:${PORT}/api/update`);
  console.log(`🔗 Admin Panel: http://localhost:${PORT}/admin\n`);
});
