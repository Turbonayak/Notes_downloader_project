require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Issuer, Strategy } = require('openid-client');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// CORS setup - change origin to your frontend URL
app.use(cors({
  origin: 'http://localhost:5500',  // your frontend server address
  credentials: true,
}));

app.use(express.json());

// Session setup for passport
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// Admin emails list from .env
const adminEmails = (process.env.ADMINS || '').split(',').map(email => email.trim());

// Decode JWT token (simple decode for demo - verify properly in production)
function verifyToken(token) {
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
}

// Middleware to protect routes and check if user is admin by email
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Malformed token' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ message: 'Invalid token' });

  if (!payload.email || !adminEmails.includes(payload.email)) {
    return res.status(403).json({ message: 'Access denied: Admins only' });
  }

  req.user = payload;
  next();
}

(async () => {
  try {
    // Discover the OpenID provider from IBM App ID
    const issuer = await Issuer.discover(process.env.DISCOVERY_URL);

    // Create a client
    const client = new issuer.Client({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      redirect_uris: [process.env.REDIRECT_URI],
      response_types: ['code'],
    });

    // Configure passport strategy for OIDC
    passport.use('oidc', new Strategy({ client }, (tokenSet, userinfo, done) => {
      return done(null, userinfo);
    }));

    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((obj, done) => done(null, obj));

    // Routes

    // Login route - redirect to IBM App ID login
    app.get('/login', passport.authenticate('oidc'));

    // Callback route after login
// Callback route after login with custom redirect based on role
app.get('/callback', passport.authenticate('oidc', {
  failureRedirect: '/login',
}), (req, res) => {
  const userEmail = req.user.email;
  if (adminEmails.includes(userEmail)) {
    // Redirect to admin panel (you must have admin.html in your frontend folder)
    res.redirect('http://localhost:5500/admin.html');
  } else {
    // Redirect to user dashboard
    res.redirect('http://localhost:5500/user.html');
  }
});


    // Home page (protected)
    app.get('/', (req, res) => {
      if (!req.user) return res.redirect('/login');
      res.send(`<h1>Hello, ${req.user.name || req.user.email}</h1><p><a href="/logout">Logout</a></p>`);
    });

    // Logout route
    app.get('/logout', (req, res) => {
      req.logout(() => {
        res.redirect('/');
      });
    });

    // Get list of notes (admin only)
    app.get('/notes', authMiddleware, (req, res) => {
      fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
        if (err) return res.status(500).json({ message: 'Error reading files' });
        res.json(files);
      });
    });

    // Upload note (admin only)
    app.post('/upload', authMiddleware, upload.single('file'), (req, res) => {
      if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
      res.json({ message: 'File uploaded successfully', filename: req.file.filename });
    });

    // Download note (admin only)
    app.get('/download/:filename', authMiddleware, (req, res) => {
      const filePath = path.join(__dirname, 'uploads', req.params.filename);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'File not found' });
      }
      res.download(filePath);
    });

    // Start the server
    app.listen(3000, () => {
      console.log('✅ Backend running on http://localhost:3000');
    });

  } catch (err) {
    console.error('Error setting up OpenID client:', err);
  }
})();
