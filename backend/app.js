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

// Use your deployed frontend URL here
const FRONTEND_URL = 'https://notes-downloader.vercel.app';

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
}));

app.use(express.json());

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const adminEmails = (process.env.ADMINS || '').split(',').map(email => email.trim());

function verifyToken(token) {
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
}

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
    const issuer = await Issuer.discover(process.env.DISCOVERY_URL);

    const client = new issuer.Client({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      redirect_uris: [process.env.REDIRECT_URI],
      response_types: ['code'],
    });

    passport.use('oidc', new Strategy({ client }, (tokenSet, userinfo, done) => done(null, userinfo)));

    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((obj, done) => done(null, obj));

    app.get('/login', passport.authenticate('oidc'));

    app.get('/callback', passport.authenticate('oidc', {
      failureRedirect: '/login',
    }), (req, res) => {
      const userEmail = req.user.email;
      if (adminEmails.includes(userEmail)) {
        res.redirect(`${FRONTEND_URL}/admin.html`);
      } else {
        res.redirect(`${FRONTEND_URL}/user.html`);
      }
    });

    app.get('/', (req, res) => {
      if (!req.user) return res.redirect('/login');
      res.send(`<h1>Hello, ${req.user.name || req.user.email}</h1><p><a href="/logout">Logout</a></p>`);
    });

    app.get('/logout', (req, res) => {
      req.logout(() => {
        res.redirect('/');
      });
    });

    app.get('/notes', authMiddleware, (req, res) => {
      fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
        if (err) return res.status(500).json({ message: 'Error reading files' });
        res.json(files);
      });
    });

    app.post('/upload', authMiddleware, upload.single('file'), (req, res) => {
      if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
      res.json({ message: 'File uploaded successfully', filename: req.file.filename });
    });

    app.get('/download/:filename', authMiddleware, (req, res) => {
      const filePath = path.join(__dirname, 'uploads', req.params.filename);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'File not found' });
      }
      res.download(filePath);
    });

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`✅ Backend running on port ${PORT}`);
    });

  } catch (err) {
    console.error('Error setting up OpenID client:', err);
  }
})();
