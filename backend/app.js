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

const uploadsDir = path.join(__dirname, 'uploads');
// Ensure uploads directory exists
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const upload = multer({ dest: uploadsDir });

app.use(cors({
  origin: 'http://localhost:5500',
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: 'lax' },
}));

app.use(passport.initialize());
app.use(passport.session());

const adminEmails = (process.env.ADMINS || '').split(',').map(e => e.trim());

const metadataFile = path.join(uploadsDir, 'metadata.json');

function readMetadata() {
  if (!fs.existsSync(metadataFile)) return {};
  try {
    const data = fs.readFileSync(metadataFile, 'utf-8');
    return JSON.parse(data || '{}');
  } catch (e) {
    console.error('Failed to read metadata:', e);
    return {};
  }
}

function saveMetadata(metadata) {
  fs.writeFileSync(metadataFile, JSON.stringify(metadata, null, 2));
}

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET || 'your-secret');
  } catch (e) {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);

  if (!token || !payload) return res.status(403).json({ message: 'Invalid or expired token' });

  req.user = payload;
  next();
}

function adminMiddleware(req, res, next) {
  if (!adminEmails.includes(req.user.email)) {
    return res.status(403).json({ message: 'Admins only' });
  }
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

    passport.use('oidc', new Strategy({ client }, (tokenSet, userinfo, done) => {
      return done(null, userinfo);
    }));

    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((obj, done) => done(null, obj));

    app.get('/login', passport.authenticate('oidc'));

    app.get('/callback', passport.authenticate('oidc', {
      failureRedirect: '/login',
    }), (req, res) => {
      const email = req.user.email;
      const token = jwt.sign({ email }, process.env.JWT_SECRET || 'your-secret', { expiresIn: '1h' });

      const redirectTo = adminEmails.includes(email)
        ? ` https://notes-downloader.vercel.app/frontend/admin.html#token=${token}`
        : ` https://notes-downloader.vercel.app/frontend/user.html#token=${token}`;

      return res.redirect(redirectTo);
    });

    app.get('/', (req, res) => {
      res.send(`<h1>Welcome, ${req.user?.email || 'Guest'}</h1>`);
    });

    app.get('/logout', (req, res) => {
      req.logout(err => {
        if (err) return res.status(500).json({ message: 'Logout error' });
        req.session.destroy(() => res.redirect('/'));
      });
    });

    // Upload file (admin only) with optional description in form field
    app.post('/upload', authMiddleware, adminMiddleware, upload.single('file'), (req, res) => {
      if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

      const description = req.body.description || '';
      const metadata = readMetadata();

      metadata[req.file.filename] = {
        originalName: req.file.originalname,
        description
      };

      saveMetadata(metadata);

      res.json({ message: 'File uploaded', filename: req.file.filename });
    });

    // List files (any authenticated user) with metadata
    app.get('/notes', authMiddleware, (req, res) => {
      fs.readdir(uploadsDir, (err, files) => {
        if (err) {
          console.error('Failed to read uploads directory:', err);
          return res.status(500).json({ message: 'Failed to read files' });
        }

        const metadata = readMetadata();
        const filteredFiles = files.filter(f => f !== 'metadata.json');

        const notes = filteredFiles.map(filename => ({
          storedFilename: filename,
          originalName: metadata[filename]?.originalName || filename,
          description: metadata[filename]?.description || ''
        }));

        res.json(notes);
      });
    });

    // Download file (any authenticated user) with original filename
    app.get('/download/:filename', authMiddleware, (req, res) => {
      const filename = req.params.filename;
      const filePath = path.join(uploadsDir, filename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'File not found' });
      }

      const metadata = readMetadata();
      const originalName = metadata[filename]?.originalName || filename;

      res.download(filePath, originalName, (err) => {
        if (err) {
          console.error('Download error:', err);
          if (!res.headersSent) {
            res.status(500).json({ message: 'Error downloading file' });
          }
        }
      });
    });

    // Delete file (admin only) and remove metadata
    app.delete('/delete/:filename', authMiddleware, adminMiddleware, (req, res) => {
      const filename = req.params.filename;
      const filePath = path.join(uploadsDir, filename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: 'File not found' });
      }

      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Error deleting file:', err);
          return res.status(500).json({ message: 'Error deleting file' });
        }

        // Remove metadata entry
        const metadata = readMetadata();
        if (metadata[filename]) {
          delete metadata[filename];
          saveMetadata(metadata);
        }

        res.json({ message: 'File deleted successfully' });
      });
    });

    app.listen(3000, () => {
      console.log('✅ Backend running at https://notes-downloader.onrender.com');
    });

  } catch (err) {
    console.error('❌ App ID setup failed:', err);
  }
})();
