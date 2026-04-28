const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const path = require('path');
const sqlite3 = require('sqlite3');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
    secret: 'kabianga-tracker-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 4 }
  })
);

let db;

async function createDatabase() {
  db = new sqlite3.Database(path.join(__dirname, 'kabianga.db'), (err) => {
    if (err) {
      throw err;
    }
  });

  db.run = promisify(db.run.bind(db));
  db.get = promisify(db.get.bind(db));
  db.all = promisify(db.all.bind(db));
  db.exec = promisify(db.exec.bind(db));

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      location TEXT NOT NULL,
      type TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Other',
      status TEXT NOT NULL,
      reported_by INTEGER NOT NULL,
      claimed_by INTEGER,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(reported_by) REFERENCES users(id),
      FOREIGN KEY(claimed_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      requested_at TEXT NOT NULL,
      processed_at TEXT,
      FOREIGN KEY(item_id) REFERENCES items(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  const columns = await db.all("PRAGMA table_info(items)");
  if (!columns.some(column => column.name === 'category')) {
    await db.run("ALTER TABLE items ADD COLUMN category TEXT NOT NULL DEFAULT 'Other'");
  }

  const existingUsers = await db.get('SELECT COUNT(*) AS count FROM users');
  if (!existingUsers || existingUsers.count === 0) {
    const adminPassword = await bcrypt.hash('admin123', 10);
    const securityPassword = await bcrypt.hash('security123', 10);
    const studentPassword = await bcrypt.hash('student123', 10);

    await db.run(
      'INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
      ['Admin Officer', 'admin@kabianga.edu', 'admin', adminPassword, 'admin']
    );
    await db.run(
      'INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
      ['Security Office', 'security@kabianga.edu', 'security', securityPassword, 'security']
    );
    await db.run(
      'INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
      ['Student User', 'student@kabianga.edu', 'student', studentPassword, 'user']
    );
  }
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).render('forbidden', { title: 'Forbidden' });
    }
    next();
  };
}

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('login', { title: 'Kabianga Lost & Track Login', error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);

  if (!user) {
    return res.render('login', { title: 'Kabianga Lost & Track Login', error: 'Invalid credentials.' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.render('login', { title: 'Kabianga Lost & Track Login', error: 'Invalid credentials.' });
  }

  req.session.user = {
    id: user.id,
    name: user.name,
    username: user.username,
    role: user.role
  };

  res.redirect('/dashboard');
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('register', { title: 'Student Registration', error: null });
});

app.post('/register', async (req, res) => {
  const { name, email, username, password } = req.body;
  if (!name || !email || !username || !password) {
    return res.render('register', { title: 'Student Registration', error: 'All fields are required.' });
  }

  const existing = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
  if (existing) {
    return res.render('register', { title: 'Student Registration', error: 'Email or username already exists.' });
  }

  const hashed = await bcrypt.hash(password, 10);
  await db.run(
    'INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)',
    [name, email, username, hashed, 'user']
  );

  res.render('login', { title: 'Kabianga Lost & Track Login', error: 'Registration successful. Please log in.' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/dashboard', requireLogin, (req, res) => {
  const role = req.session.user.role;
  if (role === 'admin') return res.redirect('/admin');
  if (role === 'security') return res.redirect('/security');
  return res.redirect('/user');
});

app.get('/report', requireLogin, (req, res) => {
  if (req.session.user.role !== 'user') return res.redirect('/dashboard');
  res.redirect('/user#report');
});

app.get('/browse', requireLogin, (req, res) => {
  if (req.session.user.role !== 'user') return res.redirect('/dashboard');
  res.redirect('/user#browse');
});

app.get('/admin', requireLogin, requireRole('admin'), async (req, res) => {
  const userCount = await db.get('SELECT COUNT(*) AS count FROM users');
  const itemCount = await db.get('SELECT COUNT(*) AS count FROM items');
  const foundCount = await db.get("SELECT COUNT(*) AS count FROM items WHERE type='found'");
  const lostCount = await db.get("SELECT COUNT(*) AS count FROM items WHERE type='lost'");
  const pendingClaims = await db.get("SELECT COUNT(*) AS count FROM claims WHERE status = 'pending'");
  const items = await db.all(
    `SELECT items.*, users.name AS reporter FROM items JOIN users ON items.reported_by = users.id ORDER BY items.created_at DESC LIMIT 50`
  );
  const claims = await db.all(
    `SELECT claims.*, items.title AS item_title, users.name AS claimant FROM claims JOIN items ON claims.item_id = items.id JOIN users ON claims.user_id = users.id ORDER BY claims.requested_at DESC LIMIT 20`
  );

  res.render('admin', {
    title: 'Admin Dashboard',
    metrics: {
      users: userCount.count,
      items: itemCount.count,
      found: foundCount.count,
      lost: lostCount.count,
      claims: pendingClaims.count
    },
    items,
    claims
  });
});

app.get('/security', requireLogin, requireRole('security'), async (req, res) => {
  const items = await db.all(
    `SELECT items.*, users.name AS reporter FROM items JOIN users ON items.reported_by = users.id ORDER BY items.updated_at DESC`);
  const claims = await db.all(
    `SELECT claims.*, items.title AS item_title, users.name AS claimant FROM claims JOIN items ON claims.item_id = items.id JOIN users ON claims.user_id = users.id WHERE claims.status = 'pending' ORDER BY claims.requested_at DESC`
  );
  res.render('security', { title: 'Security Office', items, claims });
});

app.get('/user', requireLogin, requireRole('user'), async (req, res) => {
  const user = req.session.user;
  const myItems = await db.all('SELECT * FROM items WHERE reported_by = ? ORDER BY updated_at DESC', [user.id]);
  const availableClaims = await db.all(
    `SELECT items.*, users.name AS reporter FROM items JOIN users ON items.reported_by = users.id WHERE items.type = 'found' AND items.status = 'ready_for_claim' AND items.reported_by != ? ORDER BY items.updated_at DESC`,
    [user.id]
  );
  const myClaims = await db.all(
    `SELECT claims.*, items.title AS item_title, items.status AS item_status FROM claims JOIN items ON claims.item_id = items.id WHERE claims.user_id = ? ORDER BY claims.requested_at DESC`,
    [user.id]
  );
  res.render('user', { title: 'Student Portal', userItems: myItems, claimables: availableClaims, myClaims });
});

app.post('/report-item', requireLogin, requireRole('user'), async (req, res) => {
  const { title, description, location, type, category } = req.body;
  if (!title || !description || !location || !type || !category) {
    return res.redirect('/user');
  }

  const now = new Date().toISOString();
  const status = type === 'found' ? 'with_security' : 'reported_lost';
  await db.run(
    `INSERT INTO items (title, description, location, type, category, status, reported_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [title, description, location, type, category, status, req.session.user.id, now, now]
  );
  res.redirect('/user');
});

app.post('/items/:id/prepare-claim', requireLogin, requireRole('security'), async (req, res) => {
  const itemId = req.params.id;
  await db.run(`UPDATE items SET status = 'ready_for_claim', updated_at = ? WHERE id = ? AND type = 'found'`, [new Date().toISOString(), itemId]);
  res.redirect('/security');
});

app.post('/items/:id/mark-claimed', requireLogin, requireRole('security'), async (req, res) => {
  const itemId = req.params.id;
  const item = await db.get('SELECT * FROM items WHERE id = ?', [itemId]);
  if (item && item.type === 'lost') {
    await db.run(`UPDATE items SET status = 'claimed', claimed_by = reported_by, updated_at = ? WHERE id = ?`, [new Date().toISOString(), itemId]);
  }
  res.redirect('/security');
});

app.post('/items/:id/request-claim', requireLogin, requireRole('user'), async (req, res) => {
  const itemId = req.params.id;
  const existing = await db.get('SELECT * FROM claims WHERE item_id = ? AND user_id = ? AND status = ?', [itemId, req.session.user.id, 'pending']);
  if (!existing) {
    await db.run(
      `INSERT INTO claims (item_id, user_id, status, requested_at) VALUES (?, ?, 'pending', ?)`,
      [itemId, req.session.user.id, new Date().toISOString()]
    );
  }
  res.redirect('/user');
});

app.post('/claims/:id/approve', requireLogin, requireRole('security'), async (req, res) => {
  const claimId = req.params.id;
  const claim = await db.get('SELECT * FROM claims WHERE id = ?', [claimId]);
  if (claim) {
    await db.run('UPDATE claims SET status = ?, processed_at = ? WHERE id = ?', ['approved', new Date().toISOString(), claimId]);
    await db.run('UPDATE items SET status = ?, claimed_by = ?, updated_at = ? WHERE id = ?', ['claimed', claim.user_id, new Date().toISOString(), claim.item_id]);
  }
  res.redirect('/security');
});

app.post('/claims/:id/reject', requireLogin, requireRole('security'), async (req, res) => {
  const claimId = req.params.id;
  await db.run('UPDATE claims SET status = ?, processed_at = ? WHERE id = ?', ['rejected', new Date().toISOString(), claimId]);
  res.redirect('/security');
});

app.get('/reports', requireLogin, async (req, res) => {
  const role = req.session.user.role;
  if (role === 'user') {
    return res.redirect('/dashboard');
  }
  const items = await db.all(
    `SELECT items.*, users.name AS reporter FROM items JOIN users ON items.reported_by = users.id ORDER BY items.created_at DESC`
  );
  const claims = await db.all(
    `SELECT claims.*, items.title AS item_title, users.name AS claimant FROM claims JOIN items ON claims.item_id = items.id JOIN users ON claims.user_id = users.id ORDER BY claims.requested_at DESC`
  );
  res.render('reports', { title: 'System Reports', items, claims, role });
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'Page Not Found' });
});

createDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Kabianga Lost & Track System running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to start application', err);
});
