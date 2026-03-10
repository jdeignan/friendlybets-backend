const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || "friendlybets-secret-change-in-prod";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "friendlybets.db");

// --- DB SETUP ---
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    avatar_color TEXT DEFAULT '#00e676',
    balance INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (friend_id) REFERENCES users(id),
    UNIQUE(user_id, friend_id)
  );

  CREATE TABLE IF NOT EXISTS bets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'admin',
    is_public INTEGER DEFAULT 0,
    creator_id INTEGER NOT NULL,
    admin_id INTEGER,
    amount INTEGER NOT NULL,
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'active',
    result TEXT,
    updates TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS bet_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bet_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    pick TEXT,
    status TEXT DEFAULT 'pending',
    joined_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (bet_id) REFERENCES bets(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(bet_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS bet_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bet_id INTEGER NOT NULL,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (bet_id) REFERENCES bets(id),
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
  );
`);

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// --- AUTH ROUTES ---

// POST /api/signup
app.post("/api/signup", (req, res) => {
  const { username, email, password, avatarColor } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });
  if (username.length < 3) return res.status(400).json({ error: "Username too short" });
  if (password.length < 6) return res.status(400).json({ error: "Password too short" });

  const existing = db.prepare("SELECT id FROM users WHERE username = ? OR email = ?").get(username, email);
  if (existing) return res.status(409).json({ error: "Username or email already taken" });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    "INSERT INTO users (username, email, password_hash, avatar_color) VALUES (?, ?, ?, ?)"
  ).run(username.toLowerCase(), email.toLowerCase(), hash, avatarColor || "#00e676");

  const user = db.prepare("SELECT id, username, email, avatar_color, balance FROM users WHERE id = ?").get(result.lastInsertRowid);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user });
});

// POST /api/login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid username or password" });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid username or password" });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, avatar_color: user.avatar_color, balance: user.balance } });
});

// GET /api/me
app.get("/api/me", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id, username, email, avatar_color, balance, created_at FROM users WHERE id = ?").get(req.user.id);
  res.json(user);
});

// --- USER SEARCH ---
app.get("/api/users/search", authMiddleware, (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  const users = db.prepare(
    "SELECT id, username, avatar_color FROM users WHERE username LIKE ? AND id != ? LIMIT 10"
  ).all(`%${q}%`, req.user.id);
  res.json(users);
});

// --- FRIENDS ---
app.post("/api/friends/request", authMiddleware, (req, res) => {
  const { friendUsername } = req.body;
  const friend = db.prepare("SELECT id FROM users WHERE username = ?").get(friendUsername?.toLowerCase());
  if (!friend) return res.status(404).json({ error: "User not found" });
  if (friend.id === req.user.id) return res.status(400).json({ error: "Can't friend yourself" });

  try {
    db.prepare("INSERT INTO friendships (user_id, friend_id, status) VALUES (?, ?, 'pending')").run(req.user.id, friend.id);
    res.json({ success: true });
  } catch {
    res.status(409).json({ error: "Friend request already sent" });
  }
});

app.post("/api/friends/accept", authMiddleware, (req, res) => {
  const { friendshipId } = req.body;
  db.prepare("UPDATE friendships SET status = 'accepted' WHERE id = ? AND friend_id = ?").run(friendshipId, req.user.id);
  res.json({ success: true });
});

app.get("/api/friends", authMiddleware, (req, res) => {
  const friends = db.prepare(`
    SELECT u.id, u.username, u.avatar_color, f.status, f.id as friendship_id
    FROM friendships f
    JOIN users u ON (u.id = CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END)
    WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'accepted'
  `).all(req.user.id, req.user.id, req.user.id);
  res.json(friends);
});

// --- BETS ---
app.get("/api/bets", authMiddleware, (req, res) => {
  const bets = db.prepare(`
    SELECT b.*, u.username as creator_name,
      (SELECT COUNT(*) FROM bet_participants WHERE bet_id = b.id AND status = 'accepted') as participant_count,
      bp.pick as my_pick, bp.status as my_status
    FROM bets b
    JOIN users u ON b.creator_id = u.id
    LEFT JOIN bet_participants bp ON bp.bet_id = b.id AND bp.user_id = ?
    WHERE bp.user_id IS NOT NULL OR b.creator_id = ?
    ORDER BY b.created_at DESC
  `).all(req.user.id, req.user.id);

  // Attach participant usernames to each bet
  const result = bets.map(bet => {
    const participants = db.prepare(`
      SELECT u.username FROM bet_participants bp
      JOIN users u ON bp.user_id = u.id
      WHERE bp.bet_id = ? AND bp.status = 'accepted'
    `).all(bet.id).map(r => r.username);
    return { ...bet, participants_list: participants, my_username: req.user.username };
  });
  res.json(result);
});

app.post("/api/bets", authMiddleware, (req, res) => {
  const { title, description, category, amount, endTime, isPublic } = req.body;
  if (!title || !amount) return res.status(400).json({ error: "Missing fields" });

  const result = db.prepare(
    "INSERT INTO bets (title, description, category, amount, end_time, is_public, creator_id, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(title, description || "", category || "admin", amount, endTime || null, isPublic ? 1 : 0, req.user.id, req.user.id);

  // Auto-join creator
  db.prepare("INSERT INTO bet_participants (bet_id, user_id, status) VALUES (?, ?, 'accepted')").run(result.lastInsertRowid, req.user.id);

  const bet = db.prepare("SELECT * FROM bets WHERE id = ?").get(result.lastInsertRowid);
  res.json(bet);
});

app.post("/api/bets/:id/invite", authMiddleware, (req, res) => {
  const { userIds } = req.body;
  const betId = req.params.id;
  for (const uid of userIds) {
    try {
      db.prepare("INSERT INTO bet_invites (bet_id, from_user_id, to_user_id) VALUES (?, ?, ?)").run(betId, req.user.id, uid);
    } catch {}
  }
  res.json({ success: true });
});

app.post("/api/bets/:id/resolve", authMiddleware, (req, res) => {
  const { result, winnerId } = req.body;
  db.prepare("UPDATE bets SET status = 'settled', result = ? WHERE id = ? AND admin_id = ?").run(result, req.params.id, req.user.id);
  res.json({ success: true });
});

// --- INVITES ---
app.get("/api/invites", authMiddleware, (req, res) => {
  const invites = db.prepare(`
    SELECT bi.*, b.title, b.amount, b.end_time, u.username as from_username,
      (SELECT COUNT(*) FROM bet_participants WHERE bet_id = b.id) as participant_count
    FROM bet_invites bi
    JOIN bets b ON bi.bet_id = b.id
    JOIN users u ON bi.from_user_id = u.id
    WHERE bi.to_user_id = ? AND bi.status = 'pending'
  `).all(req.user.id);
  res.json(invites);
});

app.post("/api/invites/:id/accept", authMiddleware, (req, res) => {
  const invite = db.prepare("SELECT * FROM bet_invites WHERE id = ? AND to_user_id = ?").get(req.params.id, req.user.id);
  if (!invite) return res.status(404).json({ error: "Invite not found" });
  db.prepare("UPDATE bet_invites SET status = 'accepted' WHERE id = ?").run(invite.id);
  try {
    db.prepare("INSERT INTO bet_participants (bet_id, user_id, status) VALUES (?, ?, 'accepted')").run(invite.bet_id, req.user.id);
  } catch {}
  res.json({ success: true });
});

app.post("/api/invites/:id/decline", authMiddleware, (req, res) => {
  db.prepare("UPDATE bet_invites SET status = 'declined' WHERE id = ? AND to_user_id = ?").run(req.params.id, req.user.id);
  res.json({ success: true });
});

// --- DELETE BET ---
app.delete("/api/bets/:id", authMiddleware, (req, res) => {
  const bet = db.prepare("SELECT * FROM bets WHERE id = ? AND creator_id = ?").get(req.params.id, req.user.id);
  if (!bet) return res.status(404).json({ error: "Bet not found or not authorized" });
  db.prepare("DELETE FROM bet_participants WHERE bet_id = ?").run(req.params.id);
  db.prepare("DELETE FROM bet_invites WHERE bet_id = ?").run(req.params.id);
  db.prepare("DELETE FROM bets WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// --- POST UPDATE ON BET ---
app.post("/api/bets/:id/update", authMiddleware, (req, res) => {
  const { update } = req.body;
  if (!update) return res.status(400).json({ error: "Update text required" });
  const bet = db.prepare("SELECT * FROM bets WHERE id = ?").get(req.params.id);
  if (!bet) return res.status(404).json({ error: "Bet not found" });
  const updates = JSON.parse(bet.updates || "[]");
  updates.push({ text: update, author: req.user.username, time: new Date().toISOString() });
  db.prepare("UPDATE bets SET updates = ? WHERE id = ?").run(JSON.stringify(updates), req.params.id);
  res.json({ success: true, updates });
});

// --- HEALTH CHECK ---
app.get("/api/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`FriendlyBets backend running on port ${PORT}`));
