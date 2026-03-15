const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || "friendlybets-secret-change-in-prod";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_color TEXT DEFAULT '#00e676',
      animal_id TEXT DEFAULT 'bear',
      balance INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS friendships (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      friend_id INTEGER NOT NULL REFERENCES users(id),
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, friend_id)
    );
    CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      category TEXT DEFAULT 'admin',
      is_public BOOLEAN DEFAULT FALSE,
      creator_id INTEGER NOT NULL REFERENCES users(id),
      admin_id INTEGER REFERENCES users(id),
      amount INTEGER NOT NULL,
      start_time TIMESTAMPTZ,
      end_time TIMESTAMPTZ,
      status TEXT DEFAULT 'active',
      result TEXT,
      updates JSONB DEFAULT '[]',
      odds_home TEXT,
      odds_away TEXT,
      home_team TEXT,
      away_team TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS bet_participants (
      id SERIAL PRIMARY KEY,
      bet_id INTEGER NOT NULL REFERENCES bets(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      pick TEXT,
      status TEXT DEFAULT 'pending',
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(bet_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS bet_invites (
      id SERIAL PRIMARY KEY,
      bet_id INTEGER NOT NULL REFERENCES bets(id),
      from_user_id INTEGER NOT NULL REFERENCES users(id),
      to_user_id INTEGER NOT NULL REFERENCES users(id),
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // Safely add new columns if they don't exist
  const alterations = [
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS odds_home TEXT",
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS odds_away TEXT",
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS home_team TEXT",
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS away_team TEXT",
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS bet_type TEXT",
    "ALTER TABLE bets ADD COLUMN IF NOT EXISTS guess_answer TEXT",
    "ALTER TABLE bet_participants ADD COLUMN IF NOT EXISTS pick TEXT",
    "ALTER TABLE bet_participants ADD COLUMN IF NOT EXISTS guess TEXT",
    "ALTER TABLE bet_participants ADD COLUMN IF NOT EXISTS start_value NUMERIC",
    "ALTER TABLE bet_participants ADD COLUMN IF NOT EXISTS end_value NUMERIC",
  ];
  for (const sql of alterations) {
    try { await pool.query(sql); } catch(e) { console.log("Skipping:", sql); }
  }
  console.log("Database initialized");
}
initDB().catch(console.error);

app.use(cors());
app.use(express.json());

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.replace("Bearer ", "");
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

app.post("/api/signup", async (req, res) => {
  const { username, email, password, avatarColor, animalId } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });
  if (username.length < 3) return res.status(400).json({ error: "Username too short" });
  if (password.length < 6) return res.status(400).json({ error: "Password too short" });
  try {
    const existing = await pool.query("SELECT id FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($2)", [username, email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "Username or email already taken" });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username,email,password_hash,avatar_color,animal_id) VALUES (LOWER($1),LOWER($2),$3,$4,$5) RETURNING id,username,email,avatar_color,animal_id,balance",
      [username, email, hash, avatarColor||"#00e676", animalId||"bear"]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE LOWER(username)=LOWER($1)", [username]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid username or password" });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid username or password" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, avatar_color: user.avatar_color, animal_id: user.animal_id, balance: user.balance } });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,username,email,avatar_color,animal_id,balance,created_at FROM users WHERE id=$1", [req.user.id]);
    res.json(result.rows[0]);
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/users/search", authMiddleware, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json([]);
  try {
    const result = await pool.query("SELECT id,username,avatar_color,animal_id FROM users WHERE LOWER(username) LIKE LOWER($1) AND id!=$2 LIMIT 10", [`%${q}%`, req.user.id]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/friends/request", authMiddleware, async (req, res) => {
  const { friendUsername } = req.body;
  try {
    const friend = await pool.query("SELECT id FROM users WHERE LOWER(username)=LOWER($1)", [friendUsername]);
    if (!friend.rows[0]) return res.status(404).json({ error: "User not found" });
    if (friend.rows[0].id === req.user.id) return res.status(400).json({ error: "Can't friend yourself" });
    await pool.query("INSERT INTO friendships (user_id,friend_id,status) VALUES ($1,$2,'pending') ON CONFLICT DO NOTHING", [req.user.id, friend.rows[0].id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/friends", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id,u.username,u.avatar_color,u.animal_id,f.status,f.id as friendship_id
      FROM friendships f
      JOIN users u ON (u.id = CASE WHEN f.user_id=$1 THEN f.friend_id ELSE f.user_id END)
      WHERE (f.user_id=$1 OR f.friend_id=$1) AND f.status='accepted'
    `, [req.user.id]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/bets", authMiddleware, async (req, res) => {
  try {
    const bets = await pool.query(`
      SELECT b.*, u.username as creator_name,
        (SELECT COUNT(*) FROM bet_participants WHERE bet_id=b.id AND status='accepted') as participant_count,
        bp.pick as my_pick, bp.status as my_status
      FROM bets b
      JOIN users u ON b.creator_id=u.id
      LEFT JOIN bet_participants bp ON bp.bet_id=b.id AND bp.user_id=$1
      WHERE bp.user_id IS NOT NULL OR b.creator_id=$1
      ORDER BY b.created_at DESC
    `, [req.user.id]);
    const result = await Promise.all(bets.rows.map(async (bet) => {
      const participants = await pool.query(`
        SELECT u.username FROM bet_participants bp
        JOIN users u ON bp.user_id=u.id
        WHERE bp.bet_id=$1 AND bp.status='accepted'
      `, [bet.id]);
      return { ...bet, participants_list: participants.rows.map(r => r.username), my_username: req.user.username };
    }));
    res.json(result);
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bets", authMiddleware, async (req, res) => {
  const { title, description, category, amount, endTime, isPublic, myPick, oddsHome, oddsAway, homeTeam, awayTeam, betType, myGuess, myStartValue } = req.body;
  if (!title || !amount) return res.status(400).json({ error: "Missing fields" });
  try {
    const result = await pool.query(
      "INSERT INTO bets (title,description,category,amount,end_time,is_public,creator_id,admin_id,odds_home,odds_away,home_team,away_team) VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,$11) RETURNING *",
      [title, description||"", category||"admin", amount, endTime||null, isPublic||false, req.user.id, oddsHome||null, oddsAway||null, homeTeam||null, awayTeam||null]
    );
    const bet = result.rows[0];
    await pool.query("INSERT INTO bet_participants (bet_id,user_id,pick,guess,start_value,status) VALUES ($1,$2,$3,$4,$5,'accepted') ON CONFLICT DO NOTHING", [bet.id, req.user.id, myPick||null, myGuess||null, myStartValue||null]);
    res.json(bet);
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bets/:id/invite", authMiddleware, async (req, res) => {
  const { userIds } = req.body;
  try {
    for (const uid of userIds) {
      await pool.query("INSERT INTO bet_invites (bet_id,from_user_id,to_user_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING", [req.params.id, req.user.id, uid]);
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bets/:id/resolve", authMiddleware, async (req, res) => {
  const { result } = req.body;
  try {
    await pool.query("UPDATE bets SET status='settled', result=$1 WHERE id=$2 AND admin_id=$3", [result, req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/invites", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT bi.*, b.title, b.amount, b.end_time, u.username as from_username,
        (SELECT COUNT(*) FROM bet_participants WHERE bet_id=b.id) as participant_count
      FROM bet_invites bi
      JOIN bets b ON bi.bet_id=b.id
      JOIN users u ON bi.from_user_id=u.id
      WHERE bi.to_user_id=$1 AND bi.status='pending'
    `, [req.user.id]);
    res.json(result.rows);
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/invites/:id/accept", authMiddleware, async (req, res) => {
  try {
    const invite = await pool.query("SELECT * FROM bet_invites WHERE id=$1 AND to_user_id=$2", [req.params.id, req.user.id]);
    if (!invite.rows[0]) return res.status(404).json({ error: "Invite not found" });
    await pool.query("UPDATE bet_invites SET status='accepted' WHERE id=$1", [invite.rows[0].id]);
    await pool.query("INSERT INTO bet_participants (bet_id,user_id,status) VALUES ($1,$2,'accepted') ON CONFLICT DO NOTHING", [invite.rows[0].bet_id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/invites/:id/decline", authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE bet_invites SET status='declined' WHERE id=$1 AND to_user_id=$2", [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/bets/:id", authMiddleware, async (req, res) => {
  try {
    const bet = await pool.query("SELECT * FROM bets WHERE id=$1 AND creator_id=$2", [req.params.id, req.user.id]);
    if (!bet.rows[0]) return res.status(404).json({ error: "Bet not found or not authorized" });
    await pool.query("DELETE FROM bet_participants WHERE bet_id=$1", [req.params.id]);
    await pool.query("DELETE FROM bet_invites WHERE bet_id=$1", [req.params.id]);
    await pool.query("DELETE FROM bets WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/bets/:id/update", authMiddleware, async (req, res) => {
  const { update } = req.body;
  if (!update) return res.status(400).json({ error: "Update text required" });
  try {
    const bet = await pool.query("SELECT * FROM bets WHERE id=$1", [req.params.id]);
    if (!bet.rows[0]) return res.status(404).json({ error: "Bet not found" });
    const updates = bet.rows[0].updates || [];
    updates.push({ text: update, author: req.user.username, time: new Date().toISOString() });
    await pool.query("UPDATE bets SET updates=$1 WHERE id=$2", [JSON.stringify(updates), req.params.id]);
    res.json({ success: true, updates });
  } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`FriendlyBets backend running on port ${PORT}`));
