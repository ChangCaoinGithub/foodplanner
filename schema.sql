-- Cloudflare D1 schema for the shared Food Planner.
-- IMPORTANT: do NOT commit your real allowed emails to GitHub.
-- Add them later in the Cloudflare D1 console.

CREATE TABLE IF NOT EXISTS allowed_users (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip_hash TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ingredients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  quantity REAL NOT NULL CHECK(quantity > 0),
  unit TEXT NOT NULL CHECK(unit IN ('kg','ml','portion','pieces')),
  storage TEXT NOT NULL CHECK(storage IN ('Fridge','Freezer','Outside')),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meals (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  meal_type TEXT NOT NULL CHECK(meal_type IN ('Lunch','Dinner')),
  meal_date TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  items TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN ('planned','eaten')),
  created_at INTEGER NOT NULL
);

-- Add allowed emails manually in the Cloudflare D1 console AFTER deployment.
-- Example only (replace with your own address there, not in your public repo):
-- INSERT INTO allowed_users(email) VALUES ('your-family-secret@example.com');
