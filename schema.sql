CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL, salt TEXT NOT NULL,
  settings TEXT, verified INTEGER DEFAULT 0,
  tg_chat TEXT, tg_code TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, expires INTEGER);
CREATE TABLE IF NOT EXISTS tx(
  id TEXT PRIMARY KEY, user_id INTEGER, phone TEXT, amount INTEGER, ref TEXT,
  status TEXT, receipt TEXT, message TEXT, checkout_id TEXT, cbkey TEXT,
  source TEXT, created_at INTEGER, done_at INTEGER);
CREATE INDEX IF NOT EXISTS tx_user ON tx(user_id, created_at);
CREATE INDEX IF NOT EXISTS tx_cb ON tx(cbkey);
