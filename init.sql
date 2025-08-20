CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    credential_id TEXT UNIQUE NOT NULL,
    encrypted_raw_id TEXT NOT NULL,
    iv TEXT NOT NULL,
    label TEXT,
    auth_type TEXT,
    registration_time TEXT,
    active INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
