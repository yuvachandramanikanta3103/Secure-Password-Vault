import sqlite3

DB_PATH = "vault.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn

def initialize_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS master_user (
            id INTEGER PRIMARY KEY,
            master_pass TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_name TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_master_hash(hashed_pw: bytes):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM master_user")  # ensure single row
    cur.execute("INSERT INTO master_user (master_pass) VALUES (?)", (hashed_pw.decode(),))
    conn.commit()
    conn.close()

def get_master_hash():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT master_pass FROM master_user LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0].encode() if row else None

def add_entry(account_name, username, encrypted_password, notes):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO passwords (account_name, username, password, notes) VALUES (?, ?, ?, ?)",
                (account_name, username, encrypted_password, notes))
    conn.commit()
    conn.close()

def update_entry(entry_id, account_name, username, encrypted_password, notes):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE passwords SET account_name=?, username=?, password=?, notes=? WHERE id=?",
                (account_name, username, encrypted_password, notes, entry_id))
    conn.commit()
    conn.close()

def delete_entry(entry_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()

def fetch_all():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, account_name, username, password, notes FROM passwords ORDER BY account_name")
    rows = cur.fetchall()
    conn.close()
    return rows

def fetch_by_id(entry_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, account_name, username, password, notes FROM passwords WHERE id=?", (entry_id,))
    row = cur.fetchone()
    conn.close()
    return row
