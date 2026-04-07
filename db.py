import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'privix.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        email TEXT,
        google_id TEXT
    )
    ''')

    # Migration for existing tables
    cursor.execute("PRAGMA table_info(Users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'email' not in columns:
        cursor.execute("ALTER TABLE Users ADD COLUMN email TEXT")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON Users(email)")
    if 'google_id' not in columns:
        cursor.execute("ALTER TABLE Users ADD COLUMN google_id TEXT")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON Users(google_id)")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES Users (id)
    )
    ''')

    cursor.execute("PRAGMA table_info(SharedFiles)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'file_id' in columns:
        cursor.execute("DROP TABLE SharedFiles")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS SharedFiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shared_with_user_id INTEGER NOT NULL,
        original_owner_id INTEGER NOT NULL,
        original_file_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (shared_with_user_id) REFERENCES Users (id),
        FOREIGN KEY (original_owner_id) REFERENCES Users (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users (id)
    )
    ''')

    conn.commit()
    conn.close()


def create_user(username, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO Users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_google_id(google_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE google_id = ?", (google_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_google_user_id(user_id, google_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE Users SET google_id = ? WHERE id = ?", (google_id, user_id))
    conn.commit()
    conn.close()


def create_google_user(username, email, google_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO Users (username, email, google_id, password_hash) VALUES (?, ?, ?, NULL)",
            (username, email, google_id)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def store_file_metadata(owner_id, filename, filepath, file_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Files (owner_id, filename, filepath, hash, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
        (owner_id, filename, filepath, file_hash)
    )
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id


def get_user_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Files WHERE owner_id = ? ORDER BY id DESC", (user_id,))
    files = cursor.fetchall()
    conn.close()
    return files


def get_shared_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT sf.*, u.username as owner_name
    FROM SharedFiles sf
    JOIN Users u ON sf.original_owner_id = u.id
    WHERE sf.shared_with_user_id = ?
    ORDER BY sf.id DESC
    ''', (user_id,))
    files = cursor.fetchall()
    conn.close()
    return files


def get_file_by_id(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Files WHERE id = ?", (file_id,))
    file_record = cursor.fetchone()
    conn.close()
    return file_record


def share_file_with_user(shared_with_user_id, original_owner_id, original_file_id, filename, filepath, file_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO SharedFiles (shared_with_user_id, original_owner_id, original_file_id, filename, filepath, hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ''', (shared_with_user_id, original_owner_id, original_file_id, filename, filepath, file_hash))
    conn.commit()
    conn.close()

def remove_shared_access(shared_file_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM SharedFiles WHERE id = ? AND shared_with_user_id = ?",
        (shared_file_id, user_id)
    )
    conn.commit()
    conn.close()

def get_shared_file_by_id(shared_file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM SharedFiles WHERE id = ?", (shared_file_id,))
    file_record = cursor.fetchone()
    conn.close()
    return file_record

def is_file_already_shared(original_file_id, shared_with_user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM SharedFiles WHERE original_file_id = ? AND shared_with_user_id = ?",
        (original_file_id, shared_with_user_id)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None

def has_shared_access(shared_file_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM SharedFiles WHERE id = ? AND shared_with_user_id = ?",
        (shared_file_id, user_id)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


def get_recent_logs(user_id, limit=5):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit))
    logs = cursor.fetchall()
    conn.close()
    return logs


def log_action(user_id, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Logs (user_id, action, timestamp) VALUES (?, ?, datetime('now'))", (user_id, action))
    conn.commit()
    conn.close()


def delete_file(file_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # We no longer delete from SharedFiles so they keep their physical copies!
    cursor.execute("DELETE FROM Files WHERE id = ? AND owner_id = ?", (file_id, user_id))
    conn.commit()
    conn.close()
