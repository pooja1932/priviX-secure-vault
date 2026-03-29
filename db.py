import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'privix.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        hash TEXT NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES Users (id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS SharedFiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        shared_with_user_id INTEGER NOT NULL,
        FOREIGN KEY (file_id) REFERENCES Files (id),
        FOREIGN KEY (shared_with_user_id) REFERENCES Users (id)
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
        cursor.execute("INSERT INTO Users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None  # Username exists
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def store_file_metadata(owner_id, filename, filepath, file_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Files (owner_id, filename, filepath, hash) VALUES (?, ?, ?, ?)",
                   (owner_id, filename, filepath, file_hash))
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id

def get_user_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Files WHERE owner_id = ?", (user_id,))
    files = cursor.fetchall()
    conn.close()
    return files

def get_shared_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT f.*, u.username as owner_name 
    FROM SharedFiles sf
    JOIN Files f ON sf.file_id = f.id
    JOIN Users u ON f.owner_id = u.id
    WHERE sf.shared_with_user_id = ?
    ''', (user_id,))
    files = cursor.fetchall()
    conn.close()
    return files

def log_action(user_id, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Logs (user_id, action) VALUES (?, ?)", (user_id, action))
    conn.commit()
    conn.close()
