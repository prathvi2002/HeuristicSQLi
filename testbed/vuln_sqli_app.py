from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)
DB_PATH = 'vuln.db'

# ------------------ DB Setup ------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    cursor.executemany('''
        INSERT INTO users (username, email) VALUES (?, ?)
    ''', [
        ('admin', 'admin@example.com'),
        ('alice', 'alice@pentest.com'),
        ('bob', 'bob@pentest.com')
    ])
    conn.commit()
    conn.close()

# ------------------ Route ------------------
@app.route('/search')
def search():
    username = request.args.get('username', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ❌ Deliberately Vulnerable to SQLi
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    print(f"[DEBUG] Executing: {query}")  # optional logging for console

    # ❗ No try/except block — raw error will be returned
    cursor.execute(query)
    rows = cursor.fetchall()
    if rows:
        return '<br>'.join([f"ID: {r[0]}, Username: {r[1]}, Email: {r[2]}" for r in rows])
    else:
        return "No results found."

# ------------------ Main ------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
