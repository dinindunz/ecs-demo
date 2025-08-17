#!/usr/bin/env python3
import os
import sqlite3
import json
import re
from pathlib import Path
from flask import Flask, request, render_template_string, redirect, session, escape, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import Markup
import secrets

app = Flask(__name__)

# Security: Use environment variable for secret key with secure fallback
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Security: Disable debug mode in production
app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'

# Security: Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    ''')
    # Security: Use hashed password instead of plaintext
    hashed_password = generate_password_hash('admin123')
    conn.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)", 
                ('admin', hashed_password, 'admin@example.com'))
    conn.commit()
    conn.close()

def validate_input(input_string, max_length=100):
    """Security: Input validation function"""
    if not input_string or len(input_string) > max_length:
        return False
    # Allow only alphanumeric characters, spaces, and basic punctuation
    return re.match(r'^[a-zA-Z0-9\s\.\-_@]+$', input_string) is not None

@app.route('/')
def home():
    return '''
    <h1>Secure Web Application</h1>
    <a href="/login">Login</a> | 
    <a href="/search">Search Users</a> | 
    <a href="/upload">Upload</a>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Security: Input validation
        if not validate_input(username, 50) or not password:
            return "Invalid input", 400
        
        conn = get_db_connection()
        # Security: Use parameterized query to prevent SQL injection
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        # Security: Use secure password verification
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return "Invalid credentials", 401
    
    return '''
    <form method="POST">
        Username: <input type="text" name="username" maxlength="50" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if query:
        # Security: Validate and escape user input to prevent XSS
        if not validate_input(query, 50):
            return "Invalid search query", 400
        
        # Security: Use escape() to prevent XSS
        safe_query = escape(query)
        template = f"<h1>Search Results for: {safe_query}</h1>"
        return template
    return '<form><input name="q" placeholder="Search..." maxlength="50"><button>Search</button></form>'

# Security: Remove dangerous ping endpoint that allowed command injection
# @app.route('/ping') - REMOVED for security

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file provided", 400
            
        file = request.files['file']
        if file.filename == '':
            return "No file selected", 400
            
        try:
            # Security: Use JSON instead of pickle to prevent deserialization attacks
            file_content = file.read().decode('utf-8')
            data = json.loads(file_content)
            
            # Security: Validate JSON structure
            if not isinstance(data, dict) or len(str(data)) > 1000:
                return "Invalid file format", 400
                
            return f"Uploaded data: {escape(str(data))}"
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "Error: Invalid JSON file", 400
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" accept=".json" required>
        <input type="submit" value="Upload">
    </form>
    '''

@app.route('/config', methods=['POST'])
def config():
    config_data = request.form.get('config', '').strip()
    if not config_data:
        return "No config provided", 400
    
    try:
        # Security: Use safe JSON loading instead of unsafe YAML
        config = json.loads(config_data)
        
        # Security: Validate config structure
        if not isinstance(config, dict) or len(str(config)) > 1000:
            return "Invalid config format", 400
            
        return f"Config loaded: {escape(str(config))}"
    except json.JSONDecodeError:
        return "Invalid JSON config", 400

# Security: Remove dangerous file read endpoint that allowed path traversal
# @app.route('/read/<path:filename>') - REMOVED for security

# Security: Remove debug endpoint that exposed sensitive information
# @app.route('/debug') - REMOVED for security

@app.route('/admin')
def admin():
    # Security: Add authentication check
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email FROM users').fetchall()
    conn.close()
    
    html = "<h1>Admin Panel</h1><table><tr><th>ID</th><th>Username</th><th>Email</th></tr>"
    for user in users:
        # Security: Escape output to prevent XSS
        html += f"<tr><td>{escape(user['id'])}</td><td>{escape(user['username'])}</td><td>{escape(user['email'])}</td></tr>"
    html += "</table>"
    return html

@app.route('/comment')
def comment():
    user_comment = request.args.get('comment', '').strip()
    
    # Security: Input validation and XSS prevention
    if not validate_input(user_comment, 200):
        return "Invalid comment", 400
    
    # Security: Escape user input to prevent XSS
    safe_comment = escape(user_comment)
    return f"<h1>Your comment:</h1><div>{safe_comment}</div>"

@app.route('/dashboard')
def dashboard():
    # Security: Add authentication check
    if 'user_id' not in session:
        return redirect('/login')
    
    username = escape(session.get('username', 'Unknown'))
    return f"<h1>Welcome, {username}!</h1><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Security: Add health check endpoint (safe alternative to debug)
@app.route('/health')
def health():
    return jsonify({"status": "healthy", "version": "1.0.0"})

if __name__ == '__main__':
    init_db()
    # Security: Bind to localhost only in development
    host = '0.0.0.0' if os.environ.get('PRODUCTION') else '127.0.0.1'
    app.run(host=host, port=5000, debug=app.config['DEBUG'])