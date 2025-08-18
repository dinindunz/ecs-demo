#!/usr/bin/env python3
import os
import sqlite3
import json
import re
from flask import Flask, request, render_template_string, redirect, session, escape
import yaml
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup

app = Flask(__name__)

# Use environment variable for secret key, fallback to secure random generation
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# Disable debug mode in production
app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'

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
    # Use hashed password instead of plaintext
    hashed_password = generate_password_hash('admin123')
    conn.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)", 
                ('admin', hashed_password, 'admin@example.com'))
    conn.commit()
    conn.close()

def validate_input(input_string, max_length=100):
    """Basic input validation and sanitization"""
    if not input_string:
        return ""
    # Remove potentially dangerous characters
    cleaned = re.sub(r'[<>"\']', '', str(input_string)[:max_length])
    return cleaned.strip()

@app.route('/')
def home():
    return '''
    <h1>Secure Web Application</h1>
    <a href="/login">Login</a> | 
    <a href="/search">Search Users</a> | 
    <a href="/upload">Upload</a> | 
    <a href="/admin">Admin Panel</a>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = validate_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        if not username or not password:
            return "Username and password are required"
        
        conn = get_db_connection()
        # Use parameterized query to prevent SQL injection
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    
    return '''
    <form method="POST">
        Username: <input type="text" name="username" maxlength="50" required><br>
        Password: <input type="password" name="password" maxlength="100" required><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    query = validate_input(request.args.get('q', ''), 50)
    if query:
        # Properly escape output to prevent XSS
        safe_query = escape(query)
        template = f"<h1>Search Results for: {safe_query}</h1>"
        return template
    return '<form><input name="q" placeholder="Search..." maxlength="50"><button>Search</button></form>'

@app.route('/ping')
def ping():
    # Removed command injection vulnerability - return static message instead
    return "<p>Ping functionality has been disabled for security reasons.</p>"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file provided"
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected"
        
        try:
            # Use JSON instead of pickle to prevent deserialization attacks
            file_content = file.read().decode('utf-8')
            data = json.loads(file_content)
            # Validate and sanitize the data
            if isinstance(data, dict) and len(str(data)) < 1000:
                safe_data = {k: validate_input(str(v)) for k, v in data.items() if isinstance(k, str)}
                return f"Uploaded data: {escape(str(safe_data))}"
            else:
                return "Invalid data format or size"
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "Error: Invalid JSON file"
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" accept=".json">
        <input type="submit" value="Upload">
    </form>
    '''

@app.route('/config', methods=['POST'])
def config():
    config_data = request.form.get('config', '')
    if config_data and len(config_data) < 1000:
        try:
            # Use safe_load instead of load to prevent code execution
            config = yaml.safe_load(config_data)
            if isinstance(config, dict):
                safe_config = {k: validate_input(str(v)) for k, v in config.items() if isinstance(k, str)}
                return f"Config loaded: {escape(str(safe_config))}"
            else:
                return "Invalid config format"
        except yaml.YAMLError:
            return "Invalid YAML format"
    return "No valid config provided"

@app.route('/read/<path:filename>')
def read_file(filename):
    # Prevent path traversal attacks
    if '..' in filename or filename.startswith('/') or '~' in filename:
        return "Access denied: Invalid file path"
    
    # Only allow reading from a safe directory
    safe_files = ['readme.txt', 'info.txt', 'help.txt']
    if filename not in safe_files:
        return "Access denied: File not allowed"
    
    try:
        safe_path = os.path.join('safe_files', filename)
        if os.path.exists(safe_path):
            with open(safe_path, 'r') as f:
                content = f.read()[:1000]  # Limit content size
            return f"<pre>{escape(content)}</pre>"
        else:
            return "File not found"
    except Exception:
        return "Error reading file"

@app.route('/debug')
def debug():
    # Remove sensitive information exposure
    if app.config['DEBUG']:
        return {
            'status': 'debug_enabled',
            'message': 'Debug information available in development mode only'
        }
    else:
        return {'status': 'production', 'message': 'Debug information not available'}

@app.route('/admin')
def admin():
    # Add basic authentication check
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email FROM users').fetchall()  # Don't expose passwords
    conn.close()
    
    html = "<h1>Admin Panel</h1><table><tr><th>ID</th><th>Username</th><th>Email</th></tr>"
    for user in users:
        html += f"<tr><td>{escape(str(user['id']))}</td><td>{escape(user['username'])}</td><td>{escape(user['email'])}</td></tr>"
    html += "</table>"
    return html

@app.route('/comment')
def comment():
    user_comment = validate_input(request.args.get('comment', ''), 200)
    # Properly escape output to prevent XSS
    safe_comment = escape(user_comment)
    return f"<h1>Your comment:</h1><div>{safe_comment}</div>"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return f"<h1>Welcome, {escape(session.get('username', 'User'))}!</h1><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    # Use environment variables for configuration
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host=host, port=port, debug=debug)