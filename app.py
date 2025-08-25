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

# Use environment variable for secret key - never hardcode secrets
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# Disable debug mode for production
app.config['DEBUG'] = os.environ.get('FLASK_ENV') == 'development'

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
    """Basic input validation"""
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
    <a href="/upload">Upload</a> | 
    <a href="/admin">Admin Panel</a>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Input validation
        if not validate_input(username, 50) or not password:
            return "Invalid input format"
        
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
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if query:
        # Validate and escape input to prevent XSS
        if not validate_input(query, 100):
            return "Invalid search query format"
        # Use escape to prevent XSS
        safe_query = escape(query)
        template = f"<h1>Search Results for: {safe_query}</h1>"
        return template
    return '<form><input name="q" placeholder="Search..." maxlength="100"><button>Search</button></form>'

@app.route('/ping')
def ping():
    """Removed command injection vulnerability - implement safe ping if needed"""
    return "<p>Ping functionality disabled for security reasons. Use proper monitoring tools.</p>"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file provided"
        
        file = request.files['file']
        if file.filename == '':
            return "No file selected"
        
        try:
            # Use JSON instead of insecure pickle
            file_content = file.read().decode('utf-8')
            data = json.loads(file_content)
            
            # Validate JSON structure
            if not isinstance(data, dict) or len(str(data)) > 1000:
                return "Invalid file format or size"
            
            return f"Uploaded data: {escape(str(data))}"
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "Error: Invalid JSON file"
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" accept=".json" required>
        <input type="submit" value="Upload JSON File">
    </form>
    '''

@app.route('/config', methods=['POST'])
def config():
    config_data = request.form.get('config', '').strip()
    if config_data:
        try:
            # Use safe YAML loading instead of unsafe Loader
            config = yaml.safe_load(config_data)
            if config and len(str(config)) < 500:
                return f"Config loaded: {escape(str(config))}"
            else:
                return "Invalid or too large config"
        except yaml.YAMLError:
            return "Invalid YAML format"
    return "No config provided"

@app.route('/read/<path:filename>')
def read_file(filename):
    """Removed path traversal vulnerability - file reading disabled for security"""
    return "File reading functionality disabled for security reasons"

@app.route('/debug')
def debug():
    """Remove sensitive information exposure"""
    if app.config['DEBUG']:
        return {"message": "Debug mode enabled", "version": "1.0"}
    else:
        return {"message": "Debug information not available in production"}

@app.route('/admin')
def admin():
    # Add basic authentication check
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email FROM users').fetchall()
    conn.close()
    
    html = "<h1>Admin Panel</h1><table><tr><th>ID</th><th>Username</th><th>Email</th></tr>"
    for user in users:
        # Escape output to prevent XSS
        html += f"<tr><td>{escape(str(user['id']))}</td><td>{escape(user['username'])}</td><td>{escape(user['email'])}</td></tr>"
    html += "</table>"
    return html

@app.route('/comment')
def comment():
    user_comment = request.args.get('comment', '').strip()
    if user_comment:
        # Validate and escape input to prevent XSS
        if not validate_input(user_comment, 200):
            return "Invalid comment format"
        safe_comment = escape(user_comment)
        return f"<h1>Your comment:</h1><div>{safe_comment}</div>"
    return "<h1>No comment provided</h1>"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return f"<h1>Welcome, {escape(session['username'])}!</h1><a href='/logout'>Logout</a>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    # Use environment variables for configuration
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.run(host=host, port=port, debug=debug)