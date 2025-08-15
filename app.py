#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import pickle
from flask import Flask, request, render_template_string, redirect, session
import yaml
import logging

app = Flask(__name__)

app.secret_key = "hardcoded-secret-key-123"

app.config['DEBUG'] = True

# Configure logging to prevent malformed log entries
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT
            )
        ''')
        conn.execute("INSERT OR IGNORE INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@example.com')")
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")

@app.route('/')
def home():
    return '''
    <h1>Vulnerable Web Application</h1>
    <a href="/login">Login</a> | 
    <a href="/search">Search Users</a> | 
    <a href="/upload">Upload</a> | 
    <a href="/admin">Admin Panel</a>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            # Basic input validation to prevent crashes
            if not username or not password:
                logger.warning("Login attempt with empty credentials")
                return "Invalid credentials"
            
            # Prevent SQL injection by using parameterized queries
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                              (username, password)).fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                logger.info(f"Successful login for user: {username}")
                return redirect('/dashboard')
            else:
                logger.warning(f"Failed login attempt for user: {username}")
                return "Invalid credentials"
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return "Login error occurred"
    
    return '''
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    try:
        query = request.args.get('q', '').strip()
        if query:
            # Sanitize input to prevent template injection
            safe_query = query.replace('<', '&lt;').replace('>', '&gt;')
            template = f"<h1>Search Results for: {safe_query}</h1>"
            return template
        return '<form><input name="q" placeholder="Search..."><button>Search</button></form>'
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return "Search error occurred"

@app.route('/ping')
def ping():
    try:
        host = request.args.get('host', 'localhost').strip()
        
        # Basic input validation to prevent command injection
        if not host or any(char in host for char in [';', '&', '|', '`', '$', '(', ')']):
            logger.warning(f"Invalid ping host attempted: {host}")
            return "Invalid host parameter"
        
        # Limit to basic hostname format
        if not host.replace('.', '').replace('-', '').isalnum():
            logger.warning(f"Invalid ping host format: {host}")
            return "Invalid host format"
        
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        return f"<pre>{result.stdout}</pre>"
    except subprocess.TimeoutExpired:
        logger.error("Ping command timed out")
        return "Ping timeout"
    except Exception as e:
        logger.error(f"Ping error: {str(e)}")
        return "Ping error occurred"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return "No file provided"
            
            file = request.files['file']
            if file.filename == '':
                return "No file selected"
            
            file_data = file.read()
            if len(file_data) > 1024:  # Limit file size
                return "File too large"
            
            # Disable pickle loading to prevent deserialization attacks
            return "File upload disabled for security reasons"
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            return "Upload error occurred"
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    '''

@app.route('/config', methods=['POST'])
def config():
    try:
        config_data = request.form.get('config', '').strip()
        if config_data:
            # Use safe YAML loading to prevent code execution
            config = yaml.safe_load(config_data)
            logger.info("Config loaded successfully")
            return f"Config loaded: {str(config)[:100]}..."  # Limit output
        return "No config provided"
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error: {str(e)}")
        return "Invalid YAML format"
    except Exception as e:
        logger.error(f"Config error: {str(e)}")
        return "Config error occurred"

@app.route('/read/<path:filename>')
def read_file(filename):
    try:
        # Prevent path traversal attacks
        if '..' in filename or filename.startswith('/'):
            logger.warning(f"Path traversal attempt: {filename}")
            return "Access denied"
        
        # Limit to safe files only
        safe_files = ['README.md', 'requirements.txt']
        if filename not in safe_files:
            logger.warning(f"Unauthorized file access attempt: {filename}")
            return "File access denied"
        
        with open(filename, 'r') as f:
            content = f.read()[:1000]  # Limit content size
        return f"<pre>{content}</pre>"
    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")
        return "File not found"
    except Exception as e:
        logger.error(f"File read error: {str(e)}")
        return "File read error occurred"

@app.route('/debug')
def debug():
    try:
        # Limit debug information to prevent information disclosure
        return {
            'status': 'running',
            'version': '1.0.0'
        }
    except Exception as e:
        logger.error(f"Debug error: {str(e)}")
        return "Debug error occurred"

@app.route('/admin')
def admin():
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT username, email FROM users').fetchall()  # Don't expose passwords
        conn.close()
        
        html = "<h1>Admin Panel</h1><table>"
        for user in users:
            html += f"<tr><td>{user['username']}</td><td>{user['email']}</td></tr>"
        html += "</table>"
        return html
    except Exception as e:
        logger.error(f"Admin panel error: {str(e)}")
        return "Admin panel error occurred"

@app.route('/comment')
def comment():
    try:
        user_comment = request.args.get('comment', '').strip()
        # Sanitize comment to prevent XSS
        safe_comment = user_comment.replace('<', '&lt;').replace('>', '&gt;')
        return f"<h1>Your comment:</h1><div>{safe_comment}</div>"
    except Exception as e:
        logger.error(f"Comment error: {str(e)}")
        return "Comment error occurred"

@app.route('/dashboard')
def dashboard():
    try:
        if 'username' in session:
            return f"<h1>Welcome, {session['username']}!</h1><a href='/logout'>Logout</a>"
        return redirect('/login')
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return "Dashboard error occurred"

@app.route('/logout')
def logout():
    try:
        session.clear()
        logger.info("User logged out")
        return redirect('/')
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return "Logout error occurred"

if __name__ == '__main__':
    try:
        init_db()
        logger.info("Starting Flask application")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Application startup error: {str(e)}")