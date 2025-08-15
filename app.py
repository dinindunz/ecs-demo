#!/usr/bin/env python3
import os
import sqlite3
import subprocess
import pickle
from flask import Flask, request, render_template_string, redirect, session
import yaml

app = Flask(__name__)

app.secret_key = "hardcoded-secret-key-123"

app.config['DEBUG'] = True

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
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
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    
    return '''
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        template = f"<h1>Search Results for: {query}</h1>"
        return render_template_string(template)
    return '<form><input name="q" placeholder="Search..."><button>Search</button></form>'

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre>"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file_data = request.files['file'].read()
        try:
            data = pickle.loads(file_data)
            return f"Uploaded data: {data}"
        except:
            return "Error processing file"
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    '''

@app.route('/config', methods=['POST'])
def config():
    config_data = request.form.get('config')
    if config_data:
        config = yaml.load(config_data, Loader=yaml.Loader)
        return f"Config loaded: {config}"
    return "No config provided"

@app.route('/read/<path:filename>')
def read_file(filename):
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except:
        return "File not found"

@app.route('/debug')
def debug():
    return {
        'environment': dict(os.environ),
        'secret_key': app.secret_key,
        'config': dict(app.config)
    }

@app.route('/admin')
def admin():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    html = "<h1>Admin Panel</h1><table>"
    for user in users:
        html += f"<tr><td>{user['username']}</td><td>{user['password']}</td><td>{user['email']}</td></tr>"
    html += "</table>"
    return html

@app.route('/comment')
def comment():
    user_comment = request.args.get('comment', '')
    return f"<h1>Your comment:</h1><div>{user_comment}</div>"

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)