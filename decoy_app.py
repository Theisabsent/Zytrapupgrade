from flask import Flask, request, render_template_string, redirect, url_for, session
from datetime import datetime
import sqlite3
import logging
import requests

app = Flask(__name__)
app.secret_key = 'decoysecretkey'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

DATABASE = 'alerts.db'

# ... (templates remain the same) ...
decoy_login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Decoy Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .login-fail {
            background-color: #f8d7da !important;
            color: #721c24;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
    </style>
</head>
<body class="bg-light">
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <div class="card shadow-sm">
                <div class="card-header text-center">
                    <h4>Decoy Admin Login</h4>
                </div>
                <div class="card-body">
                    {% if error %}
                    <div class="login-fail">{{ error }}</div>
                    {% endif %}
                    <form method="post" action="{{ url_for('decoy_admin') }}">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required autofocus>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
"""

fake_admin_panel_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fake Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
    <h1>Welcome to the Fake Admin Panel</h1>
    <p>This is a fake admin panel for demonstration purposes.</p>
</div>
</body>
</html>
"""

def get_db_connection():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
    
def log_to_audit(ip, event_type, details, source='decoy', location=None):
    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if location is None:
        city, country = fetch_geolocation(ip)
        location = f"{city}, {country}" if city and country else "Unknown"
    
    conn.execute(
        'INSERT INTO audit_log (timestamp, ip, location, source, event_type, details) VALUES (?, ?, ?, ?, ?, ?)',
        (now, ip, location, source, event_type, details)
    )
    conn.commit()
    conn.close()

def fetch_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                city = data.get("city", "")
                country = data.get("country", "")
                return city, country
    except Exception:
        pass
    return "Hyderabad", "India"

def log_login_attempt(ip, username, password, success):
    test_ip = ip
    if ip == '127.0.0.1':
        test_ip = '8.8.8.8'
    city, country = fetch_geolocation(test_ip)
    location = f"{city}, {country}"

    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        'INSERT INTO login_attempts (ip, username, password, success, timestamp, source, city, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (ip, username, password, success, now, 'decoy', city, country)
    )
    conn.commit()
    conn.close()

    event_type = 'Successful Decoy Login' if success else 'Failed Decoy Login'
    details = f"Username: {username}, Password: {password}"
    log_to_audit(ip, event_type, details, source='decoy', location=location)


def log_alert(ip, message):
    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        'INSERT INTO alerts (ip, message, timestamp) VALUES (?, ?, ?)',
        (ip, message, now)
    )
    conn.commit()
    conn.close()

@app.route('/admin', methods=['GET', 'POST'])
def decoy_admin():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip == '127.0.0.1':
        ip = "202.174.120.125"
    
    log_alert(ip, 'Page Access: Decoy Visited')
    log_to_audit(ip, 'Decoy Page Visit', 'User accessed the decoy admin login page.', source='decoy')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        log_login_attempt(ip, username, password, 0) # Assume failure unless explicitly successful
        log_alert(ip, 'Login Attempt: Decoy login attempt')

        if username == 'admin' and password == 'Admin@123':
            # Overwrite the previous failed log with a success
            log_login_attempt(ip, username, password, 1)
            session['decoy_authenticated'] = True
            log_alert(ip, 'Successful Login: Decoy login success')
            return redirect(url_for('fake_admin_panel'))
        else:
            error = "Invalid username or password."
            return render_template_string(decoy_login_template, error=error)
    return render_template_string(decoy_login_template, error=None)

@app.route('/admin/panel')
def fake_admin_panel():
    if not session.get('decoy_authenticated'):
        return redirect(url_for('decoy_admin'))
    return render_template_string(fake_admin_panel_template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)