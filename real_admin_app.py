from flask import Flask, request, render_template_string, redirect, url_for, session, abort
from datetime import datetime, timedelta
import sqlite3
import logging
import requests

app = Flask(__name__)
app.secret_key = 'realsecretkey'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

DATABASE = 'alerts.db'

# Bootstrap template for real admin login page
real_login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Real Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <div class="card shadow-sm">
                <div class="card-header text-center">
                    <h4>Real Admin Login</h4>
                </div>
                <div class="card-body">
                    {% if error %}
                    <div class="alert alert-danger" role="alert">{{ error }}</div>
                    {% endif %}
                    <form method="post" action="{{ url_for('secure_admin') }}">
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

# Bootstrap template for real admin panel
real_admin_panel_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Real Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
    <h1>Welcome to the Real Admin Panel</h1>
    <p>This is the real admin panel. Access is restricted.</p>
</div>
</body>
</html>
"""

def get_db_connection():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def log_to_audit(ip, event_type, details, source='System', location=None):
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

def is_ip_whitelisted(ip):
    conn = get_db_connection()
    result = conn.execute('SELECT 1 FROM whitelisted_ips WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    return result is not None

def is_ip_blocked(ip):
    conn = get_db_connection()
    result = conn.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    return result is not None

def block_ip(ip, reason="Brute-force"):
    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        conn.execute('INSERT INTO blocked_ips (ip, timestamp, reason) VALUES (?, ?, ?)', (ip, now, reason))
        conn.commit()
        log_to_audit(ip, 'IP Blocked', f'Reason: {reason}', source='real_admin')
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def log_alert(ip, message):
    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        'INSERT INTO alerts (ip, message, timestamp) VALUES (?, ?, ?)',
        (ip, message, now)
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
    return None, None

def log_login_attempt(ip, username, password, success):
    test_ip = ip
    if ip == '127.0.0.1':
        test_ip = '8.8.8.8'
    city, country = fetch_geolocation(test_ip)
    location = f"{city}, {country}" if city and country else "Hyderabad, India"
    
    conn = get_db_connection()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        'INSERT INTO login_attempts (ip, username, password, success, timestamp, source, city, country) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (ip, username, password, success, now, 'real_admin', city, country)
    )
    conn.commit()
    conn.close()
    
    event_type = 'Successful Login' if success else 'Failed Login'
    details = f"Username: {username}, Password: {password}"
    log_to_audit(ip, event_type, details, source='real_admin', location=location)

def is_bruteforcing(ip):
    conn = get_db_connection()
    five_minutes_ago = datetime.now() - timedelta(minutes=5)
    result = conn.execute(
        'SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND timestamp > ?',
        (ip, five_minutes_ago.strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchone()
    conn.close()
    return result[0] > 5

@app.before_request
def check_ip():
    if request.path.startswith('/secure-admin'):
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip == '127.0.0.1':
            ip = "202.174.120.125"

        if is_ip_blocked(ip):
            abort(404)

        if not is_ip_whitelisted(ip):
            block_ip(ip, reason="Unauthorized Access")
            log_alert(ip, 'Blocked: Unauthorized IP access attempt to /secure-admin')
            abort(404)

@app.route('/secure-admin', methods=['GET', 'POST'])
def secure_admin():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'admin' and password == 'securePass123':
            log_login_attempt(ip, username, password, 1)
            session['secure_authenticated'] = True
            return redirect(url_for('real_admin_panel'))
        else:
            log_login_attempt(ip, username, password, 0)
            if is_bruteforcing(ip):
                block_ip(ip, reason="Brute-force")
                conn = get_db_connection()
                conn.execute('DELETE FROM whitelisted_ips WHERE ip = ?', (ip,))
                conn.commit()
                conn.close()
                log_alert(ip, f'Blocked: Brute-force detected from {ip}. IP has been blocked.')
                abort(404)

            error = "Invalid username or password."
            return render_template_string(real_login_template, error=error)
    return render_template_string(real_login_template, error=None)

@app.route('/secure-admin/panel')
def real_admin_panel():
    if not session.get('secure_authenticated'):
        return redirect(url_for('secure_admin'))
    return render_template_string(real_admin_panel_template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)