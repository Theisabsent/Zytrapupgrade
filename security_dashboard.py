from flask import Flask, render_template_string, make_response, request, redirect, url_for
import sqlite3
import requests
from datetime import datetime, timedelta
import threading

app = Flask(__name__)

DATABASE = 'alerts.db'

# Bootstrap template for security dashboard with AJAX auto update
security_dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>

<body class="bg-light">
<div class="container mt-5">
    <h1 class="mb-4">Security Dashboard</h1>

    <ul class="nav nav-tabs" id="dashboardTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="audit-log-tab" data-bs-toggle="tab" data-bs-target="#audit-log" type="button" role="tab">Audit Log</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="login-tab" data-bs-toggle="tab" data-bs-target="#login" type="button" role="tab">All Login Attempts</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="alerts-tab" data-bs-toggle="tab" data-bs-target="#alerts" type="button" role="tab">Decoy Alerts</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="blocked-ips-tab" data-bs-toggle="tab" data-bs-target="#blocked-ips" type="button" role="tab">Blocked IPs</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="whitelist-tab" data-bs-toggle="tab" data-bs-target="#whitelist" type="button" role="tab">Whitelisted IPs</button>
        </li>
    </ul>

    <div class="tab-content mt-4">
        <div class="tab-pane fade show active" id="audit-log" role="tabpanel">
            <h3>Master Audit Log</h3>
            <p class="text-muted">This log provides a comprehensive, chronological record of all significant events across the system.</p>
            <table class="table table-hover" id="auditLogTable">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP</th>
                        <th>Location</th>
                        <th>Source</th>
                        <th>Event Type</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in audit_logs %}
                    <tr class="{{ 'table-danger' if 'Failed' in log.event_type or 'Blocked' in log.event_type else 'table-success' if 'Successful' in log.event_type or 'Granted' in log.event_type else 'table-info' if 'Admin' in log.source else 'table-light' }}">
                        <td>{{ log.timestamp }}</td>
                        <td>{{ log.ip }}</td>
                        <td>{{ log.location }}</td>
                        <td><span class="badge bg-secondary">{{ log.source }}</span></td>
                        <td>{{ log.event_type }}</td>
                        <td>{{ log.details }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="tab-pane fade" id="login" role="tabpanel">
            <h3>All Login Attempts</h3>
            <input class="form-control mb-3" id="loginSearch" type="text" placeholder="Search...">
            <table class="table table-striped table-hover" id="loginAttemptsTable">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Username</th>
                        <th>Timestamp</th>
                        <th>Source</th>
                        <th>Event</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for attempt in attempts %}
                    <tr class="{{ 'table-success' if attempt.success else 'table-danger' }}">
                        <td>{{ attempt.ip }}</td>
                        <td>{{ attempt.username }}</td>
                        <td>{{ attempt.timestamp }}</td>
                        <td>{{ attempt.source }}</td>
                        <td>{{ 'Successful Login' if attempt.success else 'Failed Login' }}</td>
                        <td>{{ 'Access granted' if attempt.success else 'Access denied' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="tab-pane fade" id="alerts" role="tabpanel">
            <h3>Alerts (Decoy Only)</h3>
            <table class="table table-striped" id="alertsTable">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Message</th>
                        <th>Timestamp</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in alerts %}
                    <tr class="{% if 'Brute-force' in alert.message %}table-danger{% elif 'Visited' in alert.message %}table-warning{% elif 'Failed' in alert.message %}table-danger{% elif 'Successful' in alert.message %}table-success{% else %}table-light{% endif %}">
                        <td>{{ alert.ip }}</td>
                        <td>{{ alert.message }}</td>
                        <td>{{ alert.timestamp }}</td>
                        <td>
                            <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#alertModal{{ loop.index }}">
                                View Details
                            </button>
                            <div class="modal fade" id="alertModal{{ loop.index }}" tabindex="-1" aria-labelledby="alertModalLabel{{ loop.index }}" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="alertModalLabel{{ loop.index }}">Alert Details</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <p><strong>IP:</strong> {{ alert.ip }}</p>
                                    <p><strong>Timestamp:</strong> {{ alert.timestamp }}</p>
                                    <p><strong>Message:</strong> {{ alert.message }}</p>
                                </div>
                                </div>
                            </div>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="tab-pane fade" id="blocked-ips" role="tabpanel">
            <h3>Blocked IPs</h3>
            <table class="table table-striped" id="blockedIPsTable">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Timestamp</th>
                        <th>Reason</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for blocked_ip in blocked_ips %}
                    <tr>
                        <td>{{ blocked_ip.ip }}</td>
                        <td>{{ blocked_ip.timestamp }}</td>
                        <td><span class="badge bg-danger">{{ blocked_ip.reason }}</span></td>
                        <td>
                            <form method="post" action="{{ url_for('unblock_ip') }}" style="display:inline;" onsubmit="return confirmUnblock('{{ blocked_ip.reason }}')">
                                <input type="hidden" name="ip" value="{{ blocked_ip.ip }}">
                                <button type="submit" class="btn btn-sm btn-success">Unblock & Whitelist</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="tab-pane fade" id="whitelist" role="tabpanel">
            <h3>Whitelisted IPs</h3>
            <table class="table table-striped" id="whitelistTable">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip in whitelisted_ips %}
                    <tr>
                        <td>{{ ip.ip }}</td>
                        <td>
                            <form method="post" action="{{ url_for('remove_whitelist') }}" style="display:inline;">
                                <input type="hidden" name="ip" value="{{ ip.ip }}">
                                <button type="submit" class="btn btn-sm btn-danger">Remove</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

    </div>
</div>

<script>
function fetchDashboardData() {
    fetch('/')
        .then(response => response.text())
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');

            // Update all tables
            document.querySelector('#auditLogTable tbody').innerHTML = doc.querySelector('#auditLogTable tbody').innerHTML;
            document.querySelector('#loginAttemptsTable tbody').innerHTML = doc.querySelector('#loginAttemptsTable tbody').innerHTML;
            document.querySelector('#alertsTable tbody').innerHTML = doc.querySelector('#alertsTable tbody').innerHTML;
            document.querySelector('#blockedIPsTable tbody').innerHTML = doc.querySelector('#blockedIPsTable tbody').innerHTML;
            document.querySelector('#whitelistTable tbody').innerHTML = doc.querySelector('#whitelistTable tbody').innerHTML;
        })
        .catch(error => console.error('Error fetching dashboard data:', error));
}

    setInterval(fetchDashboardData, 3000);

    function confirmUnblock(reason) {
        if (reason && reason.toLowerCase().includes('brute-force')) {
            return confirm('Has the security issue with this IP been resolved? If you select "OK", access will be granted.');
        }
        return true;
    }

    document.addEventListener('DOMContentLoaded', function() {
        var hash = window.location.hash;
        if (hash) {
            var triggerEl = document.querySelector('.nav-tabs button[data-bs-target="' + hash + '"]');
            if (triggerEl) {
                var tab = new bootstrap.Tab(triggerEl);
                tab.show();
            }
        } else {
            // Default to audit log if no hash is present
            var firstTab = document.querySelector('#audit-log-tab');
            if(firstTab) {
                var tab = new bootstrap.Tab(firstTab);
                tab.show();
            }
        }

        const loginSearch = document.getElementById('loginSearch');
        loginSearch.addEventListener('keyup', function() {
            const filter = loginSearch.value.toUpperCase();
            const table = document.getElementById('loginAttemptsTable');
            const tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {
                let display = 'none';
                const td = tr[i].getElementsByTagName('td');
                for (let j = 0; j < td.length; j++) {
                    if (td[j]) {
                        if (td[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
                            display = '';
                            break;
                        }
                    }
                }
                tr[i].style.display = display;
            }
        });
    });
</script>
</body>
</html>
"""

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
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
    return "Unknown", "Location"

@app.route('/')
def security_dashboard():
    conn = get_db_connection()

    audit_logs = conn.execute('SELECT * FROM audit_log ORDER BY timestamp DESC').fetchall()
    attempts = conn.execute('SELECT * FROM login_attempts ORDER BY timestamp DESC').fetchall()
    
    decoy_alerts_query = "SELECT * FROM alerts WHERE message NOT LIKE ? AND message NOT LIKE ? ORDER BY timestamp DESC"
    decoy_alerts_params = ('%/secure-admin%', '%Brute-force detected%')
    decoy_alerts = conn.execute(decoy_alerts_query, decoy_alerts_params).fetchall()

    blocked_ips = conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC').fetchall()
    whitelisted_ips = conn.execute('SELECT * FROM whitelisted_ips ORDER BY ip').fetchall()
    
    conn.close()

    rendered = render_template_string(
        security_dashboard_template, 
        audit_logs=audit_logs,
        attempts=attempts, 
        alerts=decoy_alerts,
        blocked_ips=blocked_ips, 
        whitelisted_ips=whitelisted_ips
    )
    response = make_response(rendered)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/unblock', methods=['POST'])
def unblock_ip():
    ip_to_unblock = request.form.get('ip')
    if ip_to_unblock:
        conn = get_db_connection()
        conn.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip_to_unblock,))
        conn.execute('INSERT OR IGNORE INTO whitelisted_ips (ip) VALUES (?)', (ip_to_unblock,))
        conn.commit()
        conn.close()
        log_to_audit(ip_to_unblock, 'Access Granted by Admin', 'IP was unblocked and whitelisted.', source='Admin')
    return redirect(url_for('security_dashboard') + '#blocked-ips')

@app.route('/remove_whitelist', methods=['POST'])
def remove_whitelist():
    ip_to_remove = request.form.get('ip')
    if ip_to_remove:
        conn = get_db_connection()
        count_result = conn.execute('SELECT COUNT(*) FROM whitelisted_ips').fetchone()
        if count_result and count_result[0] > 1:
            conn.execute('DELETE FROM whitelisted_ips WHERE ip = ?', (ip_to_remove,))
            conn.commit()
            log_to_audit(ip_to_remove, 'Whitelist Removal', 'IP was removed from the whitelist.', source='Admin')
        else:
            print(f"Cannot remove the last whitelisted IP: {ip_to_remove}.")
        conn.close()
    return redirect(url_for('security_dashboard') + '#whitelist')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)