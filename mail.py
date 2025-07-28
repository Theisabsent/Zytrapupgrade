from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)

# MailHog configuration
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'alert@localhost.com'

mail = Mail(app)

def send_alert(alert_type, ip, timestamp):
    with app.app_context():  # <-- 🔥 FIX HERE

        subject = "Security Alert Triggered"
        message_body = ""

        if alert_type == "decoy_visited":
            subject = "🚨 Security Alert: Decoy Visited"
            message_body = f"""
                <h2>⚠️ Decoy Page Accessed</h2>
                <p><strong>IP:</strong> <em>{ip}</em></p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <p><strong>Location:</strong> Hyderabad, India</p>
                <hr>
                <p><em>This alert was generated automatically by our deception system <strong>Zytrap</strong>.</em></p>
            """
        elif alert_type == "brute_admin":
            subject = "🚨 Security Alert: Brute Force on Admin"
            message_body = f"""
                <h2>🚨 Brute Force Attempt on Admin</h2>
                <p><strong>IP:</strong> <em>{ip}</em></p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <p><strong>Location:</strong> Hyderabad, India</p>
                <hr>
                <p><em>This alert was generated automatically by our deception system <strong>Zytrap</strong>.</em></p>
            """
        elif alert_type == "brute_decoy":
            subject = "🚨 Security Alert: Brute Force on Decoy"
            message_body = f"""
                <h2>🚨 Brute Force Attempt on Decoy Page</h2>
                <p><strong>IP:</strong> <em>{ip}</em></p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <p><strong>Location:</strong> Hyderabad, India</p>
                <hr>
                <p><em>This alert was generated automatically by our deception system <strong>Zytrap</strong>.</em></p>
            """

        msg = Message(
            subject=subject,
            recipients=["securityhead@gmail.com"],
            html=message_body
        )

    with app.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent: {subject}")
        except Exception as e:
            print(f"❌ Email sending failed: {e}")
