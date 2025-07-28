import sqlite3

DATABASE = 'alerts.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Drop existing tables to recreate with new schema
    c.execute('DROP TABLE IF EXISTS login_attempts')
    c.execute('DROP TABLE IF EXISTS alerts')
    c.execute('DROP TABLE IF EXISTS whitelisted_ips')
    c.execute('DROP TABLE IF EXISTS blocked_ips')
    c.execute('DROP TABLE IF EXISTS audit_log') # Drop old audit log if it exists

    # Create login_attempts table
    c.execute('''
        CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            success INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            city TEXT,
            country TEXT
        )
    ''')
    # Create alerts table
    c.execute('''
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    # Create whitelisted_ips table
    c.execute('''
        CREATE TABLE whitelisted_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE
        )
    ''')

    # Create blocked_ips table
    c.execute('''
        CREATE TABLE blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            reason TEXT
        )
    ''')

    # Create the new audit_log table
    c.execute('''
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            location TEXT,
            source TEXT,
            event_type TEXT NOT NULL,
            details TEXT
        )
    ''')

    # Add a default whitelisted IP for local testing
    c.execute('INSERT INTO whitelisted_ips (ip) VALUES (?)', ('127.0.0.1',))


    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully with audit_log table.")