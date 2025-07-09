"""
Database initialization script for HR system (SQLite).
Creates tables and indexes if they do not exist.
"""
import sqlite3

def create_db():
    """Create all required tables and indexes for the HR system database."""
    conn = sqlite3.connect('hr_system.db')
    c = conn.cursor()
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # Lunch orders table
    c.execute('''
        CREATE TABLE IF NOT EXISTS lunch_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            dish TEXT NOT NULL,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Comments table
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (announcement_id) REFERENCES announcements (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Chat messages table
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Chat rooms table
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            is_private INTEGER DEFAULT 0
        )
    ''')
    # Chat room members table
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_room_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (room_id) REFERENCES chat_rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Lunch menus table
    c.execute('''
        CREATE TABLE IF NOT EXISTS lunch_menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL UNIQUE,
            main_menu TEXT NOT NULL,
            accompaniment TEXT,
            image_url TEXT,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ users.db created successfully.")

    # Add indexes for performance
    conn = sqlite3.connect('hr_system.db')
    c = conn.cursor()
    c.execute('CREATE INDEX IF NOT EXISTS idx_complaints_user_status ON complaints(user_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_repairs_user_status ON repairs(user_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_announcements_author ON announcements(author_id)')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_db()
