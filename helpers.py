from datetime import datetime
from flask import session
from db import get_db

# User dashboard data

def get_user_dashboard_data(user_id):
    with get_db() as db:
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
        # User's lunch orders
        lunch_orders = db.execute(
            'SELECT * FROM lunch_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5', (user_id,)
        ).fetchall()
        # User's comments
        comments = db.execute(
            'SELECT c.*, a.title as announcement_title FROM comments c JOIN announcements a ON c.announcement_id = a.id WHERE c.user_id = ? ORDER BY c.created_at DESC LIMIT 5', (user_id,)
        ).fetchall()
        # User's notifications
        notifications = db.execute(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (user_id,)
        ).fetchall()
        # Recent chat messages (public room)
        chat_messages = db.execute(
            'SELECT username, message, created_at FROM chat_messages ORDER BY created_at DESC LIMIT 10'
        ).fetchall()
    return {
        'announcements': announcements,
        'lunch_orders': lunch_orders,
        'comments': comments,
        'notifications': notifications,
        'chat_messages': list(reversed(chat_messages)),
    }

# Admin dashboard data

def get_admin_dashboard_data():
    with get_db() as db:
        user_count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        recent_users = db.execute('SELECT * FROM users ORDER BY created_at DESC LIMIT 5').fetchall()
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
        today = datetime.now().strftime('%Y-%m-%d')
        lunch_orders = db.execute('''
            SELECT lo.*, u.full_name, u.username FROM lunch_orders lo
            JOIN users u ON lo.user_id = u.id
            WHERE DATE(lo.created_at) = ?
            ORDER BY lo.created_at ASC
        ''', (today,)).fetchall()
    return {
        'user_count': user_count,
        'recent_users': recent_users,
        'announcements': announcements,
        'lunch_orders': lunch_orders
    }

# HR dashboard data

def get_hr_dashboard_data():
    with get_db() as db:
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
        employees = db.execute(
            'SELECT id, full_name, department, position FROM users WHERE role = "user" ORDER BY full_name'
        ).fetchall()
    return {'announcements': announcements, 'employees': employees}

# Notification helpers

def get_user_notifications(user_id, unread_only=False):
    with get_db() as db:
        if unread_only:
            notifications = db.execute(
                'SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC', (user_id,)
            ).fetchall()
        else:
            notifications = db.execute(
                'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', (user_id,)
            ).fetchall()
    return notifications

# Comments helpers

def get_user_comments(user_id):
    with get_db() as db:
        comments = db.execute(
            'SELECT c.*, a.title as announcement_title FROM comments c JOIN announcements a ON c.announcement_id = a.id WHERE c.user_id = ? ORDER BY c.created_at DESC', (user_id,)
        ).fetchall()
    return comments

# Lunch order helpers

def get_user_lunch_orders(user_id):
    with get_db() as db:
        orders = db.execute(
            'SELECT * FROM lunch_orders WHERE user_id = ? ORDER BY created_at DESC', (user_id,)
        ).fetchall()
    return orders

# Chat helpers

def get_recent_chat_messages(limit=10):
    with get_db() as db:
        messages = db.execute(
            'SELECT username, message, created_at FROM chat_messages ORDER BY created_at DESC LIMIT ?', (limit,)
        ).fetchall()
    return list(reversed(messages)) 