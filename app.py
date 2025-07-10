"""
Main Flask application for HR System.
Handles user authentication, dashboards, chat, notifications, HR/admin features, and file uploads.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps
import markdown
from datetime import datetime
import csv
from io import StringIO
from markupsafe import Markup
from flask_socketio import SocketIO, emit, join_room, leave_room
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate
import io
import time
from werkzeug.utils import secure_filename
from reportlab.platypus import Flowable
# from flask_wtf import CSRFProtect

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = 'b6cf94b299a1f56d63199b2298f7095c3ee344bd1bb1a77cfd6e03d4a2b95b71'
app.config['DATABASE'] = 'hr_system.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
# csrf = CSRFProtect(app)

# Database Helper Functions
def get_db():
    """Connect to the configured SQLite database and return a connection with row factory."""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize the database with all required tables and default data."""
    db = get_db()
    try:
        # Drop existing tables if they exist
        db.execute('DROP TABLE IF EXISTS users')
        db.execute('DROP TABLE IF EXISTS announcements')
        
        # Create new tables with updated schema
        db.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            full_name TEXT,
            department TEXT,
            position TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        db.execute('''
        CREATE TABLE announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )''')
        
        # Add lunch_orders table
        db.execute('''
        CREATE TABLE lunch_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            dish TEXT NOT NULL,
            notes TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Add comments table
        db.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            announcement_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (announcement_id) REFERENCES announcements (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Add chat_messages table
        db.execute('''
        CREATE TABLE chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            file_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Add notifications table
        db.execute('''
        CREATE TABLE notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            announcement_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (announcement_id) REFERENCES announcements (id)
        )''')
        
        # Add complaints table
        db.execute('''
        CREATE TABLE complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Add repairs table
        db.execute('''
        CREATE TABLE repairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Add events table
        db.execute('''
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            event_date DATE NOT NULL,
            location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Add lunch_menus table
        db.execute('''
        CREATE TABLE lunch_menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL UNIQUE,
            main_menu TEXT NOT NULL,
            accompaniment TEXT,
            image_url TEXT,
            notes TEXT
        )''')
        
        # Insert default admin user
        db.execute(
            'INSERT INTO users (username, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'admin@hrsystem.com', generate_password_hash('admin123'), 'admin', 'System Administrator')
        )
        
        # Insert sample announcement
        db.execute(
            'INSERT INTO announcements (title, content, author_id) VALUES (?, ?, ?)',
            ('Welcome to HR System', 'This is a sample announcement.', 1)
        )
        
        # Add columns for notification and theme preferences if not present
        try:
            db.execute('ALTER TABLE users ADD COLUMN notify_complaints INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN notify_comments INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN notify_new_users INTEGER DEFAULT 1')
        except sqlite3.OperationalError:
            pass
        try:
            db.execute('ALTER TABLE users ADD COLUMN theme TEXT DEFAULT "dark"')
        except sqlite3.OperationalError:
            pass
        
        db.commit()
        print("✅ Database tables created successfully.")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        db.rollback()
        raise e
    finally:
        db.close()

def initialize_database():
    """Check if the database exists and is valid, otherwise initialize it."""
    if not os.path.exists(app.config['DATABASE']):
        print("🔄 Creating new database...")
        init_db()
    else:
        print("🔍 Database exists, checking schema...")
        db = get_db()
        try:
            # Check if all tables exist
            db.execute("SELECT 1 FROM users LIMIT 1")
            db.execute("SELECT 1 FROM announcements LIMIT 1")
            print("✅ Database schema is valid.")
        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                print("⚠️ Missing tables detected. Recreating database...")
                init_db()
            else:
                print(f"❌ Database error: {e}")
        finally:
            db.close()

initialize_database()

# Decorators
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def hr_required(f):
    """Decorator to require HR or admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        if session.get('role') not in ['admin', 'hr']:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'hr':
            return redirect(url_for('hr_dashboard'))
        elif role == 'user':
            return redirect(url_for('dashboard'))
        else:
            # Unknown role, log out for safety
            session.clear()
            return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', '').strip()
        position = request.form.get('position', '').strip()

        errors = []
        
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters')
            
        if not email:
            errors.append('Email is required')
        elif '@' not in email:
            errors.append('Invalid email format')
            
        if not password:
            errors.append('Password is required')
        elif len(password) < 6:
            errors.append('Password must be at least 6 characters')
        elif password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name,
                                 department=department,
                                 position=position)

        with get_db() as db:
            existing_user = db.execute(
                'SELECT id FROM users WHERE username = ? OR email = ?',
                (username, email)
            ).fetchone()

            if existing_user:
                flash('Username or email already exists', 'danger')
                return render_template('register.html', 
                                     username=username, 
                                     email=email,
                                     full_name=full_name,
                                     department=department,
                                     position=position)

            try:
                db.execute(
                    'INSERT INTO users (username, email, password_hash, full_name, department, position) VALUES (?, ?, ?, ?, ?, ?)',
                    (username, email, generate_password_hash(password), full_name, department, position)
                )
                db.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.Error as e:
                flash('Registration failed. Please try again.', 'danger')
                print(f"Database error: {e}")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        with get_db() as db:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            
            flash(f'Welcome back, {user["full_name"] or user["username"]}!', 'success')
            
            # Redirect to appropriate dashboard based on role
            if user['role'] == 'admin':
                return redirect(url_for('dashboard'))
            elif user['role'] == 'hr':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# User Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Only allow regular users to access /dashboard
    if session.get('role') != 'user':
        # Redirect to correct dashboard for admin or hr
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'hr':
            return redirect(url_for('hr_dashboard'))
        else:
            session.clear()
            return redirect(url_for('login'))
    total_start = time.time()
    with get_db() as db:
        t1 = time.time()
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
        print('Announcements query took', time.time() - t1, 'seconds')
        t2 = time.time()
        complaints_count = db.execute(
            'SELECT COUNT(*) FROM complaints WHERE user_id = ? AND status = "pending"',
            (session['user_id'],)
        ).fetchone()[0]
        print('Complaints count query took', time.time() - t2, 'seconds')
        t3 = time.time()
        repairs_count = db.execute(
            'SELECT COUNT(*) FROM repairs WHERE user_id = ? AND status = "pending"',
            (session['user_id'],)
        ).fetchone()[0]
        print('Repairs count query took', time.time() - t3, 'seconds')
        t4 = time.time()
        unread_notifications = db.execute(
            'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
            (session['user_id'],)
        ).fetchone()[0]
        print('Notifications count query took', time.time() - t4, 'seconds')
        today = time.strftime('%Y-%m-%d')
        lunch_orders = db.execute(
            'SELECT * FROM lunch_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
            (session['user_id'],)
        ).fetchall()
        today_menu = db.execute('SELECT * FROM lunch_menus WHERE date = ?', (today,)).fetchone()
    print('Total dashboard route time:', time.time() - total_start, 'seconds')
    return render_template('user_dashboard/dashboard.html', announcements=announcements, complaints_count=complaints_count, repairs_count=repairs_count, unread_notifications=unread_notifications, lunch_orders=lunch_orders, today_str=today, today_menu=today_menu)

# Admin Section
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
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
    return render_template('admin_dashboard/dashboard.html', 
                         user_count=user_count,
                         recent_users=recent_users,
                         announcements=announcements,
                         lunch_orders=lunch_orders)

@app.route('/admin/users')
@admin_required
def admin_users():
    q = request.args.get('q', '').strip()
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    allowed_sorts = ['username', 'email', 'full_name', 'department', 'position', 'role', 'created_at']
    allowed_orders = ['asc', 'desc']
    if sort not in allowed_sorts:
        sort = 'created_at'
    if order not in allowed_orders:
        order = 'desc'
    sort_sql = f"{sort} {order.upper()}"
    with get_db() as db:
        if q:
            users = db.execute(f'''
                SELECT * FROM users WHERE 
                    username LIKE ? OR email LIKE ? OR full_name LIKE ? OR department LIKE ? OR position LIKE ?
                ORDER BY {sort_sql} LIMIT ? OFFSET ?''',
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', per_page, offset)
            ).fetchall()
            total = db.execute('''
                SELECT COUNT(*) FROM users WHERE 
                    username LIKE ? OR email LIKE ? OR full_name LIKE ? OR department LIKE ? OR position LIKE ?''',
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%')
            ).fetchone()[0]
        else:
            users = db.execute(f'SELECT * FROM users ORDER BY {sort_sql} LIMIT ? OFFSET ?', (per_page, offset)).fetchall()
            total = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_pages = (total + per_page - 1) // per_page
    return render_template('admin/users.html', users=users, q=q, page=page, total_pages=total_pages, sort=sort, order=order)

@app.route('/admin/create_announcement', methods=['POST'])
@admin_required
def create_announcement():
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if not title or not content:
        flash('Title and content are required.', 'danger')
        return redirect(url_for('admin_dashboard'))
    # Optionally render markdown to HTML for preview/storage
    content_html = Markup(markdown.markdown(content, extensions=['extra', 'nl2br', 'sane_lists']))
    with get_db() as db:
        db.execute(
            'INSERT INTO announcements (title, content, author_id) VALUES (?, ?, ?)',
            (title, content_html, session['user_id'])
        )
        db.commit()
    flash('Announcement posted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/lunch_orders/download')
@admin_required
def download_lunch_orders():
    today = datetime.now().strftime('%Y-%m-%d')
    with get_db() as db:
        orders = db.execute('''
            SELECT lo.*, u.full_name, u.username FROM lunch_orders lo
            JOIN users u ON lo.user_id = u.id
            WHERE DATE(lo.created_at) = ?
            ORDER BY lo.created_at ASC
        ''', (today,)).fetchall()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Employee', 'Dish', 'Notes', 'Status', 'Time'])
    for order in orders:
        writer.writerow([
            order['full_name'] or order['username'],
            order['dish'],
            order['notes'] or '',
            order['status'],
            order['created_at'][11:16]
        ])
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=lunch_orders_{today}.csv'}
    )

@app.route('/admin/lunch_orders/update/<int:order_id>', methods=['POST'])
@admin_required
def update_lunch_order_status(order_id):
    status = request.form.get('status', 'pending')
    with get_db() as db:
        db.execute('UPDATE lunch_orders SET status = ? WHERE id = ?', (status, order_id))
        db.commit()
    flash('Lunch order status updated.', 'success')
    return redirect(url_for('admin_dashboard'))

# HR Section
@app.route('/hr/dashboard')
@hr_required
def hr_dashboard():
    with get_db() as db:
        total_employees = db.execute('SELECT COUNT(*) FROM users WHERE role = "user"').fetchone()[0]
        open_complaints = db.execute('SELECT COUNT(*) FROM complaints WHERE status = "pending"').fetchone()[0]
        open_repairs = db.execute('SELECT COUNT(*) FROM repairs WHERE status = "pending"').fetchone()[0]
        upcoming_events = db.execute('SELECT COUNT(*) FROM events WHERE event_date >= DATE("now")').fetchone()[0]
    return render_template('hr/dashboard.html', total_employees=total_employees, open_complaints=open_complaints, open_repairs=open_repairs, upcoming_events=upcoming_events)

@app.route('/submit_lunch_order', methods=['POST'])
@login_required
def submit_lunch_order():
    main_menu = request.form.get('main_menu', '').strip()
    accompaniment = request.form.get('accompaniment', '').strip()
    notes = request.form.get('notes', '').strip()
    if not main_menu:
        flash('Please enter your main menu item.', 'danger')
        return redirect(url_for('dashboard'))
    today = datetime.now().strftime('%Y-%m-%d')
    with get_db() as db:
        existing = db.execute(
            'SELECT id FROM lunch_orders WHERE user_id = ? AND DATE(created_at) = ?',
            (session['user_id'], today)
        ).fetchone()
        if existing:
            flash('You have already ordered lunch today.', 'warning')
            return redirect(url_for('dashboard'))
        dish = f"Main: {main_menu}; Accompaniment: {accompaniment}"
        db.execute(
            'INSERT INTO lunch_orders (user_id, dish, notes) VALUES (?, ?, ?)',
            (session['user_id'], dish, notes)
        )
        db.commit()
    flash('Your lunch order has been submitted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/announcement/<int:announcement_id>', methods=['GET', 'POST'])
@login_required
def view_announcement(announcement_id):
    with get_db() as db:
        announcement = db.execute('''
            SELECT a.*, u.full_name as author_name FROM announcements a
            JOIN users u ON a.author_id = u.id
            WHERE a.id = ?
        ''', (announcement_id,)).fetchone()
        if not announcement:
            flash('Announcement not found.', 'danger')
            return redirect(url_for('dashboard'))
        comments = db.execute('''
            SELECT c.*, u.full_name, u.username FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.announcement_id = ?
            ORDER BY c.created_at ASC
        ''', (announcement_id,)).fetchall()
    return render_template('view_announcement.html', announcement=announcement, comments=comments)

# Admin-only: Delete comment
@app.route('/admin/comment/<int:comment_id>/delete', methods=['POST'])
@admin_required
def delete_comment(comment_id):
    with get_db() as db:
        db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
        db.commit()
    flash('Comment deleted.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

# Notification system: store notification for announcement author when a new comment is posted
@app.route('/announcement/<int:announcement_id>/comment', methods=['POST'])
@login_required
def add_comment(announcement_id):
    content = request.form.get('content', '').strip()
    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('view_announcement', announcement_id=announcement_id))
    with get_db() as db:
        db.execute(
            'INSERT INTO comments (announcement_id, user_id, content) VALUES (?, ?, ?)',
            (announcement_id, session['user_id'], content)
        )
        db.commit()
        # Notification logic
        announcement = db.execute('SELECT author_id FROM announcements WHERE id = ?', (announcement_id,)).fetchone()
        if announcement and announcement['author_id'] != session['user_id']:
            db.execute('''CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                announcement_id INTEGER
            )''')
            db.execute(
                'INSERT INTO notifications (user_id, message, announcement_id) VALUES (?, ?, ?)',
                (announcement['author_id'], f'New comment on your announcement (ID: {announcement_id})', announcement_id)
            )
            db.commit()
    flash('Comment posted!', 'success')
    return redirect(url_for('view_announcement', announcement_id=announcement_id))

# Mark notification as read and redirect to announcement
@app.route('/notification/<int:notification_id>/read')
@login_required
def read_notification(notification_id):
    with get_db() as db:
        notification = db.execute('SELECT * FROM notifications WHERE id = ? AND user_id = ?', (notification_id, session['user_id'])).fetchone()
        if notification:
            db.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
            db.commit()
            if notification['announcement_id']:
                return redirect(url_for('view_announcement', announcement_id=notification['announcement_id']))
        # Always redirect to the correct dashboard based on role
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'hr':
            return redirect(url_for('hr_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))

@app.before_request
def load_notifications():
    g.notifications = []
    if 'user_id' in session:
        with get_db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            g.notifications = db.execute(
                'SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC',
                (session['user_id'],)
            ).fetchall()

@app.route('/chat')
@login_required
def chat():
    return render_template('user/chat.html', current_username=session.get('full_name', session.get('username')))

# SocketIO event for sending/receiving messages
online_users = set()

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        username = session.get('full_name', session.get('username'))
        online_users.add(username)
        # Send last 50 messages (public room for now)
        with get_db() as db:
            messages = db.execute('SELECT username, message, created_at FROM chat_messages ORDER BY created_at DESC LIMIT 50').fetchall()
            for msg in reversed(messages):
                emit('receive_message', {'username': msg['username'], 'message': msg['message'], 'created_at': msg['created_at']})
        # Broadcast user list
        emit('user_list', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        username = session.get('full_name', session.get('username'))
        if username in online_users:
            online_users.remove(username)
        emit('user_list', list(online_users), broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    join_room(room)
    # Only emit to room if room is not None and emit supports 'room' param
    if room:
        # Flask-SocketIO emit supports 'to' instead of 'room' in recent versions
        emit('receive_message', {'username': 'System', 'message': f'{session.get("full_name", session.get("username"))} joined the room.'}, to=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data.get('room')
    leave_room(room)
    if room:
        emit('receive_message', {'username': 'System', 'message': f'{session.get("full_name", session.get("username"))} left the room.'}, to=room)

@socketio.on('send_message')
def handle_send_message(data):
    username = data.get('username')
    message = data.get('message')
    file_url = data.get('file_url')
    user_id = session.get('user_id')
    room = data.get('room')
    # Store message in DB (public room for now)
    with get_db() as db:
        db.execute('INSERT INTO chat_messages (user_id, username, message, file_url) VALUES (?, ?, ?, ?)', (user_id, username, message, file_url))
        db.commit()
    payload = {'username': username, 'message': message}
    if file_url:
        payload['file_url'] = file_url
    if room:
        emit('receive_message', payload, to=room)
    else:
        emit('receive_message', payload, broadcast=True)

@socketio.on('delete_message')
def handle_delete_message(data):
    message_id = data.get('message_id')
    user_id = session.get('user_id')
    with get_db() as db:
        msg = db.execute('SELECT * FROM chat_messages WHERE id = ?', (message_id,)).fetchone()
        if msg and msg['user_id'] == user_id:
            db.execute('DELETE FROM chat_messages WHERE id = ?', (message_id,))
            db.commit()
            emit('message_deleted', {'message_id': message_id}, broadcast=True)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash('Please enter a search term.', 'warning')
        return redirect(request.referrer or url_for('dashboard'))
    with get_db() as db:
        announcements = db.execute('''SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id WHERE a.title LIKE ? OR a.content LIKE ?''', (f'%{query}%', f'%{query}%')).fetchall()
        comments = db.execute('''SELECT c.*, u.full_name, u.username, a.title as announcement_title FROM comments c JOIN users u ON c.user_id = u.id JOIN announcements a ON c.announcement_id = a.id WHERE c.content LIKE ?''', (f'%{query}%',)).fetchall()
        users = db.execute('''SELECT * FROM users WHERE username LIKE ? OR full_name LIKE ? OR email LIKE ?''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
    return render_template('search_results.html', query=query, announcements=announcements, comments=comments, users=users)

@app.route('/complaints', methods=['GET', 'POST'])
@login_required
def user_complaints():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title or not description:
            flash('Title and description are required.', 'danger')
        else:
            with get_db() as db:
                db.execute(
                    'INSERT INTO complaints (user_id, title, description) VALUES (?, ?, ?)',
                    (session['user_id'], title, description)
                )
                # Notify all HR users
                hr_users = db.execute('SELECT id FROM users WHERE role IN ("hr", "admin")').fetchall()
                for hr in hr_users:
                    db.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)',
                               (hr['id'], f'New complaint submitted by {session.get("full_name", session.get("username"))}'))
                db.commit()
            flash('Complaint submitted successfully!', 'success')
        return redirect(url_for('user_complaints'))
    # GET: show user's complaints
    with get_db() as db:
        complaints = db.execute(
            'SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC',
            (session['user_id'],)
        ).fetchall()
    return render_template('user/complaints.html', complaints=complaints)

@app.route('/repairs', methods=['GET', 'POST'])
@login_required
def user_repairs():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not title or not description:
            flash('Title and description are required.', 'danger')
        else:
            with get_db() as db:
                db.execute(
                    'INSERT INTO repairs (user_id, title, description) VALUES (?, ?, ?)',
                    (session['user_id'], title, description)
                )
                # Notify all HR users
                hr_users = db.execute('SELECT id FROM users WHERE role IN ("hr", "admin")').fetchall()
                for hr in hr_users:
                    db.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)',
                               (hr['id'], f'New repair request submitted by {session.get("full_name", session.get("username"))}'))
                db.commit()
            flash('Repair request submitted successfully!', 'success')
        return redirect(url_for('user_repairs'))
    # GET: show user's repairs
    with get_db() as db:
        repairs = db.execute(
            'SELECT * FROM repairs WHERE user_id = ? ORDER BY created_at DESC',
            (session['user_id'],)
        ).fetchall()
    return render_template('user/repairs.html', repairs=repairs)

@app.route('/events')
@login_required
def user_events():
    with get_db() as db:
        events = db.execute(
            'SELECT * FROM events WHERE event_date >= DATE("now") ORDER BY event_date ASC'
        ).fetchall()
    return render_template('user/events.html', events=events)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if request.method == 'POST':
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            department = request.form.get('department', '').strip()
            position = request.form.get('position', '').strip()
            # Update user info
            db.execute('UPDATE users SET full_name = ?, email = ?, department = ?, position = ? WHERE id = ?',
                       (full_name, email, department, position, session['user_id']))
            db.commit()
            flash('Profile updated successfully.', 'success')
            # Password change
            old_password = request.form.get('old_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            if old_password or new_password or confirm_password:
                if not check_password_hash(user['password_hash'], old_password):
                    flash('Old password is incorrect.', 'danger')
                elif len(new_password) < 6:
                    flash('New password must be at least 6 characters.', 'danger')
                elif new_password != confirm_password:
                    flash('New passwords do not match.', 'danger')
                else:
                    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                               (generate_password_hash(new_password), session['user_id']))
                    db.commit()
                    flash('Password updated successfully.', 'success')
            # Refresh user info
            user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('user/settings.html', user=user)

@app.route('/hr/employees')
@hr_required
def hr_employees():
    q = request.args.get('q', '').strip()
    with get_db() as db:
        if q:
            employees = db.execute('''
                SELECT * FROM users WHERE role = "user" AND (
                    full_name LIKE ? OR username LIKE ? OR department LIKE ? OR position LIKE ?
                ) ORDER BY created_at DESC''',
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%')
            ).fetchall()
        else:
            employees = db.execute('SELECT * FROM users WHERE role = "user" ORDER BY created_at DESC').fetchall()
    return render_template('hr/employees.html', employees=employees)

@app.route('/hr/employees/<int:user_id>')
@hr_required
def hr_employee_detail(user_id):
    with get_db() as db:
        employee = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not employee:
            flash('Employee not found.', 'danger')
            return redirect(url_for('hr_employees'))
    return render_template('hr/employee_detail.html', employee=employee)

@app.route('/hr/employees/<int:user_id>/edit', methods=['GET', 'POST'])
@hr_required
def hr_employee_edit(user_id):
    with get_db() as db:
        employee = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not employee:
            flash('Employee not found.', 'danger')
            return redirect(url_for('hr_employees'))
        if request.method == 'POST':
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            department = request.form.get('department', '').strip()
            position = request.form.get('position', '').strip()
            role = request.form.get('role', employee['role'])
            db.execute('UPDATE users SET full_name = ?, email = ?, department = ?, position = ?, role = ? WHERE id = ?',
                       (full_name, email, department, position, role, user_id))
            db.commit()
            flash('Employee info updated successfully.', 'success')
            return redirect(url_for('hr_employee_detail', user_id=user_id))
    return render_template('hr/employee_edit.html', employee=employee)

@app.route('/hr/employees/export')
@hr_required
def hr_employees_export():
    q = request.args.get('q', '').strip()
    with get_db() as db:
        if q:
            employees = db.execute('''
                SELECT * FROM users WHERE role = "user" AND (
                    full_name LIKE ? OR username LIKE ? OR department LIKE ? OR position LIKE ?
                ) ORDER BY created_at DESC''',
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%')
            ).fetchall()
        else:
            employees = db.execute('SELECT * FROM users WHERE role = "user" ORDER BY created_at DESC').fetchall()
    import csv
    from io import StringIO
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Full Name', 'Username', 'Email', 'Department', 'Position', 'Date Joined'])
    for emp in employees:
        writer.writerow([
            emp['full_name'] or emp['username'],
            emp['username'],
            emp['email'],
            emp['department'] or '',
            emp['position'] or '',
            emp['created_at'][:10]
        ])
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=employees.csv'}
    )

@app.route('/hr/employees/export_pdf')
@hr_required
def hr_employees_export_pdf():
    q = request.args.get('q', '').strip()
    with get_db() as db:
        if q:
            employees = db.execute('''
                SELECT * FROM users WHERE role = "user" AND (
                    full_name LIKE ? OR username LIKE ? OR department LIKE ? OR position LIKE ?
                ) ORDER BY created_at DESC''',
                (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%')
            ).fetchall()
        else:
            employees = db.execute('SELECT * FROM users WHERE role = "user" ORDER BY created_at DESC').fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    data = [['Name', 'Department', 'Position', 'Email', 'Date Joined']]
    for emp in employees:
        data.append([
            emp['full_name'] or emp['username'],
            emp['department'] or '-',
            emp['position'] or '-',
            emp['email'],
            emp['created_at'][:10]
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e7e34')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    # --- PDF Export: Fix Table/Flowable typing ---
    elements: list[Flowable] = [table]  # type: ignore
    doc.build(elements)
    buffer.seek(0)
    return app.response_class(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment; filename=employees.pdf'})

@app.route('/hr/complaints')
@hr_required
def hr_complaints():
    status = request.args.get('status', '').strip()
    q = request.args.get('q', '').strip()
    with get_db() as db:
        query = '''SELECT c.*, u.full_name, u.username, u.department FROM complaints c JOIN users u ON c.user_id = u.id WHERE 1=1'''
        params = []
        if status:
            query += ' AND c.status = ?'
            params.append(status)
        if q:
            query += ' AND (c.title LIKE ? OR c.description LIKE ? OR u.full_name LIKE ? OR u.username LIKE ? OR u.department LIKE ?)' 
            params += [f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%']
        query += ' ORDER BY c.created_at DESC'
        complaints = db.execute(query, params).fetchall()
    return render_template('hr/complaints.html', complaints=complaints, status=status, q=q)

@app.route('/hr/complaints/<int:complaint_id>', methods=['GET', 'POST'])
@hr_required
def hr_complaint_detail(complaint_id):
    with get_db() as db:
        complaint = db.execute('''
            SELECT c.*, u.full_name, u.username, u.department FROM complaints c
            JOIN users u ON c.user_id = u.id WHERE c.id = ?''', (complaint_id,)).fetchone()
        if not complaint:
            flash('Complaint not found.', 'danger')
            return redirect(url_for('hr_complaints'))
        if request.method == 'POST':
            new_status = request.form.get('status', complaint['status'])
            db.execute('UPDATE complaints SET status = ? WHERE id = ?', (new_status, complaint_id))
            db.commit()
            flash('Complaint status updated.', 'success')
            return redirect(url_for('hr_complaint_detail', complaint_id=complaint_id))
    return render_template('hr/complaint_detail.html', complaint=complaint)

@app.route('/hr/announcements', methods=['GET', 'POST'])
@hr_required
def hr_announcements():
    with get_db() as db:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            image = request.files.get('image')
            image_filename = None
            if image and image.filename:
                image_filename = f"announcement_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                image.save(os.path.join('static', 'img', image_filename))
            # Store image filename in content as a special tag (or add a new column if needed)
            if image_filename:
                content += f'\n<img src="/static/img/{image_filename}" class="img-fluid rounded mt-3" alt="Announcement Image">'
            db.execute(
                'INSERT INTO announcements (title, content, author_id) VALUES (?, ?, ?)',
                (title, content, session['user_id'])
            )
            db.commit()
            flash('Announcement posted successfully!', 'success')
            return redirect(url_for('hr_announcements'))
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC'
        ).fetchall()
    return render_template('hr/announcements.html', announcements=announcements)

@app.route('/hr/settings', methods=['GET', 'POST'])
@hr_required
def hr_settings():
    user_id = session['user_id']
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if request.method == 'POST':
            # Profile update
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            department = request.form.get('department', '').strip()
            position = request.form.get('position', '').strip()
            theme = request.form.get('theme', user['theme'])
            notify_complaints = 1 if request.form.get('notify_complaints') == 'on' else 0
            notify_comments = 1 if request.form.get('notify_comments') == 'on' else 0
            notify_new_users = 1 if request.form.get('notify_new_users') == 'on' else 0
            db.execute('UPDATE users SET full_name=?, email=?, department=?, position=?, theme=?, notify_complaints=?, notify_comments=?, notify_new_users=? WHERE id=?',
                (full_name, email, department, position, theme, notify_complaints, notify_comments, notify_new_users, user_id))
            db.commit()
            # Password change
            old_password = request.form.get('old_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            if old_password or new_password or confirm_password:
                if not check_password_hash(user['password_hash'], old_password):
                    flash('Old password is incorrect.', 'danger')
                elif len(new_password) < 6:
                    flash('New password must be at least 6 characters.', 'danger')
                elif new_password != confirm_password:
                    flash('New passwords do not match.', 'danger')
                else:
                    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                        (generate_password_hash(new_password), user_id))
                    db.commit()
                    flash('Password updated successfully.', 'success')
            flash('Settings updated successfully.', 'success')
            user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        # Dummy login history for now
        login_history = [
            {'time': '2024-06-01 09:00', 'ip': '192.168.1.10'},
            {'time': '2024-05-30 17:22', 'ip': '192.168.1.11'},
        ]
    return render_template('hr/settings.html', user=user, login_history=login_history)

# HR Event Management
@app.route('/hr/events', methods=['GET', 'POST'])
@hr_required
def hr_events():
    with get_db() as db:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            event_date = request.form.get('event_date', '').strip()
            location = request.form.get('location', '').strip()
            if not title or not description or not event_date:
                flash('Title, description, and date are required.', 'danger')
            else:
                db.execute('INSERT INTO events (title, description, event_date, location) VALUES (?, ?, ?, ?)',
                           (title, description, event_date, location))
                db.commit()
                flash('Event created successfully!', 'success')
            return redirect(url_for('hr_events'))
        events = db.execute('SELECT * FROM events ORDER BY event_date ASC').fetchall()
    return render_template('hr/events.html', events=events)

@app.route('/hr/events/<int:event_id>/edit', methods=['GET', 'POST'])
@hr_required
def hr_event_edit(event_id):
    with get_db() as db:
        event = db.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
        if not event:
            flash('Event not found.', 'danger')
            return redirect(url_for('hr_events'))
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            event_date = request.form.get('event_date', '').strip()
            location = request.form.get('location', '').strip()
            db.execute('UPDATE events SET title=?, description=?, event_date=?, location=? WHERE id=?',
                       (title, description, event_date, location, event_id))
            db.commit()
            flash('Event updated successfully.', 'success')
            return redirect(url_for('hr_events'))
    return render_template('hr/event_edit.html', event=event)

@app.route('/hr/events/<int:event_id>/delete', methods=['POST'])
@hr_required
def hr_event_delete(event_id):
    with get_db() as db:
        db.execute('DELETE FROM events WHERE id = ?', (event_id,))
        db.commit()
        flash('Event deleted.', 'success')
    return redirect(url_for('hr_events'))

# HR Repairs Management
@app.route('/hr/repairs')
@hr_required
def hr_repairs():
    status = request.args.get('status', '').strip()
    q = request.args.get('q', '').strip()
    with get_db() as db:
        query = '''SELECT r.*, u.full_name, u.username, u.department FROM repairs r JOIN users u ON r.user_id = u.id WHERE 1=1'''
        params = []
        if status:
            query += ' AND r.status = ?'
            params.append(status)
        if q:
            query += ' AND (r.title LIKE ? OR r.description LIKE ? OR u.full_name LIKE ? OR u.username LIKE ? OR u.department LIKE ?)' 
            params += [f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%']
        query += ' ORDER BY r.created_at DESC'
        repairs = db.execute(query, params).fetchall()
    return render_template('hr/repairs.html', repairs=repairs, status=status, q=q)

@app.route('/hr/repairs/<int:repair_id>', methods=['GET', 'POST'])
@hr_required
def hr_repair_detail(repair_id):
    with get_db() as db:
        repair = db.execute('''
            SELECT r.*, u.full_name, u.username, u.department FROM repairs r
            JOIN users u ON r.user_id = u.id WHERE r.id = ?''', (repair_id,)).fetchone()
        if not repair:
            flash('Repair not found.', 'danger')
            return redirect(url_for('hr_repairs'))
        if request.method == 'POST':
            new_status = request.form.get('status', repair['status'])
            db.execute('UPDATE repairs SET status = ? WHERE id = ?', (new_status, repair_id))
            db.commit()
            flash('Repair status updated.', 'success')
            return redirect(url_for('hr_repair_detail', repair_id=repair_id))
    return render_template('hr/repair_detail.html', repair=repair)

# Mark all notifications as read
@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    with get_db() as db:
        db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
        db.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(request.referrer or url_for('dashboard'))

# View all notifications
@app.route('/notifications')
@login_required
def all_notifications():
    with get_db() as db:
        notifications = db.execute(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
            (session['user_id'],)
        ).fetchall()
    return render_template('notifications.html', notifications=notifications)

# HR Lunch Orders Management
@app.route('/hr/lunch_orders', methods=['GET', 'POST'])
@hr_required
def hr_lunch_orders():
    today = datetime.now().strftime('%Y-%m-%d')
    with get_db() as db:
        if request.method == 'POST':
            order_id = request.form.get('order_id')
            status = request.form.get('status', 'pending')
            db.execute('UPDATE lunch_orders SET status = ? WHERE id = ?', (status, order_id))
            db.commit()
            flash('Lunch order status updated.', 'success')
            return redirect(url_for('hr_lunch_orders'))
        orders = db.execute('''
            SELECT lo.*, u.full_name, u.username FROM lunch_orders lo
            JOIN users u ON lo.user_id = u.id
            WHERE DATE(lo.created_at) = ?
            ORDER BY lo.created_at ASC
        ''', (today,)).fetchall()
    return render_template('hr/lunch_orders.html', orders=orders, today=today)

@app.route('/hr/lunch_orders/download')
@hr_required
def hr_download_lunch_orders():
    today = datetime.now().strftime('%Y-%m-%d')
    with get_db() as db:
        orders = db.execute('''
            SELECT lo.*, u.full_name, u.username FROM lunch_orders lo
            JOIN users u ON lo.user_id = u.id
            WHERE DATE(lo.created_at) = ?
            ORDER BY lo.created_at ASC
        ''', (today,)).fetchall()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Employee', 'Dish', 'Notes', 'Status', 'Time'])
    for order in orders:
        writer.writerow([
            order['full_name'] or order['username'],
            order['dish'],
            order['notes'] or '',
            order['status'],
            order['created_at'][11:16]
        ])
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=lunch_orders_{today}.csv'}
    )

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/hr/lunch_menu', methods=['GET', 'POST'])
@hr_required
def hr_lunch_menu():
    today = datetime.now().strftime('%Y-%m-%d')
    with get_db() as db:
        menu = db.execute('SELECT * FROM lunch_menus WHERE date = ?', (today,)).fetchone()
        if request.method == 'POST':
            main_menu = request.form.get('main_menu', '').strip()
            accompaniment = request.form.get('accompaniment', '').strip()
            notes = request.form.get('notes', '').strip()
            image_url = request.form.get('image_url', '').strip()
            file = request.files.get('image_file')
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{today}_" + str(file.filename))
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = url_for('static', filename=f'uploads/{filename}')
            if menu:
                db.execute('UPDATE lunch_menus SET main_menu=?, accompaniment=?, image_url=?, notes=? WHERE date=?',
                           (main_menu, accompaniment, image_url, notes, today))
                flash('Today\'s menu updated!', 'success')
            else:
                db.execute('INSERT INTO lunch_menus (date, main_menu, accompaniment, image_url, notes) VALUES (?, ?, ?, ?, ?)',
                           (today, main_menu, accompaniment, image_url, notes))
                flash('Today\'s menu posted!', 'success')
            db.commit()
            return redirect(url_for('hr_lunch_menu'))
    return render_template('hr/lunch_menu.html', menu=menu, today=today)

@app.route('/chat/upload_file', methods=['POST'])
@login_required
def chat_upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(str(file.filename))
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file_url = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'file_url': file_url}), 200
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', '').strip()
        position = request.form.get('position', '').strip()
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'danger')
            return redirect(url_for('admin_add_user'))
        with get_db() as db:
            existing = db.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
            if existing:
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('admin_add_user'))
            db.execute('INSERT INTO users (username, email, password_hash, role, full_name, department, position) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (username, email, generate_password_hash(password), role, full_name, department, position))
            db.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('admin/user_form.html', action='add')

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_users'))
        if request.method == 'POST':
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            department = request.form.get('department', '').strip()
            position = request.form.get('position', '').strip()
            role = request.form.get('role', user['role'])
            db.execute('UPDATE users SET full_name = ?, email = ?, department = ?, position = ?, role = ? WHERE id = ?',
                       (full_name, email, department, position, role, user_id))
            db.commit()
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin_users'))
    return render_template('admin/user_form.html', action='edit', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    with get_db() as db:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/role/<int:user_id>', methods=['POST'])
@admin_required
def admin_change_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['user', 'hr', 'admin']:
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin_users'))
    with get_db() as db:
        db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        db.commit()
    flash('User role updated.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/management')
@admin_required
def admin_management():
    # Placeholder data for widgets
    with get_db() as db:
        notifications = db.execute('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 5').fetchall()
        lunch_orders = db.execute('SELECT * FROM lunch_orders ORDER BY created_at DESC LIMIT 2').fetchall()
        announcements = db.execute('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 3').fetchall()
    return render_template('admin/management.html', notifications=notifications, lunch_orders=lunch_orders, announcements=announcements)

@app.route('/admin/reports/users')
@admin_required
def admin_user_report():
    with get_db() as db:
        users = db.execute('SELECT username, full_name, email, role, department, position, created_at FROM users ORDER BY created_at DESC').fetchall()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Username', 'Full Name', 'Email', 'Role', 'Department', 'Position', 'Created At'])
    for user in users:
        writer.writerow([user['username'], user['full_name'], user['email'], user['role'], user['department'], user['position'], user['created_at']])
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=users_report.csv'}
    )

@app.route('/admin/reports/users/pdf')
@admin_required
def admin_user_report_pdf():
    with get_db() as db:
        users = db.execute('SELECT username, full_name, email, role, department, position, created_at FROM users ORDER BY created_at DESC').fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    data = [['Username', 'Full Name', 'Email', 'Role', 'Department', 'Position', 'Created At']]
    for user in users:
        data.append([
            user['username'],
            user['full_name'] or '-',
            user['email'],
            user['role'],
            user['department'] or '-',
            user['position'] or '-',
            user['created_at'][:10]
        ])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1e7e34')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements = [table]
    doc.build(elements)
    buffer.seek(0)
    return app.response_class(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment; filename=users_report.pdf'})

@app.route('/admin/reports/lunch_orders')
@admin_required
def admin_lunch_orders_report():
    with get_db() as db:
        orders = db.execute('SELECT lo.id, u.username, u.full_name, lo.dish, lo.notes, lo.status, lo.created_at FROM lunch_orders lo JOIN users u ON lo.user_id = u.id ORDER BY lo.created_at DESC').fetchall()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Order ID', 'Username', 'Full Name', 'Dish', 'Notes', 'Status', 'Created At'])
    for order in orders:
        writer.writerow([order['id'], order['username'], order['full_name'], order['dish'], order['notes'], order['status'], order['created_at']])
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=lunch_orders_report.csv'}
    )

@app.route('/admin/reports/activity')
@admin_required
def admin_activity_log():
    # Placeholder: In a real app, fetch from an activity log table
    logs = [
        {'event': 'User login', 'user': 'admin', 'timestamp': '2024-06-01 09:00'},
        {'event': 'Added new user', 'user': 'admin', 'timestamp': '2024-06-01 09:05'},
        {'event': 'Deleted complaint', 'user': 'admin', 'timestamp': '2024-06-01 09:10'},
    ]
    return render_template('admin/activity_log.html', logs=logs)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    # Placeholder: Add system settings logic here
    return render_template('admin/settings.html')

@app.route('/admin/notifications')
@admin_required
def admin_notifications():
    with get_db() as db:
        notifications = db.execute('SELECT * FROM notifications ORDER BY created_at DESC').fetchall()
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/hr_staff')
@admin_required
def admin_hr_staff():
    with get_db() as db:
        hr_users = db.execute('SELECT * FROM users WHERE role = "hr" ORDER BY created_at DESC').fetchall()
        all_users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('admin/hr_staff.html', hr_users=hr_users, all_users=all_users)

# --- Admin Announcements ---
@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
    with get_db() as db:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            image = request.files.get('image')
            image_filename = None
            if image and image.filename:
                image_filename = f"announcement_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                image.save(os.path.join('static', 'img', image_filename))
            if image_filename:
                content += f'\n<img src="/static/img/{image_filename}" class="img-fluid rounded mt-3" alt="Announcement Image">'
            db.execute(
                'INSERT INTO announcements (title, content, author_id) VALUES (?, ?, ?)',
                (title, content, session['user_id'])
            )
            db.commit()
            flash('Announcement posted successfully!', 'success')
            return redirect(url_for('admin_announcements'))

        # --- Search, Filter, Sort ---
        q = request.args.get('q', '').strip()
        author = request.args.get('author', '').strip()
        sort = request.args.get('sort', 'created_at')
        order = request.args.get('order', 'desc')
        valid_sort = {'created_at', 'title', 'author_name'}
        if sort not in valid_sort:
            sort = 'created_at'
        if order not in {'asc', 'desc'}:
            order = 'desc'

        # Build query
        base_query = '''SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id'''
        where_clauses = []
        params = []
        if q:
            where_clauses.append('(a.title LIKE ? OR a.content LIKE ?)')
            params.extend([f'%{q}%', f'%{q}%'])
        if author:
            where_clauses.append('a.author_id = ?')
            params.append(author)
        where_sql = (' WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''
        order_sql = f' ORDER BY {sort} {order.upper()}'
        query = base_query + where_sql + order_sql
        announcements = db.execute(query, params).fetchall()

        # For author filter dropdown
        authors = db.execute('SELECT DISTINCT u.id, u.full_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY u.full_name').fetchall()

    return render_template('admin/announcements.html', announcements=announcements, q=q, author=author, sort=sort, order=order, authors=authors)

@app.route('/admin/announcements/edit/<int:announcement_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_announcement(announcement_id):
    with get_db() as db:
        announcement = db.execute('SELECT * FROM announcements WHERE id = ?', (announcement_id,)).fetchone()
        if not announcement:
            flash('Announcement not found.', 'danger')
            return redirect(url_for('admin_announcements'))
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            image = request.files.get('image')
            image_filename = None
            if image and image.filename:
                image_filename = f"announcement_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                image.save(os.path.join('static', 'img', image_filename))
            if image_filename:
                content += f'\n<img src="/static/img/{image_filename}" class="img-fluid rounded mt-3" alt="Announcement Image">'
            db.execute('UPDATE announcements SET title=?, content=? WHERE id=?', (title, content, announcement_id))
            db.commit()
            flash('Announcement updated.', 'success')
            return redirect(url_for('admin_announcements'))
    return render_template('admin/announcement_form.html', action='edit', announcement=announcement)

@app.route('/admin/announcements/delete/<int:announcement_id>', methods=['POST'])
@admin_required
def admin_delete_announcement(announcement_id):
    with get_db() as db:
        db.execute('DELETE FROM announcements WHERE id = ?', (announcement_id,))
        db.commit()
    flash('Announcement deleted.', 'success')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/events')
@admin_required
def admin_events():
    return render_template('admin/events.html')

@app.route('/admin/support')
@admin_required
def admin_support():
    return render_template('admin/support.html')

if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('templates/hr', exist_ok=True)
    
    # Run the app with SocketIO
    socketio.run(app, debug=True)