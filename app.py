from flask import Flask, render_template, request, redirect, url_for, flash, session, g
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

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'b6cf94b299a1f56d63199b2298f7095c3ee344bd1bb1a77cfd6e03d4a2b95b71'
app.config['DATABASE'] = 'hr_system.db'

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# Database Helper Functions
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
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
        
        db.commit()
        print("✅ Database tables created successfully.")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        db.rollback()
        raise e
    finally:
        db.close()

def initialize_database():
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
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
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
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

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
                return redirect(url_for('admin_dashboard'))
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
    with get_db() as db:
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
    
    return render_template('dashboard.html', announcements=announcements)

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
    return render_template('admin/dashboard.html', 
                         user_count=user_count,
                         recent_users=recent_users,
                         announcements=announcements,
                         lunch_orders=lunch_orders)

@app.route('/admin/users')
@admin_required
def admin_users():
    with get_db() as db:
        users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('admin/users.html', users=users)

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
        announcements = db.execute(
            'SELECT a.*, u.full_name as author_name FROM announcements a JOIN users u ON a.author_id = u.id ORDER BY a.created_at DESC LIMIT 5'
        ).fetchall()
        employees = db.execute(
            'SELECT id, full_name, department, position FROM users WHERE role = "user" ORDER BY full_name'
        ).fetchall()
    
    return render_template('hr/dashboard.html', 
                         announcements=announcements,
                         employees=employees)

@app.route('/submit_lunch_order', methods=['POST'])
@login_required
def submit_lunch_order():
    dish = request.form.get('dish', '').strip()
    notes = request.form.get('notes', '').strip()
    if not dish:
        flash('Please enter your lunch order.', 'danger')
        return redirect(url_for('dashboard'))
    with get_db() as db:
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
    return render_template('chat.html')

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
    emit('receive_message', {'username': 'System', 'message': f'{session.get("full_name", session.get("username"))} joined the room.'}, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data.get('room')
    leave_room(room)
    emit('receive_message', {'username': 'System', 'message': f'{session.get("full_name", session.get("username"))} left the room.'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    username = data.get('username')
    message = data.get('message')
    user_id = session.get('user_id')
    room = data.get('room')
    # Store message in DB (public room for now)
    with get_db() as db:
        db.execute('INSERT INTO chat_messages (user_id, username, message) VALUES (?, ?, ?)', (user_id, username, message))
        db.commit()
    if room:
        emit('receive_message', {'username': username, 'message': message}, room=room)
    else:
        emit('receive_message', {'username': username, 'message': message}, broadcast=True)

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

if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('templates/hr', exist_ok=True)
    
    # Run the app with SocketIO
    socketio.run(app, debug=True)