from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'b6cf94b299a1f56d63199b2298f7095c3ee344bd1bb1a77cfd6e03d4a2b95b71'
app.config['DATABASE'] = 'hr_system.db'

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
    
    return render_template('admin/dashboard.html', 
                         user_count=user_count,
                         recent_users=recent_users,
                         announcements=announcements)

@app.route('/admin/users')
@admin_required
def admin_users():
    with get_db() as db:
        users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('admin/users.html', users=users)

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

if __name__ == '__main__':
    # Create required directories if they don't exist
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('templates/hr', exist_ok=True)
    
    # Run the app
    app.run(debug=True)