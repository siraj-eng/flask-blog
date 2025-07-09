"""
SQLAlchemy models for User and Post (legacy, not used in main app.py but kept for reference).
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    """User model for authentication and user data."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)  # Unique username
    email = db.Column(db.String(120), unique=True, nullable=False)    # Unique email
    password = db.Column(db.String(60), nullable=False)               # Hashed password
    posts = db.relationship('Post', backref='author', lazy=True)      # Relationship to posts (legacy)

class Post(db.Model):
    """Blog post model (legacy, not used in HR system)."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)                 # Post title
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Date posted
    content = db.Column(db.Text, nullable=False)                      # Post content
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)      # Author reference