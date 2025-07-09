"""
Database connection helper for SQLite in Flask context.
"""
import sqlite3
from flask import current_app

def get_db():
    """Return a SQLite connection using Flask's current_app config."""
    db = sqlite3.connect(current_app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db 