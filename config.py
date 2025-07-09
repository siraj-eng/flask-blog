"""
Configuration for Flask app, using environment variables if available.
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Flask configuration: secret key, database URI, and SQLAlchemy settings."""
    SECRET_KEY = os.getenv('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False