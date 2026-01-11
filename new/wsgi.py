"""
WSGI entry point for production deployment on Render
"""
import os
import sys

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import the Flask app
from app import app

if __name__ == '__main__':
    app.run()
