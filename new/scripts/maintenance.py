#!/usr/bin/env python3
"""
Database Maintenance Script
Performs regular maintenance tasks on the database
"""
import sqlite3
import os
import sys
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')

def get_db_connection():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def vacuum_database():
    """Vacuum database to optimize space"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor.execute("VACUUM;")
        conn.commit()
        conn.close()
        
        logger.info("✓ Database vacuum completed successfully")
        return True
        
    except sqlite3.Error as e:
        logger.error(f"✗ Database vacuum failed: {e}")
        return False

def cleanup_expired_tokens():
    """Remove expired password reset tokens"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        
        cursor.execute("DELETE FROM password_reset_tokens WHERE expires_at < ?", (current_time,))
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        logger.info(f"✓ Cleaned up {deleted_count} expired password reset tokens")
        return True
        
    except sqlite3.Error as e:
        logger.error(f"✗ Token cleanup failed: {e}")
        return False

def archive_old_audit_logs(days=90):
    """Archive audit logs older than specified days"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Count records before archiving
        cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp < ?", (cutoff_date,))
        count = cursor.fetchone()[0]
        
        # Delete old audit logs
        cursor.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_date,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✓ Archived {count} audit logs older than {days} days")
        return True
        
    except sqlite3.Error as e:
        logger.error(f"✗ Audit log archiving failed: {e}")
        return False

def rebuild_indices():
    """Rebuild database indices for better performance"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor.execute("REINDEX;")
        conn.commit()
        conn.close()
        
        logger.info("✓ Database indices rebuilt successfully")
        return True
        
    except sqlite3.Error as e:
        logger.error(f"✗ Index rebuild failed: {e}")
        return False

def check_database_integrity():
    """Check database for corruption"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        result = cursor.fetchone()[0]
        
        conn.close()
        
        if result == 'ok':
            logger.info("✓ Database integrity check passed")
            return True
        else:
            logger.error(f"✗ Database integrity issue detected: {result}")
            return False
            
    except sqlite3.Error as e:
        logger.error(f"✗ Integrity check failed: {e}")
        return False

def get_database_stats():
    """Get database statistics"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        
        # Get table counts
        cursor.execute("SELECT COUNT(*) FROM users;")
        users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM students;")
        students = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM teachers;")
        teachers = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM clinic_visits;")
        visits = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM audit_log;")
        logs = cursor.fetchone()[0]
        
        conn.close()
        
        logger.info("\n=== Database Statistics ===")
        logger.info(f"Users: {users}")
        logger.info(f"Students: {students}")
        logger.info(f"Teachers: {teachers}")
        logger.info(f"Clinic Visits: {visits}")
        logger.info(f"Audit Logs: {logs}")
        logger.info(f"Database File Size: {os.path.getsize(DATABASE) / (1024*1024):.2f} MB")
        
        return True
        
    except sqlite3.Error as e:
        logger.error(f"✗ Statistics retrieval failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("Starting database maintenance...")
    
    # Run all maintenance tasks
    all_success = True
    
    all_success &= check_database_integrity()
    all_success &= cleanup_expired_tokens()
    all_success &= archive_old_audit_logs()
    all_success &= rebuild_indices()
    all_success &= vacuum_database()
    all_success &= get_database_stats()
    
    if all_success:
        logger.info("\n✓ Database maintenance completed successfully")
        sys.exit(0)
    else:
        logger.error("\n✗ Some maintenance tasks failed")
        sys.exit(1)
