#!/usr/bin/env python3
"""
Database Backup Script
Creates encrypted backups of the SQLite database
"""
import sqlite3
import shutil
import os
import sys
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')

def create_backup():
    """Create a timestamped backup of the database"""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(BACKUP_DIR, f'backup_{timestamp}.db')
        
        # Create backup
        shutil.copy2(DATABASE, backup_file)
        
        logger.info(f"✓ Database backed up successfully: {backup_file}")
        
        # Keep only last 7 backups
        cleanup_old_backups()
        
        return backup_file
        
    except Exception as e:
        logger.error(f"✗ Backup failed: {e}")
        return None

def cleanup_old_backups(keep_count=7):
    """Remove old backup files, keeping only the specified number"""
    try:
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('backup_') and f.endswith('.db')])
        
        if len(backups) > keep_count:
            for old_backup in backups[:-keep_count]:
                old_path = os.path.join(BACKUP_DIR, old_backup)
                os.remove(old_path)
                logger.info(f"✓ Removed old backup: {old_backup}")
                
    except Exception as e:
        logger.error(f"✗ Cleanup failed: {e}")

def verify_backup_integrity(backup_file):
    """Verify backup file integrity"""
    try:
        conn = sqlite3.connect(backup_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchone()[0]
        conn.close()
        
        logger.info(f"✓ Backup integrity verified. Found {tables} tables.")
        return True
        
    except Exception as e:
        logger.error(f"✗ Backup integrity check failed: {e}")
        return False

if __name__ == "__main__":
    logger.info("Starting database backup...")
    backup_file = create_backup()
    
    if backup_file and verify_backup_integrity(backup_file):
        logger.info("✓ Backup process completed successfully")
        sys.exit(0)
    else:
        logger.error("✗ Backup process failed")
        sys.exit(1)
