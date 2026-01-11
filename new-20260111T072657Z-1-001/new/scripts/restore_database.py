#!/usr/bin/env python3
"""
Database Restore Script
Restores the SQLite database from a backup
"""
import sqlite3
import shutil
import os
import sys
import argparse
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')

def list_backups():
    """List all available backups"""
    try:
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('backup_') and f.endswith('.db')])
        
        if not backups:
            logger.info("No backups found.")
            return []
        
        logger.info("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            backup_path = os.path.join(BACKUP_DIR, backup)
            size_mb = os.path.getsize(backup_path) / (1024 * 1024)
            mtime = datetime.fromtimestamp(os.path.getmtime(backup_path)).strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"  {i}. {backup} ({size_mb:.2f} MB) - {mtime}")
        
        return backups
        
    except Exception as e:
        logger.error(f"✗ Failed to list backups: {e}")
        return []

def restore_backup(backup_file):
    """Restore database from backup file"""
    try:
        backup_path = os.path.join(BACKUP_DIR, backup_file)
        
        if not os.path.exists(backup_path):
            logger.error(f"✗ Backup file not found: {backup_path}")
            return False
        
        # Verify backup integrity before restoring
        verify_conn = sqlite3.connect(backup_path)
        verify_conn.close()
        
        # Create safety backup of current database
        if os.path.exists(DATABASE):
            safety_backup = DATABASE + '.pre-restore'
            shutil.copy2(DATABASE, safety_backup)
            logger.info(f"✓ Created safety backup: {safety_backup}")
        
        # Restore from backup
        shutil.copy2(backup_path, DATABASE)
        
        logger.info(f"✓ Database restored successfully from: {backup_file}")
        return True
        
    except Exception as e:
        logger.error(f"✗ Restore failed: {e}")
        return False

def verify_database():
    """Verify restored database integrity"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchone()[0]
        
        # Check data
        cursor.execute("SELECT COUNT(*) FROM users;")
        users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM students;")
        students = cursor.fetchone()[0]
        
        conn.close()
        
        logger.info(f"✓ Database verification passed")
        logger.info(f"  Tables: {tables}")
        logger.info(f"  Users: {users}")
        logger.info(f"  Students: {students}")
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Database verification failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Restore database from backup')
    parser.add_argument('--backup-file', help='Specific backup file to restore from')
    parser.add_argument('--list', action='store_true', help='List available backups')
    
    args = parser.parse_args()
    
    if args.list:
        list_backups()
    elif args.backup_file:
        logger.info(f"Restoring database from: {args.backup_file}")
        if restore_backup(args.backup_file) and verify_database():
            logger.info("✓ Restore process completed successfully")
            sys.exit(0)
        else:
            logger.error("✗ Restore process failed")
            sys.exit(1)
    else:
        logger.info("Use --list to see available backups or --backup-file to restore")
        list_backups()
