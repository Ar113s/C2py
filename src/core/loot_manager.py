#!/usr/bin/env python3
"""
Loot Manager for C2PY Framework
Handles storage and retrieval of collected loot from agents.
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path

class LootManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS loot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                hostname TEXT,
                loot_type TEXT NOT NULL,
                content TEXT,
                source TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def add_loot(self, agent_id: int, hostname: str, loot_type: str, content: str, source: str):
        """Add a new piece of loot to the database."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO loot (agent_id, hostname, loot_type, content, source, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, hostname, loot_type, content, source, datetime.now())
            )
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            print(f"Error adding loot: {e}")
            return None

    def get_all_loot(self):
        """Retrieve all loot from the database."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, agent_id, hostname, loot_type, content, source, timestamp FROM loot ORDER BY timestamp DESC")
        return cursor.fetchall()

    def get_loot_by_type(self, loot_type: str):
        """Retrieve loot of a specific type."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, agent_id, hostname, loot_type, content, source, timestamp FROM loot WHERE loot_type = ? ORDER BY timestamp DESC", (loot_type,))
        return cursor.fetchall()

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()