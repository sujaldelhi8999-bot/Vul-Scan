-- Migration: Add private_scope table for Admin Private Scope Override
-- This table stores URLs that Admin users have overridden,
-- bypassing DNS/HTTP ownership verification.

CREATE TABLE IF NOT EXISTS private_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT UNIQUE NOT NULL,
    added_by TEXT DEFAULT 'admin',
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used TEXT
);

CREATE INDEX IF NOT EXISTS idx_private_scope_target_url ON private_scope (target_url);
