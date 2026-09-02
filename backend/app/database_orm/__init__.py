"""Future PostgreSQL/SQLAlchemy migration infrastructure.

The active runtime database for the current application is the SQLite layer in
``app.database``. This package is intentionally retained for a future
PostgreSQL migration, but it is not imported by ``main.py`` or used as runtime
persistence today.
"""

from app.database_orm.base import Base
from app.database_orm.connection import (
    DatabaseManager,
    db_manager,
    get_db_session,
    initialize_database,
    shutdown_database,
)

__all__ = [
    "Base",
    "DatabaseManager",
    "db_manager",
    "get_db_session",
    "initialize_database",
    "shutdown_database",
]
