"""Data-access helper; docstring claims the SQL is internally built."""
import sqlite3


def run_query(sql):
    # Execute a prepared statement. `sql` is expected to be built internally.
    return sqlite3.connect("app.db").execute(sql).fetchall()   # SINK (opaque arg)
