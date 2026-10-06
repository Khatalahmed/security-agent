"""Unchanged data-access helper; looks like it runs arbitrary SQL."""
import sqlite3


def run_query(sql):
    return sqlite3.connect("app.db").execute(sql).fetchall()
