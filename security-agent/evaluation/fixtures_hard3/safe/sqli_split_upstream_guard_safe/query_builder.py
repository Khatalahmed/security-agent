"""Unchanged from the vuln twin - still concatenates, so it looks like SQLi in
isolation. Safe only because app.py guarantees `username` is alphanumeric."""


def build_lookup(username):
    return "SELECT id, email FROM users WHERE name = '" + username + "'"
