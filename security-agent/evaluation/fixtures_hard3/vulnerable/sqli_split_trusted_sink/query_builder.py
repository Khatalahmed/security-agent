"""Builds a SQL string. In isolation this is 'just string formatting'."""


def build_lookup(username):
    # Assemble the user-lookup SQL from the given name.
    return "SELECT id, email FROM users WHERE name = '" + username + "'"
