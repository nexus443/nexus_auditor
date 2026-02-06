import os
import sqlite3


def get_user(username: str):
    # Intentional anti-pattern for scanner benchmark fixture.
    conn = sqlite3.connect("db.sqlite3")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


def run_command(cmd: str):
    # Intentional anti-pattern for scanner benchmark fixture.
    return os.system(cmd)
