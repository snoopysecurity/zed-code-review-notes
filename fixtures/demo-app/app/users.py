import sqlite3
import subprocess

db = sqlite3.connect("app.db")


def show(user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def ping(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def safe_show(user_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
