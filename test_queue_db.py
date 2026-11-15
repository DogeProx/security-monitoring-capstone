import sqlite3

conn = sqlite3.connect("queue_test.db")

tables = conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Các bảng trong database:")
for table in tables:
    print("-", table[0])

conn.close()