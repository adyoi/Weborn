import sqlite3
conn = sqlite3.connect("data/weborn.db")
conn.row_factory = sqlite3.Row
for r in conn.execute("SELECT id, username, role FROM users"):
    print(dict(r))
conn.close()
