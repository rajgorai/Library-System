import sqlite3

conn = sqlite3.connect('online_library.db')
conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
conn.execute("UPDATE users SET email = 'raj@example.com' WHERE username = 'Raj'")
conn.execute("UPDATE users SET email = 'jeet@example.com' WHERE username = 'Jeet'")
conn.execute("UPDATE users SET email = 'rajat@example.com' WHERE username = 'Rajat'")
conn.commit()
conn.close()
print('Database updated with email column and sample emails.')
