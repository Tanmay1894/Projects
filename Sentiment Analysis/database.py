import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('sentiment_analysis.db')

# Create a cursor object to execute SQL commands
cursor = conn.cursor()


cursor.execute('''
    CREATE TABLE IF NOT EXISTS sentiment_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        sentiment TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')


conn.commit()
conn.close()

print("Database and table created successfully.")
