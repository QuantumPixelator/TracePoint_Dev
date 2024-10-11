import sqlite3

def start_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create the User table with Email as the primary key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            Email TEXT PRIMARY KEY,
            First TEXT,
            Last TEXT,
            Password TEXT,
            AccountType TEXT
        )
    ''')

    # Create the Files table, which references Email
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Files (
            FileId INTEGER PRIMARY KEY AUTOINCREMENT,
            FileName TEXT,
            FileData BLOB,
            Email TEXT
        )
    ''')

    conn.commit()
    cursor.close()
