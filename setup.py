import sqlite3
import os

def start_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create the User table with Email as the primary key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            Email TEXT PRIMARY KEY,
            First TEXT,
            Last TEXT,
            CompanyName TEXT,
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
            Email TEXT,
            FOREIGN KEY (Email) REFERENCES Users (Email)
        )
    ''')

    conn.commit()
    cursor.close()
    conn.close()
    
    # Folder creation logic
    base_upload_folder = 'uploads'
    folders = ['admin', 'managers', 'users']

    # Create base upload folder and subfolders if they don't exist
    if not os.path.exists(base_upload_folder):
        os.makedirs(base_upload_folder)

    for folder in folders:
        folder_path = os.path.join(base_upload_folder, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)