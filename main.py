import sqlite3
from flask import Flask, render_template, redirect, request, make_response, url_for, flash, send_file, session
from io import BytesIO
from werkzeug.utils import secure_filename
import hashlib
import logging
from setup import start_db
from check import generate_token, check_token

UPLOAD_FOLDER = '/home/poisoniv/Code/COP4521/Project1/files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

logging.basicConfig(level=logging.DEBUG)
user = ['']

# Initialize the database when the app starts
start_db()

@app.route('/')
def front_page():
    return render_template('Login.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        con = sqlite3.connect('database.db')
        try:
            Email = request.form['Email']
            Password = request.form['Password']

            hashed_password = hashlib.sha256(
                Password.encode()).hexdigest()

            cur = con.cursor()

            # Fetch the user with the provided Email and Password
            cur.execute("SELECT * FROM Users WHERE Email = ? AND Password = ?", (Email, hashed_password))
            rows = cur.fetchall()
            if len(rows) == 0:
                return render_template("NoMatchingUser.html")

            # Ensure user changes password on first login
            if rows[0][3] == 'password':
                return redirect(url_for('change_password', user_id=rows[0][0]))

            token = generate_token(Email)
            user[0] = rows[0][0]

            # Redirect based on account type
            if rows[0][4] == 'Admin':
                return redirect(url_for('admin_main'))
            elif rows[0][4] == 'Manager':
                return redirect(url_for('manager_main'))
            else:
                return redirect(url_for('user_main'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('Error.html')
        finally:
            con.close()

    return render_template('Login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        con = sqlite3.connect('database.db')
        try:
            Email = request.form['Email']
            Password = 'password'  # Default password
            AccountType = request.form['AccountType']

            hashed_password = hashlib.sha256(Password.encode()).hexdigest()

            cur = con.cursor()

            # Check if the email already exists
            cur.execute("SELECT * FROM Users WHERE Email = ?", (Email,))
            existing_user = cur.fetchone()
            if existing_user:
                flash('Email already exists. Please use a different email.')
                return redirect(url_for('signup'))

            # Insert the new user into the database
            cur.execute("INSERT INTO Users (Email, Password, AccountType) VALUES (?, ?, ?)", (Email, hashed_password, AccountType))
            con.commit()

            flash('Account created successfully! Please log in with the default password and change it immediately.')
            return redirect(url_for('front_page'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('Error.html')
        finally:
            con.close()

    return render_template('SignUp.html')

@app.route('/admin_main')
def admin_main():
    return render_template('AdminMainPage.html')

@app.route('/manager_main')
def manager_main():
    return render_template('ManagerMainPage.html')

@app.route('/user_main')
def user_main():
    return render_template('UserMainPage.html')

if __name__ == '__main__':
    app.run(debug=True)
