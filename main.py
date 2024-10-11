import sqlite3
import hashlib
import os
from flask import (
    Flask, render_template, redirect, request, url_for, flash, session, send_from_directory
)
from werkzeug.utils import secure_filename
from setup import start_db
from check import generate_token, check_token

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your actual secret key
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize the database when the app starts
start_db()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def front_page():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        con = sqlite3.connect('database.db')
        try:
            email = request.form['Email']
            password = request.form['Password']

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            cur = con.cursor()

            # Fetch the user with the provided Email and Password
            cur.execute("SELECT * FROM Users WHERE Email = ? AND Password = ?", (email, hashed_password))
            user = cur.fetchone()
            if not user:
                flash('Invalid email or password.')
                return redirect(url_for('login'))

            session['email'] = user[0]
            session['account_type'] = user[5]

            # Ensure user changes password on first login
            if password == 'password':
                return redirect(url_for('change_password'))

            # Redirect based on account type
            if user[5] == 'Admin':
                return redirect(url_for('admin_main'))
            elif user[5] == 'Manager':
                return redirect(url_for('manager_main'))
            else:
                return redirect(url_for('user_main'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('error.html')
        finally:
            con.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Signup route remains for external signups if needed
    if request.method == 'POST':
        con = sqlite3.connect('database.db')
        try:
            first = request.form['First']
            last = request.form['Last']
            email = request.form['Email']
            company_name = request.form['CompanyName']
            account_type = request.form['AccountType']
            password = 'password'  # Default password

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            cur = con.cursor()

            # Check if the email already exists
            cur.execute("SELECT * FROM Users WHERE Email = ?", (email,))
            existing_user = cur.fetchone()
            if existing_user:
                flash('Email already exists. Please use a different email.')
                return redirect(url_for('signup'))

            # Insert the new user into the database
            cur.execute("""
                INSERT INTO Users (Email, First, Last, CompanyName, Password, AccountType)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, first, last, company_name, hashed_password, account_type))
            con.commit()

            flash('Account created successfully! Please log in with the default password and change it immediately.')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('error.html')
        finally:
            con.close()
    return render_template('signup.html')

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if session.get('account_type') not in ['Admin', 'Manager']:
        return redirect(url_for('login'))

    if request.method == 'POST':
        con = sqlite3.connect('database.db')
        try:
            first = request.form['First']
            last = request.form['Last']
            email = request.form['Email']
            company_name = request.form['CompanyName']
            account_type = request.form['AccountType']
            password = 'password'  # Default password

            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            cur = con.cursor()

            # Check if the email already exists
            cur.execute("SELECT * FROM Users WHERE Email = ?", (email,))
            existing_user = cur.fetchone()
            if existing_user:
                flash('Email already exists. Please use a different email.')
                return redirect(url_for('create_user'))

            # Insert the new user into the database
            cur.execute("""
                INSERT INTO Users (Email, First, Last, CompanyName, Password, AccountType)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, first, last, company_name, hashed_password, account_type))
            con.commit()

            flash('User account created successfully!')
            return redirect(url_for('create_user'))
        except Exception as e:
            print(f"Error: {e}")
            flash('An error occurred while creating the user.')
            return redirect(url_for('create_user'))
        finally:
            con.close()
    return render_template('create_user.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['NewPassword']
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()

        con = sqlite3.connect('database.db')
        try:
            cur = con.cursor()
            cur.execute("UPDATE Users SET Password = ? WHERE Email = ?", (hashed_password, session['email']))
            con.commit()
            flash('Password changed successfully.')
            return redirect(url_for('front_page'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('error.html')
        finally:
            con.close()
    return render_template('change_password.html')

@app.route('/admin_main')
def admin_main():
    if session.get('account_type') != 'Admin':
        return redirect(url_for('login'))
    return render_template('admin_main.html')

@app.route('/manager_main')
def manager_main():
    if session.get('account_type') != 'Manager':
        return redirect(url_for('login'))
    return render_template('manager_main.html')

@app.route('/user_main')
def user_main():
    if session.get('account_type') != 'User':
        return redirect(url_for('login'))
    return render_template('user_main.html')

@app.route('/view_account', methods=['GET'])
def view_account():
    if 'email' not in session:
        return redirect(url_for('login'))

    con = sqlite3.connect('database.db')
    try:
        cur = con.cursor()
        cur.execute("SELECT First, Last, CompanyName, Email FROM Users WHERE Email = ?", (session['email'],))
        user_info = cur.fetchone()
    except Exception as e:
        print(f"Error: {e}")
        return render_template('error.html')
    finally:
        con.close()
    return render_template('view_account.html', user_info=user_info)

@app.route('/edit_account', methods=['GET', 'POST'])
def edit_account():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        first = request.form['First']
        last = request.form['Last']
        company_name = request.form['CompanyName']
        email = request.form['Email']

        con = sqlite3.connect('database.db')
        try:
            cur = con.cursor()
            cur.execute("""
                UPDATE Users SET First = ?, Last = ?, CompanyName = ?, Email = ?
                WHERE Email = ?
            """, (first, last, company_name, email, session['email']))
            con.commit()
            session['email'] = email  # Update session email if changed
            flash('Account information updated successfully.')
            return redirect(url_for('view_account'))
        except Exception as e:
            print(f"Error: {e}")
            return render_template('error.html')
        finally:
            con.close()

    # GET request handling
    con = sqlite3.connect('database.db')
    try:
        cur = con.cursor()
        cur.execute("SELECT First, Last, CompanyName, Email FROM Users WHERE Email = ?", (session['email'],))
        user_info = cur.fetchone()
    except Exception as e:
        print(f"Error: {e}")
        return render_template('error.html')
    finally:
        con.close()
    return render_template('edit_account.html', user_info=user_info)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/view_users')
def view_users():
    if session.get('account_type') != 'Admin':
        return redirect(url_for('login'))

    con = sqlite3.connect('database.db')
    try:
        cur = con.cursor()
        cur.execute("SELECT Email, First, Last, CompanyName, AccountType FROM Users")
        users = cur.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        return render_template('error.html')
    finally:
        con.close()
    return render_template('view_users.html', users=users)

@app.route('/upload_files', methods=['GET', 'POST'])
def upload_files():
    if session.get('account_type') not in ['Admin', 'Manager']:
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form['Email']
        files = request.files.getlist('Files')

        # Create user-specific upload directory
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], email)
        os.makedirs(user_upload_folder, exist_ok=True)

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(user_upload_folder, filename))

        flash('Files uploaded successfully.')
        return redirect(url_for('upload_files'))

    con = sqlite3.connect('database.db')
    try:
        cur = con.cursor()
        cur.execute("SELECT Email, CompanyName FROM Users")
        users = cur.fetchall()
    except Exception as e:
        print(f"Error: {e}")
        return render_template('error.html')
    finally:
        con.close()
    return render_template('upload_files.html', users=users)

@app.route('/view_files')
def view_files():
    if 'email' not in session:
        return redirect(url_for('login'))

    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['email'])
    if not os.path.exists(user_upload_folder):
        files = []
    else:
        files = os.listdir(user_upload_folder)
    return render_template('view_files.html', files=files)

@app.route('/download_file/<filename>')
def download_file(filename):
    if 'email' not in session:
        return redirect(url_for('login'))

    user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['email'])
    return send_from_directory(user_upload_folder, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
