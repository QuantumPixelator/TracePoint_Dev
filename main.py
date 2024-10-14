
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
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def front_page():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    admin_exists = False
    con = sqlite3.connect('database.db')
    try:
        # Check if an admin already exists in the database
        cur = con.cursor()
        cur.execute("SELECT * FROM Users WHERE AccountType = 'Admin'")
        admin = cur.fetchone()

        # Set flag to true if an admin exists
        if admin:
            admin_exists = True

        if request.method == 'POST':
            email = request.form['Email']
            password = request.form['Password']
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Fetch the user with the provided Email and Password
            cur.execute("SELECT * FROM Users WHERE Email = ? AND Password = ?", (email, hashed_password))
            user = cur.fetchone()
            if not user:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))

            session['email'] = user[0]
            session['account_type'] = user[5]

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

    # Pass the admin_exists flag to the template
    return render_template('login.html', admin_exists=admin_exists)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
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
                flash('Email already exists. Please use a different email.', 'danger')
                return redirect(url_for('signup'))

            # Insert the new user into the database
            cur.execute(
                "INSERT INTO Users (Email, First, Last, CompanyName, Password, AccountType) VALUES (?, ?, ?, ?, ?, ?)",
                (email, first, last, company_name, hashed_password, account_type)
            )
            con.commit()

            flash('Account created successfully! Please log in with the default password and change it immediately.', 'success')
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
        return redirect(url_for('access_denied'))

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
                flash('Email already exists. Please use a different email.', 'danger')
                return redirect(url_for('create_user'))

            # Insert the new user into the database
            cur.execute(
                "INSERT INTO Users (Email, First, Last, CompanyName, Password, AccountType) VALUES (?, ?, ?, ?, ?, ?)",
                (email, first, last, company_name, hashed_password, account_type)
            )
            con.commit()

            flash('User account created successfully!', 'success')
            return redirect(url_for('create_user'))
        except Exception as e:
            print(f"Error: {e}")
            flash('An error occurred while creating the user.')
            return redirect(url_for('create_user'))
        finally:
            con.close()
    return render_template('create_user.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_main')
def admin_main():
    if session.get('account_type') != 'Admin':
        return redirect(url_for('access_denied'))
    return render_template('admin_main.html')

@app.route('/manager_main')
def manager_main():
    if session.get('account_type') != 'Manager':
        return redirect(url_for('access_denied'))
    return render_template('manager_main.html')

@app.route('/user_main')
def user_main():
    if 'email' not in session:
        return redirect(url_for('access_denied'))
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
            cur.execute(
                "UPDATE Users SET First = ?, Last = ?, CompanyName = ?, Email = ? WHERE Email = ?",
                (first, last, company_name, email, session['email'])
            )
            con.commit()
            session['email'] = email  # Update session email if changed
            flash('Account information updated successfully.', 'success')
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

@app.route('/view_files/<path:subpath>', methods=['GET', 'POST'])
@app.route('/view_files/', defaults={'subpath': ''}, methods=['GET', 'POST'])
def view_files(subpath):
    if 'email' not in session:
        return redirect(url_for('access_denied'))
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], subpath)

    # Handle folder creation
    if request.method == 'POST':
        folder_name = request.form.get('folder_name')
        if folder_name:
            new_folder_path = os.path.join(full_path, folder_name)
            try:
                os.makedirs(new_folder_path)
                flash('Folder created successfully!', 'success')
            except OSError as e:
                flash(f'Error creating folder: {e}', 'danger')

    # Get folder and file list
    try:
        items = os.listdir(full_path)
        folders = [item for item in items if os.path.isdir(os.path.join(full_path, item))]
        files = [item for item in items if os.path.isfile(os.path.join(full_path, item))]
    except FileNotFoundError:
        flash('The specified path does not exist.', 'danger')
        return redirect(url_for('view_files'))

    return render_template('view_files.html', subpath=subpath, folders=folders, files=files)

@app.route('/upload_files', methods=['GET', 'POST'])
@app.route('/upload_files/<path:subpath>', methods=['GET', 'POST'])
def upload_file(subpath=''):
    if 'email' not in session:
        return redirect(url_for('access_denied'))
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], subpath)

    # Ensure the directory exists
    try:
        if not os.path.exists(full_path):
            os.makedirs(full_path)
    except OSError as e:
        flash(f'Error creating directory: {e}', 'danger')
        return redirect(request.url)

    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part in the request', 'danger')
            return redirect(request.url)
        file = request.files['file']
        # If user does not select a file, browser also submits an empty part without filename
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            try:
                file.save(os.path.join(full_path, filename))
                flash('File successfully uploaded', 'success')
            except Exception as e:
                flash(f'Error saving file: {e}', 'danger')
            return redirect(url_for('view_files', subpath=subpath))

    return render_template('upload_files.html', subpath=subpath)

@app.route('/access_denied')
def access_denied():
    return render_template('access_denied.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['Email']
        # Placeholder for sending reset link functionality
        flash('A password reset link has been sent to your email.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['NewPassword']
        confirm_password = request.form['ConfirmPassword']
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))

        # Placeholder for updating the password in the database
        flash('Your password has been successfully reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
