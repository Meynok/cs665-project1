import sqlite3
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


def get_db_connection():
    connection = sqlite3.connect('fake_db.db')
    connection.row_factory = sqlite3.Row
    return connection


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        error_message = None

        if not username:
            error_message = 'Username is required.'
        elif not email:
            error_message = 'Email is required.'
        elif not password:
            error_message = 'Password is required.'

        if error_message is None:
            connection = get_db_connection()
            try:
                # Hash the password for security
                hashed_password = generate_password_hash(password)
                current_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                connection.execute(
                    'INSERT INTO users (user_id, username, email, password_hash, date_created) \
                        VALUES (NULL, ?, ?, ?, ?)',
                    (username, email, hashed_password, current_timestamp)
                )
                connection.commit()
                flash('Registration successful! You can now log in.')
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                error_message = f'User {username} or Email {email} is already registered.'
            finally:
                connection.close()

        flash(error_message)

    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)