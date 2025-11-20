import sqlite3
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


def get_db_connection():
    """
    Establishes a connection to the SQLite database.

    Returns:
        sqlite3.Connection: A connection object with row_factory set to sqlite3.Row
        to allow accessing columns by name.
    """
    connection = sqlite3.connect('fake_db.db')
    connection.row_factory = sqlite3.Row
    return connection


@app.route('/')
def index():
    """
    Renders the home page.
    """
    return render_template('index.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    """
    Handles user registration.

    GET: Renders the registration form.
    POST: Validates input, hashes the password, and creates a new user in the database.
    """
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
                hashed_password = generate_password_hash(password)
                current_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                connection.execute(
                    'INSERT INTO users (user_id, username, email, password_hash, date_created) \
                        VALUES (NULL, ?, ?, ?, ?)',
                    (username, email, hashed_password, current_timestamp)
                )
                connection.commit()
                flash('Registration successful! You can now log in.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error_message = f'User {username} or Email {email} is already registered.'
            finally:
                connection.close()

        flash(error_message)

    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    """
    Handles user authentication.

    GET: Renders the login form.
    POST: Verifies email and password. If valid, creates a session for the user.
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        error_message = None

        connection = get_db_connection()
        user = connection.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        connection.close()

        if user is None:
            error_message = 'Incorrect email.'
        elif not check_password_hash(user['password_hash'], password):
            error_message = 'Incorrect password.'

        if error_message is None:
            session.clear()
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            flash(f"Welcome back, {user['username']}!")
            return redirect(url_for('dashboard'))

        flash(error_message)

    return render_template('login.html')


@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session and redirects to the home page.
    """
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """
    Renders the user dashboard.

    Fetches and displays all projects where the logged-in user is a member.
    Redirects to login if the user is not authenticated.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    # Fetch projects the user belongs to by joining projects and project_members
    projects = connection.execute(
        '''
        SELECT p.*, pm.role
        FROM projects p
        JOIN project_members pm ON p.project_id = pm.project_id
        WHERE pm.user_id = ?
        ''',
        (user_id,)
    ).fetchall()

    connection.close()
    return render_template('dashboard.html', projects=projects)


@app.route('/create_project', methods=('GET', 'POST'))
def create_project():
    """
    Handles creation of a new project.

    GET: Renders the project creation form.
    POST: Inserts the new project into the database and adds the creator as an Admin member.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        project_name = request.form['project_name']
        description = request.form['description']
        user_id = session['user_id']

        if not project_name:
            flash('Project name is required.')
        else:
            connection = get_db_connection()
            current_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Insert the project
            cursor = connection.execute(
                'INSERT INTO projects (project_name, description, owner_id, created_at) VALUES (?, ?, ?, ?)',
                (project_name, description, user_id, current_timestamp)
            )

            # Get the new project's ID
            new_project_id = cursor.lastrowid

            # Add the creator as a member with role 'Admin'
            connection.execute(
                'INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)',
                (new_project_id, user_id, 'Admin')
            )

            connection.commit()
            connection.close()
            flash('Project created successfully!')
            return redirect(url_for('dashboard'))

    return render_template('create_project.html')


if __name__ == '__main__':
    app.run(debug=True)
