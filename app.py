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
                    'INSERT INTO users (user_id, username, email, password_hash, date_created, is_admin) \
                        VALUES (NULL, ?, ?, ?, ?, 0)',
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
            session['is_admin'] = user['is_admin']
            flash(f"Welcome back, {user['username']}!")

            if user['is_admin'] == 1:
                return redirect(url_for('admin_dashboard'))
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

    # Fetch projects
    if session.get('is_admin') == 1:
        projects = connection.execute('SELECT *, "Admin Access" as role FROM projects').fetchall()
    else:
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


@app.route('/admin')
def admin_dashboard():
    """
    Renders the special Admin Dashboard with global stats and lists.
    """
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))

    connection = get_db_connection()
    users = connection.execute('SELECT * FROM users').fetchall()
    projects = connection.execute('SELECT * FROM projects').fetchall()
    tasks = connection.execute('SELECT * FROM tasks').fetchall()
    connection.close()

    return render_template('admin.html', users=users, projects=projects, tasks=tasks)


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


@app.route('/project/<int:project_id>')
def view_project(project_id):
    """
    Displays details for a specific project, including its tasks.

    Validates that the current user is a member of the project before showing data.
    Fetches tasks and joins with the users table to show assignee names.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    # Security check to ensure the user is a member of this project or an admin
    member = connection.execute(
        'SELECT * FROM project_members WHERE project_id = ? AND user_id = ?',
        (project_id, user_id)
    ).fetchone()

    if member is None and session.get('is_admin') != 1:
        connection.close()
        flash('You do not have permission to view this project.')
        return redirect(url_for('dashboard'))

    # Fetch project details
    project = connection.execute(
        'SELECT * FROM projects WHERE project_id = ?',
        (project_id,)
    ).fetchone()

    # Fetch tasks (Left join to get assignee name even if task is unassigned)
    tasks = connection.execute(
        '''
        SELECT t.*, u.username as assignee_name
        FROM tasks t
        LEFT JOIN users u ON t.assignee_id = u.user_id
        WHERE t.project_id = ?
        ''',
        (project_id,)
    ).fetchall()
    connection.close()
    return render_template('project_details.html', project=project, tasks=tasks)


@app.route('/project/<int:project_id>/create_task', methods=('GET', 'POST'))
def create_task(project_id):
    """
    Handles the creation of a new task within a specific project.

    GET: Renders the task creation form with a list of potential assignees (project members).
    POST: Validates input and inserts the new task into the database.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    # Ensure user is a member of the project or is admin
    member = connection.execute(
        'SELECT * FROM project_members WHERE project_id = ? AND user_id = ?',
        (project_id, user_id)
    ).fetchone()

    if member is None and session.get('is_admin') != 1:
        connection.close()
        flash('You do not have permission to add tasks to this project.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        task_title = request.form['task_title']
        description = request.form['description']
        assignee_id = request.form['assignee_id']
        due_date = request.form['due_date']
        status = request.form['status']

        if not task_title:
            flash('Task title is required.')
        else:
            connection.execute(
                'INSERT INTO tasks (project_id, assignee_id, task_title, description, status, due_date) \
                 VALUES (?, ?, ?, ?, ?, ?)',
                (project_id, assignee_id if assignee_id else None, task_title, description, status, due_date)
            )
            connection.commit()
            connection.close()
            flash('Task created successfully!')
            return redirect(url_for('view_project', project_id=project_id))

    # Fetch project members to populate the "Assignee" dropdown
    members = connection.execute(
        '''
        SELECT u.user_id, u.username
        FROM users u
        JOIN project_members pm ON u.user_id = pm.user_id
        WHERE pm.project_id = ?
        ''',
        (project_id,)
    ).fetchall()

    connection.close()
    return render_template('create_task.html', project_id=project_id, members=members)


@app.route('/task/<int:task_id>/edit', methods=('GET', 'POST'))
def edit_task(task_id):
    """
    Handles editing an existing task.

    GET: Renders the edit form pre-filled with task data.
    POST: Updates the task details in the database.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    task = connection.execute('SELECT * FROM tasks WHERE task_id = ?', (task_id,)).fetchone()

    if task is None:
        connection.close()
        return "Task not found", 404

    project_id = task['project_id']

    # Ensure user is a member of the project or is admin
    member = connection.execute(
        'SELECT * FROM project_members WHERE project_id = ? AND user_id = ?',
        (project_id, user_id)
    ).fetchone()

    if member is None and session.get('is_admin') != 1:
        connection.close()
        flash('You do not have permission to edit this task.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        task_title = request.form['task_title']
        description = request.form['description']
        assignee_id = request.form['assignee_id']
        status = request.form['status']
        due_date = request.form['due_date']

        if not task_title:
            flash('Task title is required.')
        else:
            connection.execute(
                '''
                UPDATE tasks
                SET task_title = ?, description = ?, assignee_id = ?, status = ?, due_date = ?
                WHERE task_id = ?
                ''',
                (task_title, description, assignee_id if assignee_id else None, status, due_date, task_id)
            )
            connection.commit()
            connection.close()
            flash('Task updated successfully!')
            return redirect(url_for('view_project', project_id=project_id))

    members = connection.execute(
        '''
        SELECT u.user_id, u.username
        FROM users u
        JOIN project_members pm ON u.user_id = pm.user_id
        WHERE pm.project_id = ?
        ''',
        (project_id,)
    ).fetchall()

    connection.close()
    return render_template('edit_task.html', task=task, members=members)


@app.route('/project/<int:project_id>/delete', methods=('POST',))
def delete_project(project_id):
    """
    Handles the deletion of a project.
    Only Owners or Admins can delete a project.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    project = connection.execute('SELECT * FROM projects WHERE project_id = ?', (project_id,)).fetchone()

    if project is None:
        connection.close()
        flash('Project not found.')
        return redirect(url_for('dashboard'))

    if project['owner_id'] != user_id and session.get('is_admin') != 1:
        connection.close()
        flash('You do not have permission to delete this project.')
        return redirect(url_for('dashboard'))

    # Manual cascade delete
    connection.execute(
        'DELETE FROM comments WHERE task_id IN (SELECT task_id FROM tasks WHERE project_id = ?)',
        (project_id,)
    )
    # Delete tasks
    connection.execute('DELETE FROM tasks WHERE project_id = ?', (project_id,))
    # Delete members
    connection.execute('DELETE FROM project_members WHERE project_id = ?', (project_id,))
    # Delete project
    connection.execute('DELETE FROM projects WHERE project_id = ?', (project_id,))

    connection.commit()
    connection.close()
    flash('Project deleted successfully!')
    return redirect(url_for('dashboard'))


@app.route('/task/<int:task_id>/delete', methods=('POST',))
def delete_task(task_id):
    """
    Handles the deletion of a task.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    connection = get_db_connection()

    task = connection.execute('SELECT * FROM tasks WHERE task_id = ?', (task_id,)).fetchone()

    if task is None:
        connection.close()
        flash('Task not found.')
        return redirect(url_for('dashboard'))

    project_id = task['project_id']

    member = connection.execute(
        'SELECT * FROM project_members WHERE project_id = ? AND user_id = ?',
        (project_id, user_id)
    ).fetchone()

    if member is None and session.get('is_admin') != 1:
        connection.close()
        flash('You do not have permission to delete this task.')
        return redirect(url_for('dashboard'))

    # Delete comments on this task
    connection.execute('DELETE FROM comments WHERE task_id = ?', (task_id,))
    # Delete task
    connection.execute('DELETE FROM tasks WHERE task_id = ?', (task_id,))

    connection.commit()
    connection.close()
    flash('Task deleted successfully!')
    return redirect(url_for('view_project', project_id=project_id))


if __name__ == '__main__':
    app.run(debug=True)
