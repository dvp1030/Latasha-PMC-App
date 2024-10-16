from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, jsonify
import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key in production

# Define upload folder and allowed file types
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create uploads folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}  # Allowed file types

DATABASE = 'goods.db'  # Replace with your desired database name
conn = sqlite3.connect('goods.db')  # Update with your database file
cursor = conn.cursor()
cursor = conn.cursor()

# Drop the existing table
cursor.execute("DROP TABLE IF EXISTS your_table_name;")
cursor.execute("PRAGMA table_info(your_table_name);")  # Replace with the actual table name
print(cursor.fetchall())

conn.close()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('your_database.db')  # Change to your database
    conn.row_factory = sqlite3.Row
    return conn


# Add an admin route to approve registrations
@app.route('/approve_registration/<int:registration_id>', methods=['POST'])
def approve_registration(registration_id):
    conn = get_db_connection()
    try:
        # Fetch the registration details
        registration = conn.execute('SELECT * FROM pending_registrations WHERE id = ?', (registration_id,)).fetchone()
        if registration:
            username = registration['username']
            password = registration['password']
            # Insert into the users table
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            # Remove from pending registrations
            conn.execute('DELETE FROM pending_registrations WHERE id = ?', (registration_id,))
            conn.commit()
            flash(f'Registration for {username} approved!', 'success')
        else:
            flash('Registration not found!', 'error')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('view_users'))

@app.route('/request_registration', methods=['GET', 'POST'])
def request_registration():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_username = request.form['admin_username']

        # Logic to insert the registration request into a pending registrations table
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO pending_registrations (username, password, admin_username) VALUES (?, ?, ?)',
                         (username, password, admin_username))
            conn.commit()
            flash('Registration request sent to admin for approval!', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()
        return redirect(url_for('view_users'))

    return render_template('request_registration.html')  # Update with your HTML file name

with sqlite3.connect(DATABASE) as conn:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cur.fetchall()
    print("Tables in database:", tables)



def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()

        # Create the pending_registrations table
        cur.execute('''CREATE TABLE IF NOT EXISTS registration_requests (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE,
                            password TEXT,
                            role TEXT DEFAULT 'user',
                            admin_id INTEGER
                        )''')

        # Other tables
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            role TEXT NOT NULL,  -- 'admin' or 'user'
                            admin_id INTEGER,
                            is_approved INTEGER DEFAULT 0,  -- 0 = pending, 1 = approved
                            FOREIGN KEY (admin_id) REFERENCES users (id)
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS projects (
                            id INTEGER PRIMARY KEY, 
                            name TEXT NOT NULL, 
                            client TEXT NOT NULL, 
                            deadline TEXT NOT NULL, 
                            start_date TEXT NOT NULL, 
                            status TEXT NOT NULL,
                            admin_id INTEGER NOT NULL,
                            FOREIGN KEY (admin_id) REFERENCES users(id)
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS tasks (
                            id INTEGER PRIMARY KEY, 
                            project_id INTEGER, 
                            task_name TEXT, 
                            assignee TEXT, 
                            deadline TEXT, 
                            status TEXT,
                            FOREIGN KEY (project_id) REFERENCES projects(id)
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS media (
                            id INTEGER PRIMARY KEY,
                            project_id INTEGER,
                            filename TEXT,
                            label TEXT,
                            FOREIGN KEY (project_id) REFERENCES projects(id)
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS attendance (
                            id INTEGER PRIMARY KEY,
                            employee_name TEXT,
                            date TEXT,
                            time_in TEXT,
                            time_out TEXT
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS admins (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL  -- Ensure to add password field if needed
                        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS goods (
                            id INTEGER PRIMARY KEY,
                            name TEXT NOT NULL,
                            quantity INTEGER,  
                            unit TEXT NOT NULL,
                            percentage INTEGER DEFAULT 0
                        )''')

        # Create a default admin user if none exist
        create_default_user(conn)  # Ensure this function is defined

        conn.commit()
        logging.info("Database initialized successfully.")


def list_tables():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("Existing tables:", [table[0] for table in tables])

# Call this function to check existing tables
list_tables()



def create_default_user(conn):
    # Check if there are any users
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    # If no users exist, insert a default user
    if count == 0:
        cursor.execute('''INSERT INTO users (username, password, role) VALUES (?, ?, ?)''',
                       ('admin_username', generate_password_hash('admin_password'), 'admin'))  # Example admin user
        conn.commit()
        logging.info("Default admin user created.")

# Call init_db() when your application starts
init_db()
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']  # Get the role from the registration form
        data = request.form['data']  # Get any specific data for this user
        
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password, role, data) VALUES (?, ?, ?, ?)",
                        (username, password, role, data))
            conn.commit()
        flash('User registered successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT role, data FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()

    if user:
        role = user[0]
        data = user[1]
        
        # You can implement different views based on the role
        if role == 'admin1':
            # Return data specific to admin1
            return render_template('admin1_dashboard.html', data=data)
        elif role == 'admin2':
            # Return data specific to admin2
            return render_template('admin2_dashboard.html', data=data)
        # Add more roles as needed

    flash('Unauthorized access.')
    return redirect(url_for('home'))



@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Ensure the password is hashed

        with sqlite3.connect(DATABASE) as conn:
            try:
                conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                             (username, hashed_password, 'admin'))
                conn.commit()
                flash('Admin registered successfully!', 'success')
                return redirect(url_for('register_admin'))
            except sqlite3.IntegrityError:
                flash('Username already exists. Please choose a different one.')

    return render_template('register_admin.html')


def get_admins():
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM admins")
        admins = cur.fetchall()
        print([dict(admin) for admin in admins])  # Print fetched admins for debugging
        return admins

@app.route('/register/user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)
        
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            try:
                # Insert user registration request into the 'registration_requests' table
                cur.execute("INSERT INTO registration_requests (username, password, role) VALUES (?, ?, ?)", 
                            (username, hashed_password, 'user'))
                conn.commit()

                flash('Registration request submitted. Waiting for admin approval.')
                return redirect(url_for('register_user'))
            except sqlite3.IntegrityError:
                flash('Username already exists. Please choose a different one.')
    
    return render_template('register_user.html')




@app.route('/approve_users', methods=['POST', 'GET'])
def approve_users():
    if request.method == 'POST':
        user_id = request.form['user_id']
        action = request.form['action']

        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()

            if action == 'approve':
                # Fetch the user's data from the pending registrations table
                cur.execute("SELECT * FROM registration_requests WHERE id = ?", (user_id,))
                user_data = cur.fetchone()

                if user_data:
                    username = user_data[1]
                    password = user_data[2]
                    role = user_data[3]

                    # Insert the approved user into the 'users' table
                    cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                                (username, password, role))

                    # Remove the user from the pending registrations table
                    cur.execute("DELETE FROM registration_requests WHERE id = ?", (user_id,))
                    conn.commit()

                    flash(f'User {username} approved successfully!', 'success')

            elif action == 'reject':
                # Reject the user by removing them from the registration_requests table
                cur.execute("DELETE FROM registration_requests WHERE id = ?", (user_id,))
                conn.commit()

                flash('User rejected and removed successfully.', 'danger')

    # Fetch all pending registrations for display
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        pending_users = cur.execute("SELECT * FROM registration_requests").fetchall()

    return render_template('approve_users.html', pending_users=pending_users)






@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (user_id,))
        conn.commit()
        flash('User account approved successfully!')

    return redirect(url_for('approve_users'))

@app.route('/admin/reject_user/<int:user_id>', methods=['POST'])
@admin_required
def reject_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash('User account rejected successfully!')

    return redirect(url_for('approve_users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

            if user:
                print(f"User found: {user[1]}")  # Log the username
                if check_password_hash(user[2], password):  # user[2] is the password column
                    # Login successful
                    session['user_id'] = user[0]  # Store user ID
                    session['username'] = user[1]  # Store username
                    session['role'] = user[3]  # Store role
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    print("Password is incorrect.")
                    flash('Invalid password.', 'danger')  # More specific error message
            else:
                print("No user found with that username.")
                flash('Invalid username.', 'danger')  # More specific error message

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("""SELECT p.id, p.name, p.client, p.deadline, p.start_date, p.status, COUNT(t.id) as task_count
                       FROM projects p
                       LEFT JOIN tasks t ON p.id = t.project_id
                       WHERE p.admin_id = ? 
                       GROUP BY p.id""", (session['user_id'],))
        projects = cur.fetchall()
    return render_template('home.html', username=session.get('username'), role=session.get('role'), projects=projects)




@app.route('/projects/<int:project_id>/add_task', methods=['GET', 'POST'])
@login_required
def add_task(project_id):
    if request.method == 'POST':
        task_name = request.form.get('task_name')
        assignee = request.form.get('assignee')
        deadline = request.form.get('deadline')
        
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO tasks (project_id, task_name, assignee, deadline, status) VALUES (?, ?, ?, ?, ?)", 
                       (project_id, task_name, assignee, deadline, 'Not Started'))
            conn.commit()
        
        flash('Task added successfully!')
        return redirect(url_for('view_project_details', project_id=project_id))
    
    return render_template('add_task.html', project_id=project_id)

@app.route('/add-project/', methods=['GET', 'POST'])
@login_required
def add_project():
    if request.method == 'POST':
        name = request.form['name']
        client = request.form['client']
        deadline = request.form['deadline']
        start_date = request.form['start_date']
        status = request.form['status']

        # Format start_date to DD-MM-YYYY
        try:
            start_date_formatted = datetime.strptime(start_date, '%Y-%m-%d').strftime('%d-%m-%Y')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.')
            return redirect(url_for('add_project'))

        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO projects (name, client, deadline, start_date, status) VALUES (?, ?, ?, ?, ?)", 
                       (name, client, deadline, start_date_formatted, status))
            conn.commit()
        flash('Project added successfully!')
        return redirect(url_for('view_projects'))
    return render_template('add_project.html')

@app.route('/projects')
def projects():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    admin_id = session['admin_id']
    projects = Project.query.filter_by(admin_id=admin_id).all()

    return render_template('projects.html', projects=projects)


@app.route('/users/')
@admin_required
def view_users():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users")
        users = cur.fetchall()

    return render_template('users.html', users=users)

@app.route('/projects/')
@login_required
def view_projects():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("""SELECT p.id, p.name, p.client, p.deadline, p.start_date, p.status, COUNT(t.id) as task_count
                       FROM projects p
                       LEFT JOIN tasks t ON p.id = t.project_id
                       GROUP BY p.id""")
        projects = cur.fetchall()

    return render_template('projects.html', projects=projects)

@app.route('/projects/<int:project_id>', methods=['GET'])
@login_required
def view_project_details(project_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        project = cur.fetchone()

        if project:
            cur.execute("SELECT * FROM tasks WHERE project_id = ?", (project_id,))
            tasks = cur.fetchall()
            return render_template('project_details.html', project=project, tasks=tasks)

        flash('Project not found.')
        return redirect(url_for('view_projects'))

@app.route('/edit-project/<int:project_id>/', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        if request.method == 'POST':
            name = request.form['name']
            client = request.form['client']
            deadline = request.form['deadline']
            start_date = request.form['start_date']
            status = request.form['status']

            # Format start_date to DD-MM-YYYY
            try:
                start_date_formatted = datetime.strptime(start_date, '%Y-%m-%d').strftime('%d-%m-%Y')
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD.')
                return redirect(url_for('edit_project', project_id=project_id))

            cur.execute("""UPDATE projects 
                           SET name = ?, client = ?, deadline = ?, start_date = ?, status = ? 
                           WHERE id = ?""", 
                           (name, client, deadline, start_date_formatted, status, project_id))
            conn.commit()
            flash('Project updated successfully!')
            return redirect(url_for('view_projects')) 

        cur.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        project = cur.fetchone()

    if project is None:
        abort(404, description="Project not found")  # Improved error handling

    return render_template('edit_project.html', project=project)

@app.route('/projects/<int:project_id>/tasks/<int:task_id>/update_status', methods=['POST'])
@login_required
def update_task_status(project_id, task_id):
    new_status = request.form.get('status')

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE tasks SET status = ? WHERE id = ?", (new_status, task_id))
        conn.commit()

    flash('Task status updated successfully!')
    return redirect(url_for('view_project_details', project_id=project_id))

@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    if request.method == 'POST':
        task_name = request.form.get('task_name')
        task_status = request.form.get('status')
        project_id = request.form.get('project_id')  

        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("UPDATE tasks SET task_name = ?, status = ? WHERE id = ?", (task_name, task_status, task_id))
            conn.commit()

        flash('Task updated successfully!')
        return redirect(url_for('view_project_details', project_id=project_id))

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        task = cur.fetchone()

    return render_template('edit_task.html', task=task)

@app.route('/projects/<int:project_id>/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(project_id, task_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM tasks WHERE id = ? AND project_id = ?", (task_id, project_id))
        conn.commit()

    flash("Task removed successfully")
    return redirect(url_for('view_project_details', project_id=project_id))

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.commit()
    flash('Project deleted successfully!')
    return redirect(url_for('view_projects'))

@app.route('/upload_media/<int:project_id>', methods=['GET', 'POST'])
@login_required
def upload_media(project_id):
    if request.method == 'POST':
        return handle_upload(project_id)
    
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT filename FROM media WHERE project_id = ?", (project_id,))
        media_files = [row[0] for row in cur.fetchall()]  # Get list of filenames
    
    return render_template('upload_media.html', project_id=project_id, media_list=media_files)

@app.route('/upload/<int:project_id>', methods=['GET', 'POST'])
@login_required
def handle_upload(project_id):
    if request.method == 'POST':
        files = request.files.getlist('media')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)  # Secure the filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Save file info in database
                with sqlite3.connect(DATABASE) as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO media (project_id, filename, label) VALUES (?, ?, ?)", (project_id, filename, "Label"))  # Change label as needed
                    conn.commit()
        flash('Files uploaded successfully!')
        return redirect(url_for('upload_media', project_id=project_id))
    
    return render_template('upload_media.html', project_id=project_id)

@app.route('/view_uploaded_media/<int:project_id>', methods=['GET'])
@login_required
def view_uploaded_media(project_id):
    media_list = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('view_uploaded_media.html', media_list=media_list, project_id=project_id)

@app.route('/delete_media/<int:project_id>', methods=['POST'])
@login_required
def delete_media(project_id):
    media = request.form.get('media')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], media)

    try:
        os.remove(file_path)  # Delete the file
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM media WHERE filename = ? AND project_id = ?", (media, project_id))
            conn.commit()
        flash('Media deleted successfully!')
        return jsonify(success=True)
    except Exception as e:
        print(e)  # Print the exception for debugging
        return jsonify(success=False)

@app.route('/edit_media/<int:project_id>', methods=['POST'])
@login_required
def edit_media(project_id):
    old_name = request.form.get('old_name')
    new_name = request.form.get('new_name')

    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], old_name)
    new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_name)

    if os.path.exists(old_file_path):
        try:
            os.rename(old_file_path, new_file_path)
            with sqlite3.connect(DATABASE) as conn:
                cur = conn.cursor()
                cur.execute("UPDATE media SET filename = ? WHERE filename = ? AND project_id = ?", (new_name, old_name, project_id))
                conn.commit()
            flash('Media renamed successfully!')
            return jsonify(success=True)
        except Exception as e:
            return jsonify(success=False, error=str(e))
    else:
        return jsonify(success=False, error="File does not exist.")

@app.route('/view_media/<int:project_id>')
@login_required
def view_media(project_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM media WHERE project_id = ?", (project_id,))
        media_files = cur.fetchall()
    
    return render_template('view_media.html', media_files=media_files, project_id=project_id)

@app.route('/record-attendance/')
@login_required
def record_attendance():
    return render_template('record_attendance.html')

@app.route('/submit-attendance', methods=['POST'])
@login_required
def submit_attendance():
    employee_name = request.form['employee_name']
    date = request.form['date']
    time_in = request.form['time_in']
    time_out = request.form['time_out']

    # Save the attendance record in the database
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO attendance (employee_name, date, time_in, time_out) VALUES (?, ?, ?, ?)", 
                   (employee_name, date, time_in, time_out))
        conn.commit()

    flash('Attendance recorded successfully!')
    return redirect(url_for('view_attendance'))

@app.route('/view-attendance/')
@login_required
def view_attendance():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM attendance ORDER BY date ASC")
        attendance_records = cur.fetchall()  # Fetch all attendance records
    
    # Format the records for rendering
    attendance_records = [{
        'employee_name': record[1],
        'date': record[2],
        'time_in': record[3],
        'time_out': record[4]
    } for record in attendance_records]

    return render_template('view_attendance.html', attendance_records=attendance_records)

@app.route('/view-goods/', methods=['GET'])
@login_required
def view_goods():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM goods")
        goods = cursor.fetchall()
    return render_template('goods.html', goods=goods)

@app.route('/add-good/', methods=['POST'])
@login_required
def add_good():
    name = request.form['goodsName']
    quantity = request.form.get('quantity')  # May be None
    unit = request.form['unit']
    percentage = request.form.get('percentage', 0, type=int)

    # Convert quantity to integer if provided, else set to None
    try:
        quantity = int(quantity) if quantity else None
    except ValueError:
        flash('Quantity must be an integer.')
        return redirect(url_for('view_goods'))

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO goods (name, quantity, unit, percentage) 
                          VALUES (?, ?, ?, ?)''',
                       (name, quantity, unit, percentage))
        conn.commit()
    flash('Good added successfully!')
    return redirect(url_for('view_goods'))

@app.route('/edit-good/', methods=['POST'])
@login_required
def edit_good():
    good_id = int(request.form['id'])
    name = request.form['goodsName']
    quantity = request.form.get('quantity')  # May be None
    unit = request.form['unit']
    percentage = request.form.get('percentage', 0, type=int)

    # Convert quantity to integer if provided, else set to None
    try:
        quantity = int(quantity) if quantity else None
    except ValueError:
        flash('Quantity must be an integer.')
        return redirect(url_for('view_goods'))

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''UPDATE goods 
                          SET name = ?, quantity = ?, unit = ?, percentage = ? 
                          WHERE id = ?''',
                       (name, quantity, unit, percentage, good_id))
        conn.commit()
    flash('Good updated successfully!')
    return redirect(url_for('view_goods'))

@app.route('/remove_user/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    # Prevent admin from removing themselves
    if user_id == session.get('user_id'):
        flash("You cannot remove your own account.")
        return redirect(url_for('view_users'))
    
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        # Check if user exists
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if user:
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            flash(f"User '{user[1]}' has been removed successfully.")
        else:
            flash("User not found.")
    return redirect(url_for('view_users'))

if __name__ == '__main__':
    init_db()  # Initialize the database on startup
    app.run(debug=True)
