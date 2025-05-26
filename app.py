# app.py (Updated for your template structure)
import bcrypt
import os
import time
import logging
import mysql.connector
from flask import Flask, render_template,jsonify, request,send_from_directory, redirect, url_for, session, flash, g,abort
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
from werkzeug.utils import secure_filename
# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(**DB_CONFIG)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def execute_query(query, params=(), fetch_one=False):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params)
        return cursor.fetchone() if fetch_one else cursor.fetchall()
    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        raise
    finally:
        cursor.close()

# Authentication Routes
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = execute_query(
            "SELECT * FROM users WHERE username = %s",
            (username,),
            fetch_one=True
        )
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
        return redirect(url_for('login'))

    return render_template('auth/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            execute_query(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            flash("Signup successful! Please login.")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username or Email already exists!")
        except Exception as e:
            logging.error(f"Signup error: {str(e)}")
            flash("Registration failed")

    return render_template('auth/signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
# Syllabus Routes
@app.route('/syllabus', methods=['GET', 'POST'])
def syllabus():
    if 'username' not in session:
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        try:
            semester = request.form.get('semester')
            subject_name = request.form.get('subject_name')
            result = execute_query(
                """SELECT syllabus_pdf FROM syllabus 
                   WHERE dept_id = %s AND semester = %s AND subject_name = %s""",
                ('01', semester, subject_name),
                fetch_one=True
            )
        except Exception as e:
            flash("Error retrieving syllabus")
            print(f"Syllabus error: {str(e)}")

    return render_template('syllabus.html', result=result)
@app.route('/get_subjects')
def get_subjects():
    try:
        semester = request.args.get('semester')
        print(f"Fetching subjects for semester: {semester}")  # Debug
        
        # Explicitly convert semester to string since your DB stores it as string
        subjects = execute_query(
            "SELECT DISTINCT subject_name FROM syllabus WHERE dept_id = %s AND semester = %s",
            ('01', str(semester))  # Both values as strings
        )
        
        print(f"Found subjects: {subjects}")  # Debug
        
        if not subjects:
            return jsonify({
                'success': True,
                'message': 'No subjects found for this semester',
                'subjects': []
            })
            
        return jsonify({
            'success': True,
            'subjects': [s['subject_name'] for s in subjects]
        })

    except Exception as e:
        print(f"Error: {str(e)}")  # Debug
        return jsonify({
            'success': False,
            'error': str(e),
            'subjects': []
        })

@app.route('/timetable', methods=['GET', 'POST'])
def exam_timetable():
    dept_id = '01'  # Default department
    result = None
    subjects = []
    
    semesters = execute_query(
        "SELECT DISTINCT semester FROM exam_timetable WHERE dept_id = %s",
        (dept_id,)
    )

    if request.method == 'POST':
        semester = request.form.get('semester')
        subject = request.form.get('subject_name')

        subjects = execute_query(
            """SELECT DISTINCT subject_name FROM exam_timetable 
            WHERE dept_id = %s AND semester = %s""",
            (dept_id, semester)
        )

        if subject:
            result = execute_query(
                """SELECT subject_name, exam_date, exam_time, location 
                FROM exam_timetable 
                WHERE dept_id = %s AND semester = %s AND subject_name = %s""",
                (dept_id, semester, subject),
                fetch_one=True
            )

    return render_template('timetable.html',
        semesters=semesters,
        subjects=subjects,
        result=result,
        semester_selected=request.form.get('semester')
    )

@app.route('/materials', methods=['GET', 'POST'])
def materials():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            subject_name = request.form.get('subject_name', '').strip().lower()
            
            if not subject_name:
                flash("Please enter a subject name")
                return redirect(url_for('materials'))
            
            # Search with case-insensitive partial matching
            materials = execute_query(
                """SELECT subject_name, material_type, material_link, file_name 
                   FROM materials 
                   WHERE LOWER(subject_name) LIKE %s
                   ORDER BY subject_name""",
                (f"%{subject_name}%",)
            )
            
            if not materials:
                similar = execute_query(
                    """SELECT DISTINCT subject_name 
                       FROM materials 
                       WHERE subject_name LIKE %s
                       LIMIT 5""",
                    (f"%{subject_name[:4]}%",)
                )
                return render_template('materials.html',
                                    results=None,
                                    searched_subject=subject_name,
                                    suggestions=similar)
            
            return render_template('materials.html',
                                results=materials,
                                searched_subject=subject_name)
            
        except Exception as e:
            print(f"Error: {str(e)}")
            return render_template('materials.html',
                                error="Error searching materials",
                                results=None)
    
    return render_template('materials.html', results=None)
app.config['MATERIALS_FOLDER'] = os.path.join(os.path.dirname(__file__), 'materials')


@app.route('/download/<filename>')
def download_file(filename):
    try:
        # Security checks
        if not filename or '..' in filename or filename.startswith('/'):
            abort(400, description="Invalid filename")
            
        materials_dir = app.config['MATERIALS_FOLDER']
        file_path = os.path.join(materials_dir, filename)
        
        # Verify file exists
        if not os.path.isfile(file_path):
            # Try to find similar files (case-insensitive)
            all_files = os.listdir(materials_dir)
            matched_file = next((f for f in all_files if f.lower() == filename.lower()), None)
            if matched_file:
                file_path = os.path.join(materials_dir, matched_file)
            else:
                abort(404, description="File not found")
        
        # Get the original filename from database if available
        material = execute_query(
            "SELECT file_name FROM materials WHERE material_link = %s",
            (filename,),
            fetch_one=True
        )
        
        download_name = material['file_name'] if material else filename
        
        return send_from_directory(
            directory=materials_dir,
            path=os.path.basename(file_path),
            as_attachment=True,
            download_name=download_name  # This will show the original filename to users
        )
        
    except Exception as e:
        app.logger.error(f"Download failed: {str(e)}")
        abort(500, description="Download failed")
@app.route('/debug/materials')
def debug_materials():
    materials_dir = app.config.get('MATERIALS_FOLDER')
    exists = os.path.exists(materials_dir) if materials_dir else False
    files = os.listdir(materials_dir) if exists else []
    
    return jsonify({
        'configured_path': materials_dir,
        'path_exists': exists,
        'files': files
    })
@app.route('/test-download')
def test_download():
    """Test route to verify download functionality"""
    filename = "Java.pdf"  # Use one of your actual filenames
    return send_from_directory(
        directory=app.config['MATERIALS_FOLDER'],
        path=filename,
        as_attachment=True
    )
@app.route('/placement')
def placements():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        companies = execute_query(
            """SELECT company_name, eligibility_criteria, 
                      job_role, registration_link 
               FROM placements"""
        )

        return render_template('placement.html', companies=companies)

    except Exception as e:
        print(f"Placements error: {str(e)}")
        return render_template('placement.html',
                               error="Error loading placement information")
@app.route('/navigation', methods=['GET', 'POST'])
def navigation():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Get all navigation points for dropdown
        locations = execute_query(
            "SELECT name FROM navigation_points ORDER BY name ASC"
        )
        
        result = None
        if request.method == 'POST':
            selected_name = request.form['name'].strip()
            
            # Get details for selected location
            result = execute_query(
                "SELECT name, description FROM navigation_points WHERE name = %s",
                (selected_name,),
                fetch_one=True
            )
            
            if not result:
                flash("Location not found")
        
        return render_template('navigation.html',
                            locations=locations,
                            result=result)
    
    except Exception as e:
        print(f"Navigation error: {str(e)}")
        return render_template('navigation.html',
                            locations=[],
                            result=None,
                            error="Error loading navigation information")

@app.route('/courses')
def courses():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Get all additional courses
        courses = execute_query(
            """SELECT course_name, description, registration_link, offered_by 
               FROM additional_courses 
               ORDER BY course_name ASC"""
        )
        
        return render_template('courses.html', courses=courses)
    
    except Exception as e:
        print(f"Courses error: {str(e)}")
        return render_template('courses.html',
                            courses=None,
                            error="Error loading course information")
@app.route('/seat', methods=['GET', 'POST'])
def seat():
    if 'username' not in session:
        return redirect(url_for('login'))

    result = None
    error = None

    if request.method == 'POST':
        student_id = request.form.get('student_id').strip()

        try:
            # Fetch seat allocation for the entered student_id
            query = """
                SELECT subject_name, seat_number, room_number
                FROM seat_allocation
                WHERE student_id = %s
            """
            results = execute_query(query, (student_id,))

            if results:
                result = results[0]  # fetchone logic
            else:
                error = "No seat allocation found for the given Student ID."

        except Exception as e:
            print(f"Seat allocation error: {str(e)}")
            error = "Error retrieving seat allocation."

    return render_template('seat.html', result=result, error=error)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = execute_query(
            "SELECT * FROM admins WHERE username = %s",
            (username,),
            fetch_one=True
        )

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
            session['admin_logged_in'] = True
            session['admin_username'] = admin['username']
            return redirect(url_for('admin_dashboard'))

        flash('Invalid admin credentials')
    return render_template('admin/login.html')
# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin/dashboard.html')

# Admin Logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please login as admin to access this page', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/users')
@admin_required
def manage_users():
    search_query = request.args.get('search', '')
    
    if search_query:
        users = execute_query(
            "SELECT id, username, email, created_at FROM users WHERE username LIKE %s OR email LIKE %s",
            (f"%{search_query}%", f"%{search_query}%")
        )
    else:
        users = execute_query("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC")
    
    return render_template('admin/users.html', users=users, search_query=search_query)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if session.get('admin_username') == 'admin':  # Prevent deleting the main admin
        execute_query("DELETE FROM users WHERE id = %s", (user_id,))
        flash('User deleted successfully', 'success')
    else:
        flash('Only main admin can delete users', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/admin/user/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not all([username, email, password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('manage_users'))
    
    try:
        hashed_password = generate_password_hash(password)
        execute_query(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        flash('User added successfully', 'success')
    except Exception as e:
        flash(f'Error adding user: {str(e)}', 'danger')
    
    return redirect(url_for('manage_users'))
# Syllabus Configuration
SYLLABUS_CONFIG = {
    'UPLOAD_FOLDER': os.path.join(app.static_folder, 'pdfs'),
    'ALLOWED_EXTENSIONS': {'pdf'},
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024  # 16MB max file size
}

def allowed_syllabus_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in SYLLABUS_CONFIG['ALLOWED_EXTENSIONS']

def generate_syllabus_filename(semester, subject_name, original_filename):
    """Generate a consistent filename for syllabus PDFs"""
    ext = original_filename.rsplit('.', 1)[1].lower()
    safe_subject = subject_name.replace(' ', '_').replace('/', '_')
    return f"sem{semester}_{safe_subject}.{ext}"

def get_syllabus_path(filename):
    """Get full path to syllabus file"""
    return os.path.join(SYLLABUS_CONFIG['UPLOAD_FOLDER'], filename)
@app.route('/admin/syllabus')
@admin_required
def manage_syllabus():
    search_query = request.args.get('search', '')
    semester_filter = request.args.get('semester', '')
    dept_filter = request.args.get('dept', '01')  # Default department

    # Base query
    query = """SELECT s.syllabus_id, s.semester, s.subject_name, s.syllabus_pdf, 
                      d.dept_name 
               FROM syllabus s
               JOIN departments d ON s.dept_id = d.dept_id
               WHERE s.dept_id = %s"""
    params = [dept_filter]
    
    # Add filters if provided
    if search_query:
        query += " AND s.subject_name LIKE %s"
        params.append(f"%{search_query}%")
    
    if semester_filter:
        query += " AND s.semester = %s"
        params.append(semester_filter)
    
    query += " ORDER BY s.semester, s.subject_name"
    
    try:
        syllabi = execute_query(query, tuple(params))
    except Exception as e:
        flash(f"Database error: {str(e)}", 'danger')
        syllabi = []

    # Get filter options
    semesters = execute_query(
        "SELECT DISTINCT semester FROM syllabus WHERE dept_id = %s ORDER BY semester",
        (dept_filter,)
    )
    
    departments = execute_query("SELECT dept_id, dept_name FROM departments")
    
    return render_template('admin/syllabus.html', 
                         syllabi=syllabi,
                         semesters=semesters,
                         departments=departments,
                         current_dept=dept_filter,
                         search_query=search_query,
                         semester_filter=semester_filter)

@app.route('/admin/syllabus/add', methods=['POST'])
@admin_required
def add_syllabus():
    semester = request.form.get('semester')
    subject_name = request.form.get('subject_name')
    syllabus_file = request.files.get('syllabus_pdf')
    
    if not all([semester, subject_name, syllabus_file]):
        flash('All fields are required', 'danger')
        return redirect(url_for('manage_syllabus'))
    
    if not syllabus_file or not allowed_syllabus_file(syllabus_file.filename):
        flash('Only PDF files are allowed', 'danger')
        return redirect(url_for('manage_syllabus'))
    
    try:
        filename = generate_syllabus_filename(semester, subject_name, syllabus_file.filename)
        filepath = get_syllabus_path(filename)
        
        # Check for existing file
        if os.path.exists(filepath):
            flash('A syllabus with this name already exists', 'warning')
            return redirect(url_for('manage_syllabus'))
        
        syllabus_file.save(filepath)
        
        execute_query(
            """INSERT INTO syllabus 
            (dept_id, semester, subject_name, syllabus_pdf) 
            VALUES (%s, %s, %s, %s)""",
            ('01', semester, subject_name, filename)  # Using your schema with auto-increment ID
        )
        flash('Syllabus added successfully', 'success')
    except Exception as e:
        flash(f'Error adding syllabus: {str(e)}', 'danger')
    
    return redirect(url_for('manage_syllabus'))

@app.route('/admin/syllabus/delete/<int:syllabus_id>', methods=['POST'])
@admin_required
def delete_syllabus(syllabus_id):
    try:
        # Get file info before deletion
        syllabus = execute_query(
            "SELECT syllabus_pdf FROM syllabus WHERE syllabus_id = %s",
            (syllabus_id,),
            fetch_one=True
        )
        
        if syllabus:
            # Delete file
            filepath = os.path.join(app.config['SYLLABUS_UPLOAD_FOLDER'], syllabus['syllabus_pdf'])
            if os.path.exists(filepath):
                os.remove(filepath)
            
            # Delete record
            execute_query(
                "DELETE FROM syllabus WHERE syllabus_id = %s",
                (syllabus_id,)
            )
            flash('Syllabus deleted successfully', 'success')
        else:
            flash('Syllabus not found', 'danger')
    except Exception as e:
        flash(f'Error deleting syllabus: {str(e)}', 'danger')
    
    return redirect(url_for('manage_syllabus'))

@app.route('/syllabus/view/<int:syllabus_id>')
def view_syllabus(syllabus_id):
    try:
        syllabus = execute_query(
            """SELECT s.syllabus_pdf, s.subject_name, d.dept_name 
               FROM syllabus s
               JOIN departments d ON s.dept_id = d.dept_id
               WHERE s.syllabus_id = %s""",
            (syllabus_id,),
            fetch_one=True
        )
        
        if syllabus:
            return send_from_directory(
                app.config['SYLLABUS_UPLOAD_FOLDER'],
                syllabus['syllabus_pdf'],
                as_attachment=False  # Display in browser
            )
        abort(404)
    except Exception as e:
        abort(500)

@app.route('/syllabus/download/<filename>')
def download_syllabus(filename):
    try:
        # Security checks
        if not filename or '..' in filename or '/' in filename:
            abort(400)
            
        return send_from_directory(
            SYLLABUS_CONFIG['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        abort(404)

# Exam Timetable Admin Routes
@app.route('/admin/timetable')
@admin_required
def manage_timetable():
    search_query = request.args.get('search', '')
    semester_filter = request.args.get('semester', '')
    dept_filter = request.args.get('dept', '01')  # Default department

    # Base query with department join
    query = """SELECT e.exam_id, e.semester, e.subject_name, e.exam_date, 
                      e.exam_time, e.location, d.dept_name
               FROM exam_timetable e
               JOIN departments d ON e.dept_id = d.dept_id
               WHERE e.dept_id = %s"""
    params = [dept_filter]
    
    # Add filters if provided
    if search_query:
        query += " AND e.subject_name LIKE %s"
        params.append(f"%{search_query}%")
    
    if semester_filter:
        query += " AND e.semester = %s"
        params.append(semester_filter)
    
    query += " ORDER BY e.exam_date, e.exam_time"
    
    try:
        exams = execute_query(query, tuple(params))
    except Exception as e:
        flash(f"Database error: {str(e)}", 'danger')
        exams = []

    # Get filter options
    semesters = execute_query(
        "SELECT DISTINCT semester FROM exam_timetable WHERE dept_id = %s ORDER BY semester",
        (dept_filter,)
    )
    
    departments = execute_query("SELECT dept_id, dept_name FROM departments")
    
    return render_template('admin/timetable.html', 
                         exams=exams,
                         semesters=semesters,
                         departments=departments,
                         current_dept=dept_filter,
                         search_query=search_query,
                         semester_filter=semester_filter)

@app.route('/admin/timetable/add', methods=['POST'])
@admin_required
def add_exam():
    dept_id = request.form.get('dept_id')
    semester = request.form.get('semester')
    subject_name = request.form.get('subject_name')
    exam_date = request.form.get('exam_date')
    exam_time = request.form.get('exam_time')
    location = request.form.get('location')
    
    if not all([dept_id, semester, subject_name, exam_date, exam_time, location]):
        flash('All fields are required', 'danger')
        return redirect(url_for('manage_timetable'))
    
    try:
        execute_query(
            """INSERT INTO exam_timetable 
            (dept_id, semester, subject_name, exam_date, exam_time, location) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (dept_id, semester, subject_name, exam_date, exam_time, location)
        )
        flash('Exam added successfully', 'success')
    except Exception as e:
        flash(f'Error adding exam: {str(e)}', 'danger')
    
    return redirect(url_for('manage_timetable'))

@app.route('/admin/timetable/edit/<int:exam_id>', methods=['POST'])
@admin_required
def edit_exam(exam_id):
    semester = request.form.get('semester')
    subject_name = request.form.get('subject_name')
    exam_date = request.form.get('exam_date')
    exam_time = request.form.get('exam_time')
    location = request.form.get('location')
    
    if not all([semester, subject_name, exam_date, exam_time, location]):
        flash('All fields are required', 'danger')
        return redirect(url_for('manage_timetable'))
    
    try:
        execute_query(
            """UPDATE exam_timetable 
            SET semester = %s, 
                subject_name = %s, 
                exam_date = %s, 
                exam_time = %s, 
                location = %s
            WHERE exam_id = %s""",
            (semester, subject_name, exam_date, exam_time, location, exam_id)
        )
        flash('Exam updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating exam: {str(e)}', 'danger')
    
    return redirect(url_for('manage_timetable'))

@app.route('/admin/timetable/delete/<int:exam_id>', methods=['POST'])
@admin_required
def delete_exam(exam_id):
    try:
        execute_query(
            "DELETE FROM exam_timetable WHERE exam_id = %s",
            (exam_id,)
        )
        flash('Exam deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting exam: {str(e)}', 'danger')
    
    return redirect(url_for('manage_timetable'))

# Materials Configuration
app.config['MATERIALS_FOLDER'] = os.path.join(os.path.dirname(__file__), 'materials')
os.makedirs(app.config['MATERIALS_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'ppt', 'pptx', 'doc', 'docx', 'txt'}

def allowed_material_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/admin/materials')
@admin_required
def manage_materials():
    search_query = request.args.get('search', '')
    semester_filter = request.args.get('semester', '')
    dept_filter = request.args.get('dept', '1')  # Default department ID
    
    # Base query
    query = """SELECT m.material_id, m.dept_id, m.semester, m.subject_name, 
                      m.material_type, m.material_link, m.file_name,
                      d.dept_name
               FROM materials m
               LEFT JOIN departments d ON m.dept_id = d.dept_id
               WHERE 1=1"""
    params = []
    
    # Add filters
    if dept_filter:
        query += " AND m.dept_id = %s"
        params.append(dept_filter)
    
    if semester_filter:
        query += " AND m.semester = %s"
        params.append(semester_filter)
    
    if search_query:
        query += " AND (m.subject_name LIKE %s OR m.file_name LIKE %s)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    query += " ORDER BY m.semester, m.subject_name"
    
    try:
        materials = execute_query(query, tuple(params)) if params else execute_query(query)
    except Exception as e:
        flash(f"Database error: {str(e)}", 'danger')
        materials = []

    # Get filter options
    semesters = execute_query("SELECT DISTINCT semester FROM materials WHERE semester IS NOT NULL ORDER BY semester")
    departments = execute_query("SELECT dept_id, dept_name FROM departments")
    
    return render_template('admin/materials.html',
                         materials=materials,
                         semesters=semesters,
                         departments=departments,
                         current_dept=dept_filter,
                         semester_filter=semester_filter,
                         search_query=search_query)

@app.route('/admin/materials/add', methods=['POST'])
@admin_required
def add_material():
    try:
        dept_id = request.form.get('dept_id')
        semester = request.form.get('semester')
        subject_name = request.form.get('subject_name')
        material_type = request.form.get('material_type')
        material_file = request.files.get('material_file')

        if not all([dept_id, subject_name, material_type, material_file]):
            flash('All required fields must be filled', 'danger')
            return redirect(url_for('manage_materials'))

        if not material_file or material_file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('manage_materials'))

        # Generate unique filename while preserving original
        original_filename = secure_filename(material_file.filename)
        file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        unique_id = str(int(time.time()))
        stored_filename = f"{secure_filename(subject_name)}_{unique_id}.{file_ext}"
        
        filepath = os.path.join(app.config['MATERIALS_FOLDER'], stored_filename)
        material_file.save(filepath)

        execute_query(
            """INSERT INTO materials 
            (dept_id, semester, subject_name, material_type, material_link, file_name) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (dept_id, semester, subject_name, material_type, stored_filename, original_filename)
        )
        flash('Material added successfully', 'success')

    except Exception as e:
        flash(f'Error adding material: {str(e)}', 'danger')
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
    
    return redirect(url_for('manage_materials'))
@app.route('/materials/download/<filename>')
def download_material(filename):
    try:
        if not filename or '..' in filename or filename.startswith('/'):
            abort(400)
        return send_from_directory(app.config['MATERIALS_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route('/admin/materials/delete/<int:material_id>', methods=['POST'])
@admin_required
def delete_material(material_id):
    try:
        # Get material details
        material = execute_query(
            "SELECT material_link FROM materials WHERE material_id = %s",
            (material_id,),
            fetch_one=True
        )

        if not material:
            flash('Material not found', 'danger')
            return redirect(url_for('manage_materials'))

        # Delete file if exists
        if material and material.get('material_link'):
            try:
                filepath = os.path.join(app.config['MATERIALS_FOLDER'], material['material_link'])
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                flash(f'Warning: Could not delete file - {str(e)}', 'warning')

        # Delete database record
        execute_query(
            "DELETE FROM materials WHERE material_id = %s",
            (material_id,)
        )
        flash('Material deleted successfully', 'success')

    except Exception as e:
        flash(f'Error deleting material: {str(e)}', 'danger')
    
    return redirect(url_for('manage_materials'))
# Additional Courses Management Routes
@app.route('/admin/courses')
@admin_required
def admin_courses():
    """Display all additional courses with search functionality"""
    search_query = request.args.get('search', '')
    dept_filter = request.args.get('dept', '')
    
    base_query = "SELECT * FROM additional_courses"
    params = []
    
    conditions = []
    if search_query:
        conditions.append("(course_name LIKE %s OR description LIKE %s)")
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    if dept_filter:
        conditions.append("dept_id = %s")
        params.append(dept_filter)
    
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY course_name"
    
    try:
        courses = execute_query(base_query, tuple(params)) if params else execute_query(base_query)
        departments = execute_query("SELECT dept_id, dept_name FROM departments")
        return render_template('admin/additionalcourses.html',
                            courses=courses,
                            departments=departments,
                            current_dept=dept_filter,
                            search_query=search_query)
    except Exception as e:
        flash(f"Database error: {str(e)}", 'danger')
        return render_template('admin/additionalcourses.html',
                            courses=[],
                            departments=[],
                            current_dept='',
                            search_query='')

@app.route('/admin/courses/add', methods=['POST'])
@admin_required
def add_course():
    try:
        course_name = request.form.get('course_name')
        description = request.form.get('description')
        registration_link = request.form.get('registration_link')
        offered_by = request.form.get('offered_by')
        dept_id = request.form.get('dept_id', '01')  # Default to '01' if not provided
        
        if not all([course_name, description, registration_link]):
            flash('Course name, description and registration link are required', 'danger')
            return redirect(url_for('admin_courses'))
        
        course_id = str(int(time.time()))[-6:]
        
        execute_query(
            """INSERT INTO additional_courses 
            (course_id, course_name, description, registration_link, offered_by, dept_id) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (course_id, course_name, description, registration_link, offered_by, dept_id)
        )
        flash('Course added successfully', 'success')
    except Exception as e:
        flash(f'Error adding course: {str(e)}', 'danger')
    
    return redirect(url_for('admin_courses'))
@app.route('/admin/courses/edit/<course_id>')
@admin_required
def view_edit_course(course_id):
    """Display the edit form for a course"""
    try:
        course = execute_query(
            "SELECT * FROM additional_courses WHERE course_id = %s",
            (course_id,),
            fetch_one=True
        )
        if not course:
            flash('Course not found', 'danger')
            return redirect(url_for('admin_courses'))
        
        departments = execute_query("SELECT dept_id, dept_name FROM departments")
        return render_template('admin/additionalcourses.html',
                            courses=[],
                            edit_mode=True,
                            course=course,
                            departments=departments,
                            current_dept=course['dept_id'])
    except Exception as e:
        flash(f'Error retrieving course: {str(e)}', 'danger')
        return redirect(url_for('admin_courses'))

@app.route('/admin/courses/update/<course_id>', methods=['POST'])
@admin_required
def update_course(course_id):
    """Handle updating an existing course"""
    try:
        course_name = request.form.get('course_name')
        description = request.form.get('description')
        registration_link = request.form.get('registration_link')
        offered_by = request.form.get('offered_by')
        dept_id = request.form.get('dept_id')
        
        if not all([course_name, description, registration_link]):
            flash('Course name, description and registration link are required', 'danger')
            return redirect(url_for('view_edit_course', course_id=course_id))
        
        execute_query(
            """UPDATE additional_courses 
            SET course_name = %s,
                description = %s,
                registration_link = %s,
                offered_by = %s,
                dept_id = %s
            WHERE course_id = %s""",
            (course_name, description, registration_link, offered_by, dept_id, course_id)
        )
        flash('Course updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating course: {str(e)}', 'danger')
    
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/delete/<course_id>', methods=['POST'])
@admin_required
def delete_course(course_id):
    """Handle deleting a course"""
    try:
        execute_query(
            "DELETE FROM additional_courses WHERE course_id = %s",
            (course_id,)
        )
        flash('Course deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting course: {str(e)}', 'danger')
    
    return redirect(url_for('admin_courses'))
# Seat Allocation Management Routes
@app.route('/admin/seat-allocation')
@admin_required
def manage_seat_allocation():
    search = request.args.get('search', '')
    dept = request.args.get('dept', '')
    semester = request.args.get('semester', '')
    
    base_query = "SELECT * FROM seat_allocation"
    conditions = []
    params = []
    
    if search:
        conditions.append("(student_id LIKE %s OR subject_name LIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    if dept:
        conditions.append("dept_id = %s")
        params.append(dept)
    if semester:
        conditions.append("semester = %s")
        params.append(semester)
    
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY room_number, seat_number"
    
    try:
        allocations = execute_query(base_query, tuple(params)) if params else execute_query(base_query)
        departments = execute_query("SELECT dept_id, dept_name FROM departments")
        return render_template('admin/seatallocation.html',
                            allocations=allocations,
                            departments=departments,
                            current_dept=dept,
                            current_semester=semester,
                            search_query=search)
    except Exception as e:
        flash(f"Database error: {str(e)}", 'danger')
        return render_template('admin/seatallocation.html',
                            allocations=[],
                            departments=[],
                            current_dept='',
                            current_semester='',
                            search_query='')

@app.route('/admin/seat-allocation/add', methods=['POST'])
@admin_required
def add_seat_allocation():
    try:
        student_id = request.form.get('student_id')
        dept_id = request.form.get('dept_id')
        semester = request.form.get('semester')
        subject_name = request.form.get('subject_name')
        seat_number = request.form.get('seat_number')
        room_number = request.form.get('room_number')
        
        if not all([student_id, dept_id, semester, subject_name, seat_number, room_number]):
            flash('All fields are required', 'danger')
            return redirect(url_for('manage_seat_allocation'))
        
        execute_query(
            """INSERT INTO seat_allocation 
            (student_id, dept_id, semester, subject_name, seat_number, room_number) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (student_id, dept_id, semester, subject_name, seat_number, room_number)
        )
        flash('Seat allocation added successfully', 'success')
    except mysql.connector.IntegrityError as e:
        if 'Duplicate entry' in str(e):
            flash('This seat is already allocated', 'danger')
        else:
            flash(f'Database error: {str(e)}', 'danger')
    except Exception as e:
        flash(f'Error adding seat allocation: {str(e)}', 'danger')
    
    return redirect(url_for('manage_seat_allocation'))

@app.route('/admin/seat-allocation/edit/<student_id>/<subject_name>')
@admin_required
def edit_seat_allocation_view(student_id, subject_name):
    try:
        allocation = execute_query(
            """SELECT * FROM seat_allocation 
            WHERE student_id = %s AND subject_name = %s""",
            (student_id, subject_name),
            fetch_one=True
        )
        if not allocation:
            flash('Seat allocation not found', 'danger')
            return redirect(url_for('manage_seat_allocation'))
        
        departments = execute_query("SELECT dept_id, dept_name FROM departments")
        return render_template('admin/seatallocation.html',
                            allocations=[],
                            edit_mode=True,
                            allocation=allocation,
                            departments=departments)
    except Exception as e:
        flash(f'Error retrieving seat allocation: {str(e)}', 'danger')
        return redirect(url_for('manage_seat_allocation'))

@app.route('/admin/seat-allocation/update/<original_student_id>/<original_subject_name>', methods=['POST'])
@admin_required
def update_seat_allocation(original_student_id, original_subject_name):
    try:
        student_id = request.form.get('student_id')
        dept_id = request.form.get('dept_id')
        semester = request.form.get('semester')
        subject_name = request.form.get('subject_name')
        seat_number = request.form.get('seat_number')
        room_number = request.form.get('room_number')
        
        if not all([student_id, dept_id, semester, subject_name, seat_number, room_number]):
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_seat_allocation_view', 
                                 student_id=original_student_id, 
                                 subject_name=original_subject_name))
        
        execute_query(
            """UPDATE seat_allocation 
            SET student_id = %s,
                dept_id = %s,
                semester = %s,
                subject_name = %s,
                seat_number = %s,
                room_number = %s
            WHERE student_id = %s AND subject_name = %s""",
            (student_id, dept_id, semester, subject_name, seat_number, room_number,
             original_student_id, original_subject_name)
        )
        flash('Seat allocation updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating seat allocation: {str(e)}', 'danger')
    
    return redirect(url_for('manage_seat_allocation'))

@app.route('/admin/seat-allocation/delete/<student_id>/<subject_name>', methods=['POST'])
@admin_required
def delete_seat_allocation(student_id, subject_name):
    try:
        execute_query(
            """DELETE FROM seat_allocation 
            WHERE student_id = %s AND subject_name = %s""",
            (student_id, subject_name)
        )
        flash('Seat allocation deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting seat allocation: {str(e)}', 'danger')
    
    return redirect(url_for('manage_seat_allocation'))
# Dialogflow Webhook Integration

def handle_seat_allocation(params):
    student_id = params.get('studentid', '').upper()
    if not student_id:
        return "Please provide a valid student ID."
    
    result = execute_query(
        """SELECT student_id, subject_name, seat_number, room_number 
        FROM seat_allocation 
        WHERE student_id = %s""",
        (student_id,),
        fetch_one=True
    )
    if result:
        return f"""Seat Allocation for {result['student_id']}:
        • Subject: {result['subject_name']}
        • Seat No: {result['seat_number']}
        • Room No: {result['room_number']}"""
    return f"No allocation found for {student_id}."

    INTENT_HANDLERS = {
    'seatallocation': handle_seat_allocation,
    'getsyllabus': handle_syllabus_request,
    'campusnavigation': handle_navigation_request,
    # Add other intent handlers
}

@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        data = request.get_json()
        intent = data['queryResult']['intent']['displayName']
        params = data['queryResult']['parameters']
        
        handler = INTENT_HANDLERS.get(intent)
        if not handler:
            return jsonify({'fulfillmentText': "Intent not recognized"})
        
        response = handler(params)
        return jsonify({'fulfillmentText': response})
    
    except Exception as e:
        logging.error(f"Webhook error: {str(e)}")
        return jsonify({'fulfillmentText': "Service unavailable"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', True))
