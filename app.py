import os
import json
import base64
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import requests
from functools import wraps
import sqlite3
from contextlib import contextmanager

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATA_FOLDER'] = 'data'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size

# Environment variables
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
JWT_SECRET = app.config['SECRET_KEY']

# Initialize Flask extensions
CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"])
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATA_FOLDER'], exist_ok=True)

# Database setup
DATABASE_PATH = os.path.join(app.config['DATA_FOLDER'], 'grading_platform.db')

def init_database():
    """Initialize SQLite database with tables"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'teacher')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Assignments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assignments (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                subject TEXT,
                max_points INTEGER DEFAULT 100,
                due_date TIMESTAMP,
                teacher_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (teacher_id) REFERENCES users (id)
            )
        ''')
        
        # Submissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                assignment_id TEXT,
                student_id TEXT,
                file_path TEXT,
                file_name TEXT,
                mime_type TEXT,
                status TEXT DEFAULT 'submitted',
                grade INTEGER,
                feedback TEXT,
                ai_analysis TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                graded_at TIMESTAMP,
                uploaded_by TEXT,
                FOREIGN KEY (assignment_id) REFERENCES assignments (id),
                FOREIGN KEY (student_id) REFERENCES users (id),
                FOREIGN KEY (uploaded_by) REFERENCES users (id)
            )
        ''')
        
        # Create initial data if tables are empty
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:
            # Create default users
            users_data = [
                ('user-1', 'Alice Johnson', 'alice@school.edu', generate_password_hash('Student123!'), 'student'),
                ('user-2', 'Bob Smith', 'bob@school.edu', generate_password_hash('Student123!'), 'student'),
                ('user-3', 'Dr. Wilson', 'wilson@school.edu', generate_password_hash('Teacher123!'), 'teacher')
            ]
            cursor.executemany(
                'INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
                users_data
            )
            
            # Create default assignment
            cursor.execute('''
                INSERT INTO assignments (id, title, description, subject, max_points, due_date, teacher_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('assign-1', 'Algebra Quiz #1', 'Complete all algebraic equations and show your work', 
                  'Math', 100, datetime.now() + timedelta(days=30), 'user-3'))
        
        conn.commit()
        print("✅ Database initialized successfully")

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    try:
        yield conn
    finally:
        conn.close()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user_id = data['user_id']
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE id = ?', (current_user_id,))
                current_user = cursor.fetchone()
                
                if not current_user:
                    return jsonify({'error': 'User not found'}), 401
                    
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(dict(current_user), *args, **kwargs)
    
    return decorated

def role_required(roles):
    """Role-based access control decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            if current_user['role'] not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

# Utility functions
def allowed_file(filename):
    """Check if uploaded file is allowed"""
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_token(user_id):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

# Routes

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_file('templates/index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ('email', 'password', 'name', 'role')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if data['role'] not in ['student', 'teacher']:
            return jsonify({'error': 'Invalid role'}), 400
        
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
            if cursor.fetchone():
                return jsonify({'error': 'User already exists'}), 400
            
            # Create user
            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(data['password'])
            
            cursor.execute('''
                INSERT INTO users (id, name, email, password, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, data['name'], data['email'], hashed_password, data['role']))
            
            conn.commit()
            
            # Generate token
            token = generate_token(user_id)
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user_id,
                    'name': data['name'],
                    'email': data['email'],
                    'role': data['role']
                }
            }), 201
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ('email', 'password')):
            return jsonify({'error': 'Email and password required'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (data['email'],))
            user = cursor.fetchone()
            
            if not user or not check_password_hash(user['password'], data['password']):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            token = generate_token(user['id'])
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role']
                }
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    """Verify JWT token"""
    return jsonify({
        'success': True,
        'user': {
            'id': current_user['id'],
            'name': current_user['name'],
            'email': current_user['email'],
            'role': current_user['role']
        }
    })

# Assignment routes
@app.route('/api/assignments', methods=['GET'])
@token_required
def get_assignments(current_user):
    """Get assignments based on user role"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            if current_user['role'] == 'teacher':
                cursor.execute('''
                    SELECT * FROM assignments 
                    WHERE teacher_id = ? AND is_active = 1 
                    ORDER BY created_at DESC
                ''', (current_user['id'],))
            else:  # student
                cursor.execute('''
                    SELECT * FROM assignments 
                    WHERE is_active = 1 
                    ORDER BY created_at DESC
                ''')
            
            assignments = [dict(row) for row in cursor.fetchall()]
            return jsonify({'assignments': assignments})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments', methods=['POST'])
@token_required
@role_required(['teacher'])
def create_assignment(current_user):
    """Create a new assignment"""
    try:
        data = request.get_json()
        
        required_fields = ['title', 'description', 'subject', 'max_points', 'due_date']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            assignment_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO assignments (id, title, description, subject, max_points, due_date, teacher_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (assignment_id, data['title'], data['description'], data['subject'],
                  data['max_points'], data['due_date'], current_user['id']))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'assignment_id': assignment_id,
                'message': 'Assignment created successfully'
            }), 201
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Submission routes
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """Upload a file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        assignment_id = request.form.get('assignment_id')
        student_id = request.form.get('student_id', current_user['id'])
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        if not assignment_id:
            return jsonify({'error': 'Assignment ID required'}), 400
        
        # Verify assignment exists
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assignments WHERE id = ?', (assignment_id,))
            assignment = cursor.fetchone()
            
            if not assignment:
                return jsonify({'error': 'Assignment not found'}), 404
            
            # For teacher uploads, validate student
            if current_user['role'] == 'teacher' and student_id != current_user['id']:
                cursor.execute('SELECT * FROM users WHERE id = ? AND role = ?', (student_id, 'student'))
                student = cursor.fetchone()
                if not student:
                    return jsonify({'error': 'Student not found'}), 404
            
            # Check for existing submission
            cursor.execute('''
                SELECT id FROM submissions 
                WHERE assignment_id = ? AND student_id = ?
            ''', (assignment_id, student_id))
            
            existing = cursor.fetchone()
            if existing:
                return jsonify({'error': 'Submission already exists'}), 409
            
            # Save file
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Create submission record
            submission_id = str(uuid.uuid4())
            cursor.execute('''
                INSERT INTO submissions (id, assignment_id, student_id, file_path, file_name, mime_type, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (submission_id, assignment_id, student_id, unique_filename, filename, file.content_type, current_user['id']))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'submission_id': submission_id,
                'file_info': {
                    'filename': unique_filename,
                    'original_name': filename,
                    'mime_type': file.content_type
                }
            }), 201
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions', methods=['GET'])
@token_required
def get_submissions(current_user):
    """Get submissions based on user role"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            
            if current_user['role'] == 'teacher':
                cursor.execute('''
                    SELECT s.*, a.title as assignment_title, u.name as student_name
                    FROM submissions s
                    JOIN assignments a ON s.assignment_id = a.id
                    JOIN users u ON s.student_id = u.id
                    WHERE a.teacher_id = ?
                    ORDER BY s.submitted_at DESC
                ''', (current_user['id'],))
            else:  # student
                cursor.execute('''
                    SELECT s.*, a.title as assignment_title
                    FROM submissions s
                    JOIN assignments a ON s.assignment_id = a.id
                    WHERE s.student_id = ?
                    ORDER BY s.submitted_at DESC
                ''', (current_user['id'],))
            
            submissions = [dict(row) for row in cursor.fetchall()]
            return jsonify({'submissions': submissions})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions/<submission_id>/analyze', methods=['POST'])
@token_required
@role_required(['teacher'])
def analyze_submission(current_user, submission_id):
    """Analyze submission using AI"""
    try:
        if not GEMINI_API_KEY:
            return jsonify({'error': 'AI analysis not configured'}), 500
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get submission with assignment info
            cursor.execute('''
                SELECT s.*, a.title as assignment_title, a.teacher_id
                FROM submissions s
                JOIN assignments a ON s.assignment_id = a.id
                WHERE s.id = ?
            ''', (submission_id,))
            
            submission = cursor.fetchone()
            if not submission:
                return jsonify({'error': 'Submission not found'}), 404
            
            # Check if teacher owns the assignment
            if submission['teacher_id'] != current_user['id']:
                return jsonify({'error': 'Access denied'}), 403
            
            # Read file and convert to base64
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], submission['file_path'])
            if not os.path.exists(file_path):
                return jsonify({'error': 'File not found'}), 404
            
            with open(file_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode('utf-8')
            
            # Prepare AI request
            prompt = """You are an expert math teacher's assistant. Analyze the following student submission (a math test).
Provide a detailed analysis in a structured JSON format. The JSON object must contain exactly three keys:
1. "recommendedGrade": An integer between 0 and 100 representing a fair grade for the work.
2. "positivePoints": An array of strings highlighting what the student did well.
3. "areasForImprovement": An array of strings suggesting where the student can improve.

Respond ONLY with valid JSON, no additional text or formatting."""
            
            # Build API payload
            if submission['mime_type'].startswith('image/') or submission['mime_type'] == 'application/pdf':
                payload = {
                    "contents": [{
                        "role": "user",
                        "parts": [
                            {"text": prompt},
                            {
                                "inlineData": {
                                    "mimeType": submission['mime_type'],
                                    "data": file_data
                                }
                            }
                        ]
                    }],
                    "generationConfig": {
                        "temperature": 0.4,
                        "topK": 32,
                        "topP": 1,
                        "maxOutputTokens": 4096
                    }
                }
            else:
                # For text files
                text_content = base64.b64decode(file_data).decode('utf-8')
                payload = {
                    "contents": [{
                        "role": "user",
                        "parts": [{"text": f"{prompt}\n\nStudent work to analyze:\n{text_content}"}]
                    }],
                    "generationConfig": {
                        "temperature": 0.4,
                        "topK": 32,
                        "topP": 1,
                        "maxOutputTokens": 4096
                    }
                }
            
            # Call Gemini API
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
            
            response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
            
            if not response.ok:
                return jsonify({'error': f'AI analysis failed: {response.text}'}), 500
            
            data = response.json()
            
            if 'candidates' in data and data['candidates'][0]['content']['parts'][0]['text']:
                analysis_text = data['candidates'][0]['content']['parts'][0]['text'].strip()
                
                # Clean and parse JSON
                analysis_text = analysis_text.replace('```json', '').replace('```', '').strip()
                
                # Find JSON object
                import re
                json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
                if json_match:
                    analysis_text = json_match.group(0)
                
                analysis = json.loads(analysis_text)
                
                # Validate structure
                required_keys = ['recommendedGrade', 'positivePoints', 'areasForImprovement']
                if not all(key in analysis for key in required_keys):
                    raise ValueError("Invalid analysis structure")
                
                # Update submission with AI analysis
                cursor.execute('''
                    UPDATE submissions 
                    SET ai_analysis = ?, grade = ?
                    WHERE id = ?
                ''', (json.dumps(analysis), analysis['recommendedGrade'], submission_id))
                
                conn.commit()
                
                return jsonify(analysis)
            else:
                return jsonify({'error': 'No analysis received from AI'}), 500
                
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/submissions/<submission_id>/grade', methods=['PUT'])
@token_required
@role_required(['teacher'])
def grade_submission(current_user, submission_id):
    """Grade a submission"""
    try:
        data = request.get_json()
        grade = data.get('grade')
        feedback = data.get('feedback', '')
        
        if grade is None or not (0 <= grade <= 100):
            return jsonify({'error': 'Valid grade (0-100) required'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Verify submission and teacher permissions
            cursor.execute('''
                SELECT s.*, a.teacher_id
                FROM submissions s
                JOIN assignments a ON s.assignment_id = a.id
                WHERE s.id = ?
            ''', (submission_id,))
            
            submission = cursor.fetchone()
            if not submission:
                return jsonify({'error': 'Submission not found'}), 404
            
            if submission['teacher_id'] != current_user['id']:
                return jsonify({'error': 'Access denied'}), 403
            
            # Update grade and feedback
            cursor.execute('''
                UPDATE submissions 
                SET grade = ?, feedback = ?, graded_at = CURRENT_TIMESTAMP, status = 'graded'
                WHERE id = ?
            ''', (grade, feedback, submission_id))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Submission graded successfully'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/students', methods=['GET'])
@token_required
@role_required(['teacher'])
def get_students(current_user):
    """Get all students for teacher"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, email, created_at
                FROM users 
                WHERE role = 'student'
                ORDER BY name
            ''')
            
            students = [dict(row) for row in cursor.fetchall()]
            return jsonify({'students': students})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    init_database()
    print("🚀 AI Grading Platform starting...")
    print("📁 Upload folder:", app.config['UPLOAD_FOLDER'])
    print("💾 Database:", DATABASE_PATH)
    print("🌐 Server running at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)