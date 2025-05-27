from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_from_directory, current_app, abort
from markupsafe import escape
from markupsafe import Markup
import os
import subprocess
import pickle
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import hashlib
import secrets
import time
from urllib.parse import unquote
import random
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['TEMPLATES_FOLDER'] = 'templates'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['TEMPLATES_FOLDER']):
    os.makedirs(app.config['TEMPLATES_FOLDER'])

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    showtimes = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<Movie {self.title}>'

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    showtime = db.Column(db.String(50), nullable=False)
    tickets = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref=db.backref('bookings', lazy=True))
    movie = db.relationship('Movie', backref=db.backref('bookings', lazy=True))

    def __repr__(self):
        return f'<Booking for {self.movie.title} by {self.user.username}>'

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    movie = db.relationship('Movie', backref=db.backref('reviews', lazy=True))

    def __repr__(self):
        return f'<Review {self.filename} for {self.movie.title}>'

# Initialize Database
def init_db():
    with app.app_context():
        db.create_all()
        # Add some initial data if the database is empty
        if not User.query.first():
            admin_user = User(username='admin', email='admin@example.com', password=generate_password_hash('adminpassword'))
            user1 = User(username='user1', email='user1@example.com', password=generate_password_hash('test'))
            db.session.add_all([admin_user, user1])

        if not Movie.query.first():
            movie1 = Movie(title='Spectacular Action Movie', genre='Action', rating=4.5, showtimes='10:00,13:00,16:00,19:00')
            movie2 = Movie(title='Romantic Comedy Bliss', genre='Comedy', rating=4.2, showtimes='11:30,15:00,18:30,21:00')
            movie3 = Movie(title='Intriguing Mystery Thriller', genre='Thriller', rating=4.8, showtimes='14:00,17:30,20:00,22:30')
            db.session.add_all([movie1, movie2, movie3])
        db.session.commit()

# Call init_db when the app starts
init_db()

# HTML Templates (as strings to be written to files)


# Write templates to files
 

# Utility function to get a movie by ID
def get_movie(movie_id):
    return db.session.get(Movie, movie_id)

# Routes and View Functions

@app.route('/')
def index():
    movies = db.session.query(Movie).all()
    return render_template('index.html', movies=movies)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = 'Passwords do not match.'
        elif db.session.query(User).filter_by(username=username).first():
            error = 'Username already exists.'
        elif db.session.query(User).filter_by(email=email).first():
            error = 'Email address already exists.'
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

def display_data(data):
    print(f"[VULNERABILITY DEMO] Data to display: {data}")
    return data

# 1. A07:2017 Broken Authentication (now A02:2021 Cryptographic Failures) - Partially addressed with password hashing
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password' # Less informative error
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

# 2. A04:2021 Insecure Design (Insecure Deserialization) - Still present in profile cookie
@app.route('/profile')
def profile():
    profile_cookie = request.cookies.get('profile_data')
    profile_data = None
    user = None
    error_message = None

    if profile_cookie:
        try:
            profile_data = pickle.loads(base64.b64decode(profile_cookie))
        except Exception as e:
            error_message = f"Error deserializing profile data: {e}"
            profile_data = None

    if not profile_data and 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            profile_data = {
                'name': user.username,
                'email': user.email,
                'role': 'user'
            }

    return render_template('profile.html', profile_data=profile_data, user=user, error_message=error_message)


app.route('/set_profile', methods=['POST'])
def set_profile():
    profile = {'name': request.form.get('name'), 'email': request.form.get('email'), 'role': 'user'}
    serialized_profile = base64.b64encode(pickle.dumps(profile)).decode('utf-8')
    response = make_response(redirect(url_for('profile')))
    response.set_cookie('profile_data', serialized_profile)
    return response

# 3. A03:2021 Injection (Command Injection via Filename) - Still present
@app.route('/upload_review', methods=['GET', 'POST'])
def upload_review():
    upload_message = None
    movies = db.session.query(Movie).all()
    if request.method == 'POST':
        if 'review_file' not in request.files:
            upload_message = 'No file part'
        file = request.files['review_file']
        if file.filename == '':
            upload_message = 'No selected file'
        if file and 'user_id' in session:
            filename = secure_filename(file.filename)
            movie_id = int(request.form['movie_id'])
            movie = db.session.get(Movie, movie_id)
            if movie:
                new_review = Review(movie_id=movie_id, filename=filename)
                db.session.add(new_review)
                db.session.commit()
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                upload_message = f'Review "{filename}" for "{movie.title}" uploaded successfully.'
            else:
                upload_message = 'Invalid movie selected.'
        elif not session.get('user_id'):
            upload_message = 'You must be logged in to upload a review.'
    return render_template('upload_review.html', movies=movies, upload_message=upload_message)

@app.route('/uploaded_files')
def view_uploaded():
    if 'user_id' in session:
        # For simplicity, showing all reviews for all movies
        reviews = db.session.query(Review).all()
        return render_template('view_uploaded.html', reviews=reviews)
    else:
        return redirect(url_for('login'))

@app.route('/view_file/<path:filename>')
def view_file(filename):
    upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filepath = os.path.abspath(os.path.join(upload_folder_abs, unquote(filename)))

    if filepath.startswith(upload_folder_abs):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return render_template('view_file_content.html', filename=filename, content=content)
        except FileNotFoundError:
            return "File not found."
        except Exception as e:
            return f"Error: {e}"
    else:
        return "Access Denied: Path traversal detected."
    

# 4. A01:2021 Broken Access Control (Unrestricted File Upload & Access) - Still present

# 5. A03:2021 Injection (SQL Injection - Simulated) - Now using SQLAlchemy
@app.route('/search')
def search():
    return render_template('search.html')
from flask import request, render_template
from sqlalchemy import text  # Import text for raw SQL execution

@app.route('/search_results')
def search_results():
    query = request.args.get('query')
    results = []

    if query and query.lower() == "' or 1=1 --'":
        sql = "SELECT * FROM Movie UNION SELECT id, title, genre, rating, showtimes FROM Movie --"
        print(f"Executing SQL (Special Case): {sql}")
        try:
            results = db.session.execute(text(sql)).fetchall()
            print(f"Results (Special Case): {results}")
        except Exception as e:
            print(f"SQL Error (Special Case): {e}")
            results = []
    elif query: # Default search behavior
        try:
            results = db.session.query(Movie).filter(Movie.title.like(f"%{query}%")).all()
            print(f"Results (Default Search): {results}")
        except Exception as e:
            print(f"SQL Error (Default Search): {e}")
            results = []

    return render_template('search_results.html', query=Markup(query), results=results)

# 7. A03:2021 Injection (Server-Side Template Injection - SSTI) - Potential still exists

@app.route('/movie/<int:movie_id>/reviews')
def view_movie_reviews(movie_id):
    movie = get_movie(movie_id)
    if not movie:
        return "Movie not found."
    reviews = db.session.query(Review).filter_by(movie_id=movie_id).all()
    return render_template('view_reviews.html', movie=movie, reviews=reviews)

import chardet
@app.route('/movie/<int:movie_id>/reviews/<path:filename>') # Use <path:filename> to allow slashes
def view_review_content(movie_id, filename):
    """
    VULNERABLE ROUTE: Displays file content OR executes .py/.ps1 files.
    Vulnerable to Path Traversal via 'filename' parameter.
    Vulnerable to RCE via execution of specified scripts.
    Vulnerable to Command Injection via crafted filenames when shell=True.
    """
    movie = get_movie(movie_id)
    if not movie:
        abort(404, description="Movie not found.")

    # VULNERABILITY (Path Traversal): 'filename' comes directly from the URL path.
    # No sanitization like secure_filename() is applied.
    # os.path.join allows constructing paths, but ../ is not blocked here.
    # os.path.abspath resolves ../ sequences relative to the current working directory
    # or the UPLOAD_FOLDER's absolute path, potentially pointing outside.
    try:
        # Construct the potentially malicious path
        requested_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        filepath = os.path.abspath(requested_path)

        # --- Optional: Flawed check attempt (can often be bypassed) ---
        # upload_folder_abs = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
        # if not filepath.startswith(upload_folder_abs):
        #     print(f"Path Traversal Attempt Blocked? Resolved: {filepath} vs Base: {upload_folder_abs}")
        #     abort(400, description="Invalid file path.") # Bad Request
        # --- End Optional Check ---

        print(f"Attempting to access/execute: {filepath}") # Debugging log

        content = None
        error = None
        is_execution_output = False # Flag for template

        # Check if file exists before proceeding
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File does not exist at resolved path: {filepath}")

        # --- Execute if .py or .ps1 ---
        if filename.endswith('.py'):
            is_execution_output = True
            # VULNERABILITY (Command Injection): Path directly in command string
            command_to_run = f"python \"{filepath}\""
            print(f"Executing command: {command_to_run}")
            try:
                # VULNERABILITY: RCE via Command Injection (shell=True)
                result = subprocess.run(
                    command_to_run, shell=True, capture_output=True, text=True,
                    timeout=10, check=False # Don't raise error on non-zero exit
                )
                content = f" '{escape(filename)}' ---\n" # Escape filename for display
                content += f"{result.stdout}\n  \n"
              
            except subprocess.TimeoutExpired:
                error = f"Execution timed out for '{escape(filename)}'."
            except Exception as e:
                error = f"Error executing Python script '{escape(filename)}': {type(e).__name__}"
                print(f"RCE Python Error: {e}") # Log full error server-side

        elif filename.endswith('.ps1'):
            is_execution_output = True
            # VULNERABILITY (Command Injection): Path directly in command string
            command_to_run = f"powershell -ExecutionPolicy Bypass -File \"{filepath}\""
            print(f"Executing command: {command_to_run}")
            try:
                 # VULNERABILITY: RCE via Command Injection (shell=True)
                result = subprocess.run(
                    command_to_run, shell=True, capture_output=True, text=True,
                    timeout=15, check=False
                )
                content = f"--- PowerShell Execution Output for '{escape(filename)}' ---\n" # Escape filename
                content += f"Exit Code: {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
                content += "\n--- End Output ---"
            except subprocess.TimeoutExpired:
                error = f"Execution timed out for '{escape(filename)}'."
            except Exception as e:
                error = f"Error executing PowerShell script '{escape(filename)}': {type(e).__name__}"
                print(f"RCE PowerShell Error: {e}") # Log full error server-side

        # --- Otherwise, read and display content ---
        else:
            is_execution_output = False
            try:
                with open(filepath, 'rb') as f:
                    raw_data = f.read()
                # Detect encoding (best effort)
                detection = chardet.detect(raw_data)
                # Use detected encoding if confidence is reasonable, else fallback
                detected_encoding = detection['encoding'] if detection['confidence'] and detection['confidence'] > 0.6 else 'utf-8'
                print(f"Detected encoding: {detected_encoding} with confidence {detection.get('confidence')}")

                try:
                    # Decode using detected or fallback encoding, replace errors
                    content = raw_data.decode(detected_encoding, errors='replace')
                except Exception as decode_error:
                    error = f"Error decoding file with encoding '{detected_encoding}': {decode_error}. Trying UTF-8 fallback."
                    print(error)
                    try:
                        # Fallback to UTF-8
                        content = raw_data.decode('utf-8', errors='replace')
                    except Exception as utf8_error:
                        error = f"Error decoding file even with UTF-8: {utf8_error}"
                        print(error)
                        content = "[Binary or Undecodable File Content]"

            except Exception as read_error:
                # Catch potential permission errors during open() or read()
                error = f"Error reading file '{escape(filename)}': {type(read_error).__name__}"
                print(f"File Read Error: {read_error}")


    except FileNotFoundError:
        # Catch file not existing after path resolution
        abort(404, description=f"File not found at resolved path for '{escape(filename)}'.")
    except Exception as e:
        # Catch unexpected errors during path processing or file access
        print(f"General Error in view_review_content: {e}") # Log full error
        abort(500, description=f"An unexpected error occurred processing '{escape(filename)}'.") # Internal Server Error

    # Render the template, passing the content (file or output), filename, error, and type flag
    return render_template('view_file_content.html',
                           filename=filename, # Pass original filename for display
                           content=content,
                           error=error,
                           is_output=is_execution_output)

# 8. A05:2021 Security Misconfiguration - Still present

@app.route('/book_movie/<int:movie_id>', methods=['GET', 'POST'])
def book_movie(movie_id):
    movie = get_movie(movie_id)
    if not movie:
        return "Movie not found."
    booking_error = None
    if request.method == 'POST':
        if 'user_id' not in session:
            booking_error = "You must be logged in to book tickets."
        else:
            showtime = request.form['showtime']
            tickets = int(request.form['tickets'])
            user_id = session['user_id']
            new_booking = Booking(user_id=user_id, movie_id=movie_id, showtime=showtime, tickets=tickets)
            db.session.add(new_booking)
            db.session.commit()
            return f"Booking confirmed for {tickets} tickets for {movie.title} at {showtime}."
    return render_template('book_movie.html', movie=movie, booking_error=booking_error)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)