# Detailed Code Explanation: Line-by-Line

This document provides line-by-line explanations of key code sections.

---

## FILE: src/app.py - Main Application (Lines 1-100)

### Lines 1-20: Imports

```python
import logging                                    # For writing application logs
import re                                         # Regular expressions for validation
from flask import Flask, render_template, ...    # Flask web framework core
from flask_wtf.csrf import CSRFProtect           # Cross-Site Request Forgery protection
from flask_mail import Mail, Message            # Email sending functionality
from functools import wraps                      # Decorator utilities
import sqlite3                                   # SQLite database driver
import os                                        # Operating system utilities
import csv                                       # CSV file reading/writing
import io                                        # In-memory file operations
import json                                      # JSON serialization
import shutil                                    # File operations (copy, move)
import bcrypt                                    # Password hashing library
import random                                    # Random number/choice generation
import string                                    # String constants (digits, letters)
from datetime import datetime, timedelta         # Date/time manipulation
from werkzeug.utils import secure_filename       # Sanitize uploaded filenames
from pathlib import Path                         # Object-oriented path handling
from encryption_utils import get_encryption_handler, should_encrypt_field
```

**Why each import:**

- `logging`: Tracks application events (errors, info)
- `re`: Validates emails, usernames with patterns
- `flask`: Core web framework
- `CSRFProtect`: Security against form forgery attacks
- `Mail/Message`: Send email (password resets)
- `wraps`: Preserves function names in decorators
- `sqlite3`: Database queries
- `json`: Convert Python objects to JSON (audit logs)
- `bcrypt`: One-way password hashing
- `datetime`: Manage time-based operations (token expiry, timestamps)

### Lines 21-28: Logging Configuration

```python
logging.basicConfig(
    level=logging.INFO,  # Only log INFO level and above (not DEBUG)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)  # Create logger for this module
```

**Purpose:**

- Configures what messages are logged
- Format: Timestamp - Module Name - Level - Message
- Creates logger object for `app.py` module

**Log Levels (in order):**

- DEBUG: Detailed diagnostic info
- INFO: General informational messages
- WARNING: Warning messages
- ERROR: Error messages
- CRITICAL: Critical errors

### Lines 29-32: Environment Variables

```python
try:
    from dotenv import load_dotenv
    load_dotenv()  # Loads variables from .env file
except ImportError:
    logger.warning("python-dotenv not installed...")
```

**Purpose:**

- Loads configuration from `.env` file (not committed to git)
- Example `.env` contents:
  ```
  FLASK_DEBUG=True
  MAIL_USERNAME=noreply@school.edu
  MAIL_PASSWORD=secret123
  DATABASE_ENCRYPTION_KEY=base64encodedkey
  ```

### Lines 35-43: Flask App Initialization

```python
from flask import Flask
app = Flask(__name__,
    template_folder=os.path.join(PROJECT_ROOT, 'templates'),
    static_folder=os.path.join(PROJECT_ROOT, 'static')
)
```

**Explanation:**

- `Flask(__name__)`: Creates Flask app instance
- `template_folder`: Where HTML templates are located
- `static_folder`: Where CSS, JS, images are located
- `PROJECT_ROOT`: Parent directory of `src/` folder

### Lines 45-53: Secret Key Management

```python
SECRET_KEY_FILE = os.path.join(PROJECT_ROOT, 'config', '.secret_key')
os.makedirs(os.path.dirname(SECRET_KEY_FILE), exist_ok=True)

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)
```

**Process:**

1. Check if `.secret_key` file exists
2. If yes: Load key from file (persistent across restarts)
3. If no:
   - Try to get from `SECRET_KEY` environment variable
   - Fallback: Generate 32 random bytes converted to hex string
   - Save to file for future use

**Why Persistent Key:**

- Session cookies signed with this key
- If key changes, all sessions invalidated
- Users logged out after restart (bad UX)
- Persistent key maintains sessions

### Lines 55-57: CSRF Protection

```python
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None
```

**CSRF Explanation:**

- Attacker trick: Force user to submit form on different site
- Example: Attacker posts `<form action="myapp/delete-user">` on malicious site
- User visits and clicks, unintentionally deletes record
- Protection: Requires CSRF token in all forms (random, unique per session)
- User must submit token from legitimate form to succeed
- `TIME_LIMIT = None`: Token never expires (safer but less flexible)

### Lines 59-65: Email Configuration

```python
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER',
    'noreply@lyfjshs.edu.ph')

mail = Mail(app)
```

**Email Settings:**

- `MAIL_SERVER`: SMTP server host (Gmail by default)
- `MAIL_PORT`: 587 (TLS port, not 465 SSL or 25)
- `MAIL_USE_TLS`: Encrypt connection to server
- `MAIL_USERNAME/PASSWORD`: SMTP authentication credentials
- `MAIL_DEFAULT_SENDER`: From address in emails
- `mail = Mail(app)`: Initialize Flask-Mail

### Lines 70-80: Database & Directory Setup

```python
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')
DOCUMENTS_DIR = os.path.join(PROJECT_ROOT, 'documents')
PROFILE_PICS_DIR = os.path.join(PROJECT_ROOT, 'static', 'profile_pics')

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(DOCUMENTS_DIR, exist_ok=True)
os.makedirs(PROFILE_PICS_DIR, exist_ok=True)
```

**Purpose:**

- Define paths to database and directories
- Create directories if they don't exist
- `exist_ok=True`: Don't error if directory already exists

### Lines 82-85: File Upload Configuration

```python
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xlsx', 'xls'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
```

**Security:**

- Only allows specific file types (blacklist prevented)
- Prevents executable uploads (.exe, .sh)
- Image extensions subset for profile pictures
- Maximum file size prevents disk space attacks

---

## FILE: src/app.py - Helper Functions (Lines 150-250)

### Lines 170-185: Database Connection

```python
def get_db_connection():
    """Get database connection with error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None
```

**Explanation:**

- `sqlite3.connect()`: Opens database file
- `row_factory = sqlite3.Row`: Allows accessing columns by name instead of index

  ```python
  # Without row_factory:
  name = row[0]  # Must know column index

  # With row_factory:
  name = row['name']  # More readable
  name = row[1]  # Still works
  ```

- Returns None if connection fails (error handled gracefully)

### Lines 228-245: Password Hashing

```python
def hash_password(password):
    """Hash password using bcrypt with salt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
```

**bcrypt Process:**

1. `password.encode()`: Convert string to bytes (bcrypt requires bytes)
2. `bcrypt.gensalt()`: Generate random salt (different each call)
3. `bcrypt.hashpw(password, salt)`: Hash password with salt
4. `.decode()`: Convert bytes result back to string for storage
5. Returns something like: `$2b$12$hash...` (includes salt and algorithm)

**Key Feature:**

- Each call produces different hash (includes different salt)
- But all hashes correctly verify same password
- Example: "password123" might hash to:
  - First call: `$2b$12$abcd...xyz`
  - Second call: `$2b$12$efgh...uvw`
  - Both verify correctly against "password123"

### Lines 290-320: User Validation

```python
def validate_user_input(fullname, username, email, password, confirm_password=None):
    """Validate required user registration fields"""
    if not all([fullname, username, email, password]):
        return False, "All fields are required."

    return validate_password(password, confirm_password)

def validate_password(password, confirm_password=None):
    """Validate password requirements"""
    if not password:
        return False, "Password is required."

    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."

    return True, ""
```

**Returns:**

- Tuple: (is_valid: bool, message: str)
- Example: `(False, "Passwords do not match.")`

---

## FILE: src/app.py - Authentication Routes (Lines 580-720)

### Lines 581-617: /register Route (Detailed)

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    """Public user registration (creates pending users)"""

    # Only process POST requests (GET shows form)
    if request.method == "POST":
        # Extract and clean form inputs (strip() removes whitespace)
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        advisory_class = request.form.get("advisory_class", "").strip()

        # Step 1: Validate inputs
        is_valid, message = validate_user_input(
            fullname, username, email, password, confirm_password
        )
        if not is_valid:
            flash(message, "danger")  # Show error message to user
            return render_template("auth/register.html")

        # Step 2: Check if username already exists
        username_check = username_exists(username)
        if username_check is None:
            # Database error
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/register.html")
        elif username_check:
            # Username taken
            flash("Username already exists. Please choose another.", "danger")
            return render_template("auth/register.html")

        # Step 3: Create user in database
        success, user_id, message = create_user_in_db(
            username, password, fullname, email,
            role='pending',  # New users have 'pending' role
            advisory_class=advisory_class
        )

        if not success:
            flash(f"Registration failed: {message}", "danger")
            return render_template("auth/register.html")

        # Step 4: Success - redirect to login
        flash("Registration successful! You can now login. Awaiting admin to assign your role.", "success")
        return redirect(url_for("login"))

    # GET request - show empty registration form
    return render_template("auth/register.html")
```

**Request Form Data:**

```html
<form method="POST">
  <input name="fullname" placeholder="Full Name" />
  <input name="username" placeholder="Username" />
  <input name="email" placeholder="Email" />
  <input name="password" type="password" />
  <input name="confirm_password" type="password" />
  <select name="advisory_class">
    <option value="">Not a Class Advisor</option>
    <option value="Grade 11">Grade 11</option>
  </select>
</form>
```

**Database Insert** (in `create_user_in_db`):

```sql
INSERT INTO users (username, password, fullname, email, role, is_active, advisory_class)
VALUES ('john_doe', '$2b$12$hash...', 'John Doe', 'john@school.edu', 'pending', 1, NULL)
```

### Lines 676-716: /login Route (Detailed)

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with credentials validation and session setup"""

    if request.method == "POST":
        # Get form inputs
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Validate inputs are provided
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("auth/index.html")

        # Authenticate user (check username and password hash)
        is_authentic, user = authenticate_user(username, password)
        if not is_authentic:
            flash("Invalid username or password.", "danger")
            return render_template("auth/index.html")

        # Check if account is still active (not disabled by admin)
        is_active = safe_row_get(user, 'is_active', 1)
        if not is_active:
            flash("Your account has been disabled. Please contact the administrator.", "danger")
            return render_template("auth/index.html")

        # Set session variables (stored in secure cookie)
        session["logged_in"] = True           # Flag to check if authenticated
        session["user_id"] = user["id"]       # User primary key
        session["username"] = user["username"]  # Display name
        session["role"] = safe_row_get(user, "role", "health_officer")  # User permission level

        # Log successful login for audit trail
        log_audit("LOGIN", "users", user["id"])

        # Show success message
        flash(f"Welcome back, {user['fullname']}!", "success")

        # Redirect pending users to approval page
        if session["role"] == "pending":
            return redirect(url_for("pending_approval"))

        # Redirect other users to dashboard
        return redirect(url_for("dashboard"))

    # GET request - show login form
    return render_template("auth/index.html")
```

**Session Flow:**

1. User fills login form (HTML form with username/password)
2. Form POSTs to /login
3. Python authenticates credentials
4. If valid, creates session (encrypted cookie stored in browser)
5. User's browser includes cookie in all future requests
6. Server reads cookie, verifies it, knows user is logged in

**Session Cookie Details:**

- Encrypted with `app.secret_key`
- Tamper-evident (Flask validates signature)
- Expires when browser closes (session-based)
- Contains: `logged_in`, `user_id`, `username`, `role`

### Lines 731-827: /forgot-password Route (Simplified)

```python
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Handle forgot password request - user enters email"""

    # Rate limiting: max 5 attempts per hour per IP
    client_ip = request.remote_addr or "unknown"
    rate_limit_key = f"pwd_reset_{client_ip}"

    current_time = datetime.now()
    attempts = session.get(rate_limit_key, [])

    # Remove attempts older than 1 hour
    attempts = [t for t in attempts if isinstance(t, (int, float))
                and t > current_time.timestamp() - 3600]

    if len(attempts) >= 5:
        # Too many attempts
        flash("Too many password reset attempts. Please try again in an hour.", "danger")
        return render_template("auth/forgot_password.html")

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("auth/forgot_password.html")

        # Validate email format with regex
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash("Please enter a valid email address.", "danger")
            return render_template("auth/forgot_password.html")

        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/forgot_password.html")

        try:
            cursor = db.cursor()

            # Periodically clean up expired tokens (1 in 10 requests)
            if random.randint(1, 10) == 1:
                current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                cursor.execute(
                    "DELETE FROM password_reset_tokens WHERE expires_at < ?",
                    (current_time_str,)
                )

            # Find user by email
            cursor.execute("SELECT id, fullname FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            # Record attempt (timestamp to avoid timezone issues)
            attempts.append(current_time.timestamp())
            session[rate_limit_key] = attempts

            if not user:
                # For security, don't reveal if email exists or not
                flash("If that email address is associated with an account, you will receive a reset code.",
                      "success")
                db.close()
                return redirect(url_for("login"))

            user_id = user['id']
            user_fullname = user['fullname']

            # Generate 6-digit reset code
            reset_code = ''.join(random.choices(string.digits, k=6))

            # Delete any existing reset tokens for this user
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ? AND is_used = 0",
                (user_id,)
            )

            # Create new reset token (expires in 15 minutes)
            expires_at = datetime.now() + timedelta(minutes=15)
            cursor.execute("""
                INSERT INTO password_reset_tokens
                (user_id, email, reset_code, expires_at)
                VALUES (?, ?, ?, ?)
            """, (user_id, email, reset_code, expires_at))

            db.commit()
            db.close()

            # Send reset code via email
            email_sent, email_message = send_password_reset_email(
                email, user_fullname, reset_code
            )

            if email_sent:
                flash(f"Reset code has been sent to {email}.", "success")
            else:
                flash("Account found, but could not send email.", "warning")

            return redirect(url_for("verify_reset_code", email=email))

        except sqlite3.Error as e:
            flash("An error occurred. Please try again.", "danger")
            if db:
                db.close()
            return render_template("auth/forgot_password.html")

    return render_template("auth/forgot_password.html")
```

**Reset Code Table Structure:**

```sql
CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    email TEXT,
    reset_code TEXT,  -- 6-digit code
    expires_at TIMESTAMP,  -- 15 minutes from creation
    is_used INTEGER DEFAULT 0,  -- 0 = unused, 1 = used
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## FILE: src/app.py - Decorators (Lines 400-450)

### Lines 410-430: @require_role Decorator

```python
def require_role(*allowed_roles):
    """Decorator to check user role"""

    # *allowed_roles allows multiple roles: @require_role('admin', 'health_officer')
    def decorator(f):
        @wraps(f)  # Preserve original function name and docstring
        def decorated_function(*args, **kwargs):

            # Check if user is logged in
            if not session.get("logged_in"):
                flash("Please login first.", "warning")
                return redirect(url_for("login"))

            # Get database connection
            db = get_db_connection()
            if not db:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))

            try:
                # Get user's role from database
                cursor = db.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?",
                             (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()

                # Check if user's role is in allowed list
                if not user or safe_row_get(user, 'role') not in allowed_roles:
                    flash("You don't have permission to access this page.", "danger")
                    return redirect(url_for("dashboard"))

                # User authorized - call original function
                return f(*args, **kwargs)

            except sqlite3.Error:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))

        return decorated_function
    return decorator
```

**Usage Example:**

```python
@app.route("/admin-only")
@require_role('super_admin')  # Only super_admin can access
def admin_only():
    return "Admin content"

@app.route("/health-management")
@require_role('super_admin', 'health_officer')  # Multiple roles allowed
def health_management():
    return "Health officer content"
```

**Decorator Flow:**

1. User requests `/admin-only`
2. Flask routes to `admin_only()` function
3. But first, `require_role` decorator intercepts
4. Decorator checks if user has 'super_admin' role
5. If yes: Calls original function
6. If no: Redirects to dashboard

**@wraps Purpose:**

```python
# Without @wraps:
def require_role(*allowed_roles):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@require_role('admin')
def my_function():
    """This is my function"""
    pass

print(my_function.__name__)  # Prints: 'decorated_function' (wrong!)

# With @wraps:
from functools import wraps

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)  # Copies metadata from f
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

print(my_function.__name__)  # Prints: 'my_function' (correct!)
```

---

## FILE: src/encryption_utils.py (Full Explanation)

### Lines 1-30: Class Definition and Initialization

```python
class DataEncryption:
    """Handle encryption and decryption of sensitive data"""

    def __init__(self, master_key=None):
        """Initialize encryption with a master key"""

        # If master_key provided, use it
        if master_key:
            self.key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            # Fallback: get or create key
            self.key = self._get_or_create_key()

        try:
            # Create Fernet cipher object with the key
            self.cipher = Fernet(self.key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")
```

**Fernet Encryption Explained:**

- **Symmetric**: Same key encrypts and decrypts
- **Authenticated**: Detects tampering
- **Time-stamped**: Includes creation timestamp in ciphertext
- **Non-reusable**: Same plaintext produces different ciphertext (includes random IV)

**Key Format:**

- Fernet requires 32 bytes of random data
- Encoded as base64 for storage/display
- Example: `Fz1Z7PbwHaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=`

### Lines 31-48: Get or Create Encryption Key

```python
def _get_or_create_key(self):
    """Get encryption key from environment or create/load from file"""

    # First, check environment variable
    key_env = os.environ.get('DATABASE_ENCRYPTION_KEY')
    if key_env:
        return key_env.encode()

    # Second, check if key file exists
    key_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'config',
        '.encryption_key'
    )
    os.makedirs(os.path.dirname(key_file), exist_ok=True)

    if os.path.exists(key_file):
        # Load existing key from file
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new key and save it
        key = Fernet.generate_key()  # Generate 32 random bytes, base64 encoded
        with open(key_file, 'wb') as f:
            f.write(key)

        # Restrict file permissions to owner only (user can read/write, others cannot)
        os.chmod(key_file, 0o600)

        return key
```

**File Permissions (0o600):**

```
0o600 = -rw-------
- Owner can read and write
- Group cannot access
- Others cannot access
```

**Priority for Key:**

1. Environment variable `DATABASE_ENCRYPTION_KEY` (for production, secrets manager)
2. File `config/.encryption_key` (for development)
3. Generate new key and save to file (first run)

### Lines 49-65: Encryption Function

```python
def encrypt(self, plaintext):
    """Encrypt plaintext string to ciphertext"""

    if not plaintext:
        return None  # Don't encrypt empty values

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')  # Convert string to bytes

    try:
        # Fernet.encrypt() returns bytes
        ciphertext = self.cipher.encrypt(plaintext)

        # Decode bytes to string for database storage
        return ciphertext.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")
```

**Encryption Process:**

```
Plaintext: "Penicillin Allergy"
    ↓
encode to bytes: b"Penicillin Allergy"
    ↓
Fernet.encrypt(): b"gAAAAABl_5R9...(base64 encoded)..."
    ↓
decode to string: "gAAAAABl_5R9...(base64 encoded)..."
    ↓
Stored in database as string
```

**Why encode/decode:**

- Fernet works with bytes
- Database stores strings
- Must convert: string → bytes → encrypt → bytes → string

### Lines 66-82: Decryption Function

```python
def decrypt(self, ciphertext):
    """Decrypt ciphertext back to plaintext"""

    if not ciphertext:
        return None

    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')

    try:
        # Fernet.decrypt() verifies signature and decrypts
        plaintext = self.cipher.decrypt(ciphertext)

        # Decode bytes to string
        return plaintext.decode('utf-8')

    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
```

**Decryption Process:**

```
Ciphertext: "gAAAAABl_5R9...(base64 encoded)..."
    ↓
encode to bytes: b"gAAAAABl_5R9...(base64 encoded)..."
    ↓
Fernet.decrypt():
  - Verifies signature (no tampering)
  - Decrypts: b"Penicillin Allergy"
    ↓
decode to string: "Penicillin Allergy"
    ↓
Returned to caller
```

**If Decryption Fails:**

- Raises exception (tampering detected or wrong key)
- Not caught here (caller must handle)

---

## FILE: HTML Templates Examples

### templates/auth/register.html (Typical Structure)

```html
{% extends "shared/base.html" %} {% block content %}
<div class="container">
  <h2>Register</h2>

  {% if error %}
  <div class="alert alert-danger">{{ error }}</div>
  {% endif %}

  <form method="POST">
    <!-- CSRF token (hidden field) -->
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />

    <div class="form-group">
      <label>Full Name</label>
      <input type="text" name="fullname" required />
    </div>

    <div class="form-group">
      <label>Username</label>
      <input type="text" name="username" required />
    </div>

    <div class="form-group">
      <label>Email</label>
      <input type="email" name="email" required />
    </div>

    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" required />
    </div>

    <div class="form-group">
      <label>Confirm Password</label>
      <input type="password" name="confirm_password" required />
    </div>

    <button type="submit" class="btn btn-primary">Register</button>
  </form>
</div>
{% endblock %}
```

**Key HTML Features:**

- `{% extends "shared/base.html" %}`: Inherits from base template
- `{% block content %}`: Overrides content block from base
- `{{ csrf_token() }}`: Inserts CSRF token (must include)
- `{{ variable }}`: Jinja2 template variable insertion
- `{% if condition %}...{% endif %}`: Template conditionals

### templates/shared/base.html (Master Template)

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LYFJSHS Health Record System</title>
    <link
      rel="stylesheet"
      href="{{ url_for('static', filename='css/style.css') }}"
    />
    {% block extra_css %}{% endblock %}
  </head>
  <body>
    {% include "components/header.html" %}

    <div class="sidebar">
      {% if current_user %}
      <p>Welcome, {{ current_user.fullname }}</p>
      <ul>
        <li><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
        {% if current_user.role in ['super_admin', 'health_officer'] %}
        <li><a href="{{ url_for('add_student') }}">Add Student</a></li>
        {% endif %}
        <li><a href="{{ url_for('logout') }}">Logout</a></li>
      </ul>
      {% endif %}
    </div>

    <div class="content">
      {% with messages = get_flashed_messages(with_categories=true) %} {% if
      messages %} {% for category, message in messages %}
      <div class="alert alert-{{ category }}">{{ message }}</div>
      {% endfor %} {% endif %} {% endwith %} {% block content %}{% endblock %}
    </div>

    <script src="{{ url_for('static', filename='js/script.js') }}"></script>
    {% block extra_js %}{% endblock %}
  </body>
</html>
```

**Base Template Features:**

- Defines common HTML structure (head, body, navbar)
- `{% block content %}`: Child templates override this
- `{{ current_user }}`: Available in all templates (from context processor)
- `get_flashed_messages()`: Retrieve messages set with `flash()`
- `{% include %}`: Include another template

### templates/admin/clinic_report.html (Report Template)

```html
{% block content %}
<div class="report-container">
    <h1>Clinic Visit Records Report</h1>

    <!-- Filter Section -->
    <div class="filter-section">
        <form method="GET" id="filterForm">
            <input type="date" name="start_date" value="{{ start_date or '' }}">
            <input type="date" name="end_date" value="{{ end_date or '' }}">
            <select name="person_type">
                <option value="">All</option>
                <option value="student" {% if person_type == 'student' %}selected{% endif %}>
                    Students
                </option>
                <option value="teacher" {% if person_type == 'teacher' %}selected{% endif %}>
                    Teachers
                </option>
            </select>
            <button type="submit" class="btn-generate">Generate Report</button>
            <button type="button" class="btn-print" onclick="window.print()">
                Print Report
            </button>
            <button type="button" class="btn-export" onclick="exportToCSV()">
                Export to CSV
            </button>
        </form>
    </div>

    <!-- Summary Statistics -->
    {% if visits %}
        <div class="summary-stats">
            <div class="stat-box">
                <div class="stat-label">Total Clinic Visits</div>
                <div class="stat-value">{{ total_visits }}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Student Visits</div>
                <div class="stat-value">{{ student_visits }}</div>
            </div>
        </div>

        <!-- Data Table -->
        <table id="reportTable" class="report-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Person Name</th>
                    <th>Type</th>
                    <th>Diagnosis</th>
                </tr>
            </thead>
            <tbody>
                {% for visit in visits %}
                    <tr>
                        <td>{{ visit.visit_date or 'N/A' }}</td>
                        <td>{{ visit.person_name or 'Unknown' }}</td>
                        <td>
                            <span class="person-type {{ visit.person_type }}">
                                {{ visit.person_type|capitalize }}
                            </span>
                        </td>
                        <td>{{ visit.diagnosis or '—' }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Pagination -->
        {% if visits|length > 7 %}
            <div class="pagination-container">
                <button onclick="previousReportPage()">← Previous</button>
                <span>Page <span id="reportCurrentPage">1</span> of
                    <span id="reportTotalPages">1</span></span>
                <button onclick="nextReportPage()">Next →</button>
            </div>
        {% endif %}
    {% else %}
        <div class="no-data">
            <p>No clinic visit records found.</p>
        </div>
    {% endif %}
</div>
{% endblock %}
```

**Report Template Features:**

- `{{ variable or 'default' }}`: Fallback for missing data
- `{{ visit.person_type|capitalize }}`: Filter to capitalize first letter
- `{% if visits %}`: Conditional rendering
- `{% for visit in visits %}`: Loop through list
- `|length > 7`: Filter for list length

---

## FILE: Static JavaScript Examples

### static/js/script.js (Pagination Example)

```javascript
// From clinic_report.html pagination code

let currentReportPage = 1;
const itemsPerPage = 7; // Show 7 items per page

function paginateReport(page) {
  // Get the report table by ID
  const table = document.getElementById("reportTable");

  // Get all rows in table body
  const rows = table
    .getElementsByTagName("tbody")[0]
    .getElementsByTagName("tr");

  // Calculate which rows to show
  const startIndex = (page - 1) * itemsPerPage; // Row to start at
  const endIndex = startIndex + itemsPerPage; // Row to end at

  // Loop through all rows
  for (let i = 0; i < rows.length; i++) {
    // Show row if it's in the current page range
    if (i >= startIndex && i < endIndex) {
      rows[i].style.display = ""; // Show (empty string = default display)
    } else {
      rows[i].style.display = "none"; // Hide
    }
  }

  // Calculate total pages
  const totalPages = Math.ceil(rows.length / itemsPerPage);

  // Update pagination display
  if (document.getElementById("reportCurrentPage")) {
    document.getElementById("reportCurrentPage").textContent = page;
    document.getElementById("reportTotalPages").textContent = totalPages;

    // Disable/enable previous button
    document.getElementById("prevReportBtn").disabled = page === 1;

    // Disable/enable next button
    document.getElementById("nextReportBtn").disabled = page === totalPages;
  }

  // Save current page
  currentReportPage = page;
}

function previousReportPage() {
  if (currentReportPage > 1) {
    paginateReport(currentReportPage - 1);
  }
}

function nextReportPage() {
  const table = document.getElementById("reportTable");
  const rows = table
    .getElementsByTagName("tbody")[0]
    .getElementsByTagName("tr");
  const totalPages = Math.ceil(rows.length / itemsPerPage);

  if (currentReportPage < totalPages) {
    paginateReport(currentReportPage + 1);
  }
}

// Initialize pagination when page loads
document.addEventListener("DOMContentLoaded", function () {
  const reportTable = document.getElementById("reportTable");
  if (reportTable && document.getElementById("reportPaginationContainer")) {
    paginateReport(1); // Start at page 1
  }
});
```

**Pagination Logic:**

```
Example: 20 rows, 7 per page
Page 1: rows 0-6     (startIndex=0, endIndex=7)
Page 2: rows 7-13    (startIndex=7, endIndex=14)
Page 3: rows 14-20   (startIndex=14, endIndex=21)

totalPages = Math.ceil(20 / 7) = 3
```

### static/js/script.js (CSV Export Example)

```javascript
function exportToCSV() {
  // Get the data table element
  const table = document.querySelector(".report-table");

  // Start CSV with header row
  let csv =
    "Date,Person Name,Type,Sex,Age,Chief Complaint,Diagnosis,Treatment,Medications,Recommendations,Follow-up\n";

  // Get all rows in table body
  const rows = table.querySelectorAll("tbody tr");

  // Loop through each row
  rows.forEach((row) => {
    // Get all cells in this row
    const cells = row.querySelectorAll("td");
    const rowData = [];

    // Loop through each cell
    cells.forEach((cell, index) => {
      if (index < 11) {
        // Only include first 11 columns
        // Get cell text and trim whitespace
        let text = cell.textContent.trim();

        // Escape quotes in CSV (double them)
        // Example: John "The Great" → John ""The Great""
        text = '"' + text.replace(/"/g, '""') + '"';

        // Add to row data
        rowData.push(text);
      }
    });

    // Add row to CSV (join cells with commas)
    csv += rowData.join(",") + "\n";
  });

  // Create download link
  const link = document.createElement("a");
  link.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  link.download = `clinic_report_${new Date().toISOString().split("T")[0]}.csv`;

  // Click link to trigger download
  link.click();
}
```

**CSV Format Example:**

```
Date,Person Name,Type,Sex,Age,Chief Complaint,Diagnosis,Treatment
2026-01-10,"John Doe","student","M","15","Headache","Migraine","Rest"
2026-01-10,"Jane Smith","student","F","16","Fever","Flu","Paracetamol"
```

---

## Summary Table

| File                  | Purpose          | Key Functions                    |
| --------------------- | ---------------- | -------------------------------- |
| `run.py`              | Entry point      | Start Flask server               |
| `app.py`              | Main application | Routes, logic, database          |
| `encryption_utils.py` | Data encryption  | Encrypt/decrypt sensitive fields |
| `settings.py`         | Configuration    | Settings and paths               |
| `init_db.py`          | Database setup   | Create tables, schema            |
| `HTML templates`      | UI Layer         | Display data, forms              |
| `CSS files`           | Styling          | Visual design                    |
| `JavaScript files`    | Interactivity    | Pagination, filtering, export    |
