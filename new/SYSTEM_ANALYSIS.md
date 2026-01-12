# LYFJSHS Health Record Management System - Comprehensive Analysis

## TABLE OF CONTENTS

1. [Module Overview](#module-overview)
2. [Architecture & Routes](#architecture--routes)
3. [System Strengths & Weaknesses](#system-strengths--weaknesses)
4. [Detailed Code Explanations](#detailed-code-explanations)

---

## MODULE OVERVIEW

### Project Structure

```
new/
├── run.py                    # Entry point for Flask application
├── wsgi.py                   # WSGI configuration for production deployment
├── Procfile                  # Heroku deployment configuration
├── src/
│   ├── __init__.py          # Flask app package initialization
│   ├── app.py               # Main Flask application (3931 lines)
│   ├── encryption_utils.py  # Data encryption/decryption utilities
│   ├── init_db.py           # Database initialization script
│   └── __pycache__/         # Python bytecode cache
├── config/
│   ├── settings.py          # Configuration settings
│   ├── production_config.py # Production-specific config
│   └── .secret_key          # Secret key file (auto-generated)
├── templates/               # HTML templates
│   ├── auth/               # Authentication templates
│   ├── admin/              # Admin panel templates
│   ├── clinic/             # Clinic management templates
│   ├── records/            # Record management templates
│   ├── components/         # Reusable components
│   └── shared/             # Shared layouts (base.html, dashboard.html)
├── static/                  # Static files
│   ├── css/                # Stylesheets
│   ├── js/                 # JavaScript files
│   ├── imgs/               # Images
│   └── profile_pics/       # User profile pictures
├── scripts/                 # Utility scripts
│   ├── backup_database.py
│   ├── restore_database.py
│   ├── maintenance.py
│   └── verify_csrf_tokens.py
├── data/                    # Database files
├── documents/              # Uploaded documents
├── logs/                   # Application logs
├── backups/                # Database backups
└── env/                    # Virtual environment

```

### Core Dependencies

```
Flask              - Web framework
Flask-WTF          - CSRF protection
Flask-Mail         - Email functionality
bcrypt             - Password hashing
cryptography       - Data encryption (Fernet)
sqlite3            - Database
dotenv             - Environment variable management
```

---

## ARCHITECTURE & ROUTES

### 1. **run.py** - Application Entry Point

**Port:** 5000 (default)  
**Function:** Starts Flask development server

```python
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(debug=debug_mode, host=host, port=port)
```

**Key Features:**

- Environment-based configuration (FLASK_DEBUG, FLASK_HOST, FLASK_PORT)
- Configurable host binding (default: 0.0.0.0 - all interfaces)
- Debug mode controlled via environment variable

---

### 2. **src/app.py** - Main Application Module (3931 lines)

#### **Configuration Section**

```python
# Flask App Initialization
app = Flask(__name__, template_folder=..., static_folder=...)

# Security Configuration
csrf = CSRFProtect(app)  # CSRF token protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Email Configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True

# Database Configuration
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')
DOCUMENTS_DIR = os.path.join(PROJECT_ROOT, 'documents')
PROFILE_PICS_DIR = os.path.join(PROJECT_ROOT, 'static', 'profile_pics')

# File Upload Configuration
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xlsx', 'xls'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
```

#### **User Roles**

```python
ROLES = {
    'pending': 'Pending Approval',          # New users awaiting role assignment
    'super_admin': 'Super Administrator',   # Full system access
    'health_officer': 'Health Officer',     # Can manage clinic records
    'class_advisor': 'Class Advisor',       # Can view own class records
    'teacher_view_only': 'Teacher (View Only)'  # Read-only access
}
```

---

### 3. **Authentication Routes**

#### **POST /register** - User Registration

- **URL:** `/register`
- **Method:** GET, POST
- **Access:** Public (no login required)
- **Creates:** Users with 'pending' role awaiting admin approval
- **Validation:**
  - Checks username uniqueness
  - Validates password (min 6 chars)
  - Password confirmation match

**Function Flow:**

1. Validates user input (fullname, username, email, password)
2. Checks if username exists
3. Creates user with 'pending' role
4. Redirects to login

---

#### **POST /api/users** - Admin User Creation

- **URL:** `/api/users`
- **Method:** POST
- **Access:** Super Admin only
- **Returns:** JSON response
- **Allows:** Direct role assignment on creation

**Function Flow:**

1. Authenticates request
2. Authorizes (super_admin only)
3. Validates password (min 8 chars for API)
4. Creates user with specified role
5. Logs audit event

---

#### **POST /login** - User Authentication

- **URL:** `/login`
- **Method:** GET, POST
- **Access:** Public
- **Session Variables Set:**
  - `logged_in`: True
  - `user_id`: User ID
  - `username`: Username
  - `role`: User role

**Authentication Process:**

1. Retrieves user from database
2. Uses bcrypt to verify password hash
3. Checks if account is active
4. Sets session variables
5. Logs login event
6. Redirects pending users to `/pending-approval`

---

#### **GET /logout** - User Logout

- **URL:** `/logout`
- **Method:** GET
- **Access:** Authenticated users
- **Effect:** Clears session

---

### 4. **Password Management Routes**

#### **POST /forgot-password** - Password Reset Request

- **URL:** `/forgot-password`
- **Method:** GET, POST
- **Rate Limiting:** 5 attempts per hour per IP
- **Process:**
  1. User enters email address
  2. System generates 6-digit reset code
  3. Code expires in 15 minutes
  4. Email sent with HTML template
  5. Redirects to code verification page

**Security Features:**

- Rate limiting to prevent brute force
- Time-based token expiration
- Code sent via encrypted email
- Tokens marked as used after reset

---

#### **POST /verify-reset-code** - Code Verification

- **URL:** `/verify-reset-code`
- **Method:** GET, POST
- **Validates:** Reset code and email match
- **Checks:** Token expiration and validity

---

#### **POST /reset-password** - Password Reset

- **URL:** `/reset-password`
- **Method:** GET, POST
- **Validates:**
  - Token validity
  - Password strength (min 8 chars)
  - Password confirmation match
- **Updates:** User password hash in database
- **Logs:** Password reset audit event

---

### 5. **User Profile Routes**

#### **GET/POST /profile-settings** - User Profile Management

- **URL:** `/profile-settings`
- **Method:** GET, POST
- **Allows:**
  - Update fullname and email
  - Upload profile picture
  - Auto-replaces old profile pic

**File Handling:**

- Saves as: `profile_{user_id}.{ext}`
- Allowed formats: jpg, jpeg, png, gif
- Deletes old picture on update

---

#### **GET /api/search-users** - User Search API

- **URL:** `/api/search-users`
- **Query Parameter:** `q` (min 2 chars)
- **Returns:** JSON list of matching users
- **Fields:** id, username, fullname
- **Limit:** 10 results

---

#### **GET /api/profile-picture** - Get Profile Picture

- **URL:** `/api/profile-picture`
- **Returns:** JSON with profile_pic filename or null

---

#### **GET /pending-approval** - Pending Approval Page

- **URL:** `/pending-approval`
- **Access:** Pending users only
- **Display:** User info and waiting message

---

### 6. **Dashboard & Analytics Routes**

#### **GET /dashboard** - Main Dashboard

- **URL:** `/dashboard`
- **Access:** Authenticated users
- **Data Displayed:**
  - Total students/teachers counts
  - Health records summary
  - Blood type distribution
  - Vaccination status
  - Recent students/teachers
  - Allergies and health conditions
  - Expired inventory items
  - Clinic visit statistics
  - Analytics by strand (for students)
  - Teachers with most clinic visits

**Role-Based Filtering:**

- Class Advisors: See only their assigned class
- Admins: See all records

---

### 7. **Student Management Routes**

#### **GET/POST /add_student** - Add Student Record

- **URL:** `/add_student`
- **Access:** Health Officer, Super Admin
- **Fields:** LRN, name, class, strand, DOB, blood type, allergies, conditions, etc.
- **Encryption:** Sensitive fields encrypted before storage

**Encryption Fields:**

- allergies
- conditions
- pastIllnesses
- parentContact
- emergencyContact
- address
- strand

---

#### **GET /students** - Students List

- **URL:** `/students`
- **Access:** Authenticated users
- **Display:** Paginated list of all students

---

#### **GET /student/<int:id>** - Student Detail View

- **URL:** `/student/<id>`
- **Access:** Authenticated users
- **Displays:** Full student health record with decryption

---

#### **GET/POST /edit_student/<int:id>** - Edit Student

- **URL:** `/edit_student/<id>`
- **Access:** Health Officer, Super Admin
- **Features:** Update all student fields, re-encrypt sensitive data

---

#### **POST /delete_student/<int:id>** - Delete Student

- **URL:** `/delete_student/<id>`
- **Access:** Super Admin only
- **Logs:** Audit event

---

### 8. **Teacher Management Routes**

#### **GET/POST /add_teacher** - Add Teacher Record

- **URL:** `/add_teacher`
- **Access:** Health Officer, Super Admin
- **Similar to:** Student management but for teachers
- **Encrypted Fields:** allergies, conditions, pastIllnesses, contact, address

---

#### **GET /teachers** - Teachers List

- **URL:** `/teachers`

---

#### **GET/POST /edit_teacher/<int:id>** - Edit Teacher

- **URL:** `/edit_teacher/<id>`

---

#### **POST /delete_teacher/<int:id>** - Delete Teacher

- **URL:** `/delete_teacher/<id>`

---

### 9. **Inventory Management Routes**

#### **GET /inventory** - Inventory List

- **URL:** `/inventory`
- **Access:** Health Officer, Super Admin
- **Displays:** Medicine/supply inventory with expiration status

---

#### **GET/POST /add_medicine** - Add Medicine

- **URL:** `/add_medicine`
- **Fields:** Name, quantity, expiration date, category, etc.

---

#### **POST /delete_medicine/<int:id>** - Delete Medicine

- **URL:** `/delete_medicine/<id>`

---

### 10. **Clinic Visit Routes**

#### **GET/POST /clinic-visit** - Record Clinic Visit

- **URL:** `/clinic-visit`
- **Access:** Health Officer
- **Fields:**
  - Person (student or teacher)
  - Date
  - Chief complaint
  - Diagnosis (encrypted)
  - Treatment/Assessment (encrypted)
  - Medications (encrypted)
  - Recommendations (encrypted)
  - Follow-up required flag

---

#### **GET /clinic-visits** - Clinic Visits List

- **URL:** `/clinic-visits`
- **Features:** Filtered by date range, person type, pagination

---

#### **GET /clinic-visit/<int:visit_id>** - Visit Detail

- **URL:** `/clinic-visit/<visit_id>`
- **Display:** Full clinic visit record with decryption

---

#### **POST /clinic-visit/<int:visit_id>/delete** - Delete Visit

- **URL:** `/clinic-visit/<visit_id>/delete`

---

### 11. **Reporting Routes**

#### **GET /clinic-reports** - Clinic Report

- **URL:** `/clinic-reports`
- **Features:**
  - Date range filtering
  - Person type filtering (student/teacher)
  - Statistics display (total visits, student visits, teacher visits, follow-ups)
  - Print-optimized format
  - CSV export

---

### 12. **Admin Management Routes**

#### **GET /user-management** - User Management Dashboard

- **URL:** `/user-management`
- **Access:** Super Admin
- **Features:** List all users with role/status info

---

#### **POST /api/user/<int:user_id>/role** - Update User Role

- **URL:** `/api/user/<user_id>/role`
- **Method:** POST
- **Access:** Super Admin
- **Payload:** `{role: 'health_officer', advisory_class: null}`

---

#### **POST /api/user/<int:user_id>/advisory-class** - Set Advisory Class

- **URL:** `/api/user/<user_id>/advisory-class`
- **Method:** POST
- **Access:** Super Admin
- **Payload:** `{advisory_class: 'Grade 11 - A'}`
- **Use:** For class advisors to view only their class

---

#### **POST /api/user/<int:user_id>/status** - Toggle User Active Status

- **URL:** `/api/user/<user_id>/status`
- **Method:** POST
- **Access:** Super Admin
- **Effect:** Deactivate/activate user account

---

#### **POST /api/user/<int:user_id>/delete** - Delete User

- **URL:** `/api/user/<user_id>/delete`
- **Method:** POST
- **Access:** Super Admin
- **Effect:** Permanently removes user

---

#### **GET /manage-users** - Manage Users Page

- **URL:** `/manage-users`
- **Access:** Super Admin
- **Template:** Displays user management interface

---

#### **GET /advanced-management** - Advanced Management

- **URL:** `/advanced-management`
- **Access:** Super Admin
- **Features:** Database operations and admin tools

---

### 13. **Data Management Routes**

#### **GET /audit-logs** - Audit Log Viewer

- **URL:** `/audit-logs`
- **Access:** Super Admin
- **Displays:** All user actions, timestamps, changes

---

#### **GET /import-export** - Import/Export Page

- **URL:** `/import-export`
- **Access:** Super Admin

---

#### **POST /api/import/students** - Import Students CSV

- **URL:** `/api/import/students`
- **Method:** POST
- **File:** CSV file with student records
- **Validates:** Required fields
- **Encrypts:** Sensitive fields

---

#### **POST /api/import/teachers** - Import Teachers CSV

- **URL:** `/api/import/teachers`
- **Method:** POST
- **Similar to:** Student import

---

### 14. **Document Management Routes**

#### **GET /documents** - Documents List

- **URL:** `/documents`
- **Access:** Authenticated users
- **Displays:** All uploaded documents with metadata

---

#### **GET/POST /documents/upload** - Upload Document

- **URL:** `/documents/upload`
- **Access:** Health Officer, Super Admin
- **Features:**
  - File upload with validation
  - Category assignment
  - Verification workflow

---

#### **GET /documents/<int:doc_id>/view** - View Document

- **URL:** `/documents/<doc_id>/view`
- **Returns:** Document file with MIME type detection

---

#### **POST /documents/<int:doc_id>/delete** - Delete Document

- **URL:** `/documents/<doc_id>/delete`

---

#### **POST /documents/<int:doc_id>/verify** - Verify Document

- **URL:** `/documents/<doc_id>/verify`
- **Access:** Super Admin
- **Marks:** Document as verified

---

### 15. **API/Notification Routes**

#### **GET /api/notifications** - Get Notifications

- **URL:** `/api/notifications`
- **Returns:** JSON list of active notifications
- **Types:**
  - Expiring medicines (within 30 days)
  - Pending vaccinations
  - Students with allergies

---

#### **POST /api/notifications/dismiss** - Dismiss Notification

- **URL:** `/api/notifications/dismiss`
- **Method:** POST
- **Effect:** Marks notification as read

---

#### **GET /api/students** - API: Get All Students

- **URL:** `/api/students`
- **Returns:** JSON list of students (decrypted)

---

#### **GET /api/teachers** - API: Get All Teachers

- **URL:** `/api/teachers`
- **Returns:** JSON list of teachers (decrypted)

---

#### **GET /api/clinic-visit/<int:visit_id>** - API: Get Clinic Visit

- **URL:** `/api/clinic-visit/<visit_id>`
- **Returns:** JSON clinic visit record (decrypted)

---

## SYSTEM STRENGTHS & WEAKNESSES

### ✅ STRENGTHS

#### 1. **Security Implementation**

- **Bcrypt Password Hashing**: Uses bcrypt with salt for secure password storage
- **CSRF Protection**: Flask-WTF CSRF token protection on all state-changing requests
- **Data Encryption**: Fernet symmetric encryption for sensitive fields (health data)
- **Rate Limiting**: Password reset requests limited to 5/hour per IP
- **Session Management**: Proper session validation and timeout handling
- **Secure File Uploads**: File extension and type validation
- **Audit Logging**: Comprehensive logging of user actions

#### 2. **Role-Based Access Control (RBAC)**

- Clear role hierarchy (5 roles with specific permissions)
- Class advisor filtering for restricted data access
- Role-specific dashboards and views
- Decorator-based access control (`@require_role`, `@require_login`)

#### 3. **Database Design**

- SQLite with Row Factory for safe column access
- Proper foreign key relationships
- Timestamp tracking for auditing
- Soft deletion capability
- Encryption key stored securely (file with restricted permissions 0o600)

#### 4. **User Experience Features**

- Profile picture upload capability
- Password reset workflow with email verification
- Pending user approval workflow
- Dashboard with analytics and statistics
- Pagination for large datasets
- Search functionality for users

#### 5. **Data Management**

- CSV import/export functionality
- Database backup and restore scripts
- Document management system
- Audit trail of all changes
- Analytics dashboard with charts

#### 6. **Email Integration**

- Flask-Mail with HTML templates
- Formatted password reset emails
- Configurable SMTP settings

---

### ⚠️ WEAKNESSES

#### 1. **Critical Security Issues**

**A. SQL Injection Risk in get_advisor_class_filter()**

```python
return f"AND class = '{safe_row_get(user, 'advisory_class')}'"
# VULNERABLE: String interpolation instead of parameterized query
```

**Risk:** If advisory_class contains single quotes, SQL injection possible
**Fix:** Use parameterized queries

**B. Plain Text Sensitive Data Display**

- Some sensitive fields stored encrypted but displayed without consistent re-encryption
- Advisory class potentially exposed in URL parameters
- Password reset tokens in URL (man-in-the-middle risk)

**C. Email Credentials in Environment**

- Email password stored in plain environment variables
- No encryption for email credentials

**D. Missing Password Complexity Requirements**

- Registration: Only 6-character minimum
- API: 8-character minimum (inconsistent!)
- No complexity requirements (uppercase, numbers, symbols)
- Should enforce: `^(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{8,}$`

**E. Weak Token Generation**

```python
reset_code = ''.join(random.choices(string.digits, k=6))
# WEAK: Only 6 digits = 1,000,000 combinations
# Brute-forceable with rate limiting disabled
```

**F. No HTTPS Enforcement**

- Application doesn't enforce HTTPS
- Cookies not marked secure
- Session IDs transmitted in plain HTTP (production risk)

---

#### 2. **Code Quality Issues**

**A. Code Duplication**

- `decrypt_student_record()`, `decrypt_teacher_record()`, `decrypt_clinic_visit_record()` use similar logic
- Should refactor into generic function
- Student/teacher add/edit code duplicated

**B. Error Handling Inconsistency**

```python
# Sometimes catches exceptions silently
except Exception as e:
    logger.error(f"Error: {e}")
    pass

# Sometimes no error handling
cursor.execute(...)  # No try-catch
```

**C. Large File**

- 3931 lines in single `app.py` file
- Should split into blueprints:
  - `auth.py` (authentication routes)
  - `admin.py` (admin routes)
  - `clinic.py` (clinic visit routes)
  - `records.py` (student/teacher routes)
  - `documents.py` (document management)

**D. Poor Variable Naming**

```python
# Unclear abbreviations
allerg = cursor.fetchall()  # What is 'allerg'?
ill = cursor.fetchall()     # What is 'ill'?
cond = cursor.fetchall()    # What is 'cond'?
```

**E. Magic Numbers**

```python
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', ...}  # Should be config
MAX_FILE_SIZE = 10 * 1024 * 1024  # Magic number
itemsPerPage = 7  # Hardcoded in JavaScript
```

**D. Inconsistent Encryption**

- Some routes decrypt data, others don't
- Frontend receives both encrypted and decrypted data
- No clear encryption boundary

---

#### 3. **Missing Features**

**A. No Input Validation Framework**

- Validates manually in each route
- No reusable validation rules
- XSS vulnerabilities possible (though Jinja2 auto-escapes)

**B. No Rate Limiting for API Endpoints**

- Only password reset has rate limiting
- `/api/students`, `/api/teachers` have no rate limit
- Possible data extraction attacks

**C. No API Documentation**

- No OpenAPI/Swagger specs
- No endpoint documentation
- Developers guess endpoint functionality

**D. Limited Search Functionality**

- Basic text search only
- No advanced filtering
- No full-text search

**E. No Data Validation on Import**

```python
# CSV import doesn't validate:
# - Duplicate LRNs
# - Invalid date formats
# - Missing required fields
```

---

#### 4. **Performance Issues**

**A. N+1 Query Problem**

```python
# Gets all students, then loops to decrypt each one
students = cursor.fetchall()
students = [decrypt_student_record(s) for s in students]
# Should batch operations
```

**B. No Query Optimization**

- No indexes defined for frequent queries
- Full table scans for every search
- No pagination in some queries

**C. Inefficient Decryption**

- Decrypts entire records even if only some fields needed
- No caching of decrypted values
- Performance degrades with large datasets

---

#### 5. **Deployment & Infrastructure**

**A. No Environment Variable Validation**

```python
# Missing .env file will silently fail
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
# No check if actual values are provided
```

**B. Hardcoded School Name**

```python
School: {{  'Luis Y. Ferrer Jr. Senior High School ' }}
# Should be configurable
```

**C. No Logging to File**

- Logging only to console
- No persistent log storage
- No log rotation

**D. Database Not Version Controlled**

- SQLite file in `data/` directory
- No database migration system
- Schema changes manual

---

#### 6. **Frontend Issues**

**A. JavaScript Not Minified/Bundled**

- Multiple separate JS files loaded
- No compression or bundling
- CSS not minimized

**B. No Form Validation on Frontend**

- Backend validates, frontend doesn't
- Poor user experience (server round-trip for validation)

**C. Accessibility Issues**

- No ARIA labels
- No alt text on images
- Poor keyboard navigation (assumed)

**D. Responsive Design Unclear**

- CSS media queries may be insufficient
- Print CSS present but complex

---

#### 7. **Documentation & Maintenance**

**A. No Code Comments**

- Routes lack docstrings beyond brief description
- Complex logic unexplained
- No README

**B. No Type Hints**

```python
def get_db_connection():  # No type hints
    # Hard to know return type and None handling
```

**C. No Unit Tests**

- No test files found
- No test coverage
- Changes break silently

**D. No API Documentation**

- No endpoint specification
- No request/response examples
- No error code documentation

---

### SUMMARY SCORE

**Overall Security:** 6/10 - Good basics but critical issues
**Code Quality:** 5/10 - Functional but needs refactoring
**Scalability:** 4/10 - Not designed for growth
**Maintainability:** 4/10 - Monolithic, undocumented
**Performance:** 5/10 - Functional for small datasets

---

## DETAILED CODE EXPLANATIONS

### src/encryption_utils.py

```python
class DataEncryption:
    """Handle encryption/decryption of sensitive data using Fernet (symmetric)"""

    def __init__(self, master_key=None):
        """
        Initialize encryption handler with a master key
        - If master_key provided: Use it
        - Else: Load from environment variable DATABASE_ENCRYPTION_KEY
        - Else: Load from file config/.encryption_key
        - Else: Generate new key and save to file
        """
        if master_key:
            self.key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            self.key = self._get_or_create_key()

        try:
            self.cipher = Fernet(self.key)  # Create cipher object
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")

    def encrypt(self, plaintext):
        """
        Encrypts plaintext string to base64-encoded ciphertext
        Returns: String (storable in database)
        """
        if not plaintext:
            return None

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')  # Convert string to bytes

        try:
            ciphertext = self.cipher.encrypt(plaintext)  # Encrypt
            return ciphertext.decode('utf-8')  # Convert bytes back to string
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, ciphertext):
        """
        Decrypts base64-encoded ciphertext back to plaintext
        Returns: Decrypted string or raises exception
        """
        if not ciphertext:
            return None

        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')

        try:
            plaintext = self.cipher.decrypt(ciphertext)  # Decrypt
            return plaintext.decode('utf-8')  # Convert to string
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

SENSITIVE_FIELDS = {
    'students': ['allergies', 'conditions', 'pastIllnesses',
                 'parentContact', 'emergencyContact', 'address', 'strand'],
    'teachers': ['allergies', 'conditions', 'pastIllnesses', 'contact', 'address'],
    'clinic_visits': ['diagnosis', 'assessment', 'physical_examination',
                      'medications_given', 'recommendations'],
}

def should_encrypt_field(table, field):
    """Checks if a field in a table should be encrypted"""
    return table in SENSITIVE_FIELDS and field in SENSITIVE_FIELDS[table]
```

**How Encryption Works:**

1. Uses Fernet (symmetric encryption from cryptography library)
2. Same key encrypts and decrypts
3. Key stored in file with restricted permissions (0o600)
4. Each plaintext produces different ciphertext (includes timestamp)
5. Decryption fails if key or data is tampered with

---

### src/app.py - Key Functions

#### **hash_password(password)**

```python
def hash_password(password):
    """Hash password using bcrypt with random salt"""
    # bcrypt.gensalt() generates new salt each time
    # bcrypt.hashpw() hashes with that salt
    # Different hash each time (includes salt), but verifies correctly
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
```

#### **authenticate_user(username, password)**

```python
def authenticate_user(username, password):
    """Verify username/password combination"""
    if not username or not password:
        return False, None

    db = get_db_connection()
    if not db:
        return False, None

    try:
        cursor = db.cursor()
        # Get user record by username
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        # Verify password hash using bcrypt
        # bcrypt.checkpw(plaintext, hash) returns True/False
        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            return True, user  # Authentication successful
        return False, None
    except sqlite3.Error:
        if db:
            db.close()
        return False, None
```

#### **decrypt_student_record(student)**

```python
def decrypt_student_record(student):
    """Decrypt sensitive fields in student record"""
    if not student or not encryption_handler:
        return student

    try:
        decrypted = dict(student)  # Convert Row to dict
        sensitive_fields = ['allergies', 'conditions', 'pastIllnesses',
                           'parentContact', 'emergencyContact', 'address', 'strand']

        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                try:
                    # Decrypt each sensitive field
                    decrypted[field] = encryption_handler.decrypt(decrypted[field])
                except:
                    # If decryption fails, leave as is (might be plaintext)
                    pass
        return decrypted
    except Exception as e:
        print(f"Error decrypting student record: {e}")
        return student
```

**Note:** This function tries to decrypt but silently fails - could hide data corruption

#### **log_audit(action, table_name, record_id, old_values, new_values)**

```python
def log_audit(action, table_name, record_id=None, old_values=None, new_values=None):
    """Log user action to audit_log table for compliance"""
    if not session.get("logged_in"):
        return  # Don't log if not logged in

    db = get_db_connection()
    if not db:
        return

    try:
        cursor = db.cursor()
        user_id = session.get("user_id")
        username = session.get("username", "unknown")
        ip_address = request.remote_addr if request else None  # Get client IP

        # Insert audit record
        cursor.execute("""
            INSERT INTO audit_log
            (user_id, username, action, table_name, record_id,
             old_values, new_values, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, action, table_name, record_id,
              json.dumps(old_values) if old_values else None,
              json.dumps(new_values) if new_values else None,
              ip_address))

        db.commit()
    except sqlite3.Error as e:
        logger.error(f"Audit logging error: {e}")
    finally:
        db.close()
```

**Audit Actions Logged:**

- LOGIN / LOGOUT
- CREATE / UPDATE / DELETE records
- PASSWORD_RESET
- ROLE_CHANGE
- etc.

#### **require_role(\*allowed_roles) - Decorator**

```python
def require_role(*allowed_roles):
    """Decorator that checks if user has required role"""
    def decorator(f):
        @wraps(f)  # Preserve original function metadata
        def decorated_function(*args, **kwargs):
            # Check if logged in
            if not session.get("logged_in"):
                flash("Please login first.", "warning")
                return redirect(url_for("login"))

            # Get user's current role
            db = get_db_connection()
            if not db:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))

            try:
                cursor = db.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?",
                             (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()

                # Check if user's role is in allowed_roles
                if not user or safe_row_get(user, 'role') not in allowed_roles:
                    flash("You don't have permission to access this page.", "danger")
                    return redirect(url_for("dashboard"))

                # User authorized, call original function
                return f(*args, **kwargs)
            except sqlite3.Error:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))

        return decorated_function
    return decorator

# Usage:
@app.route("/admin-only")
@require_role('super_admin')  # Only super_admin can access
def admin_only():
    pass
```

---

### Authentication Route Examples

#### **/register Route**

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    """Public registration - creates 'pending' users"""
    if request.method == "POST":
        # Get form data and strip whitespace
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        advisory_class = request.form.get("advisory_class", "").strip()

        # Validate inputs
        is_valid, message = validate_user_input(fullname, username, email,
                                               password, confirm_password)
        if not is_valid:
            flash(message, "danger")  # Show error message
            return render_template("auth/register.html")

        # Check if username exists
        username_check = username_exists(username)
        if username_check is None:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/register.html")
        elif username_check:
            flash("Username already exists. Please choose another.", "danger")
            return render_template("auth/register.html")

        # Create user with 'pending' role
        success, user_id, message = create_user_in_db(
            username, password, fullname, email,
            role='pending',  # User role until admin assigns one
            advisory_class=advisory_class
        )
        if not success:
            flash(f"Registration failed: {message}", "danger")
            return render_template("auth/register.html")

        flash("Registration successful! Awaiting admin to assign your role.", "success")
        return redirect(url_for("login"))  # Redirect to login page

    # GET request - show registration form
    return render_template("auth/register.html")
```

**Flow:**

1. Display registration form (GET)
2. Validate all inputs
3. Check username uniqueness
4. Hash password with bcrypt
5. Insert user with pending role
6. Redirect to login

---

#### **/login Route**

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with credentials validation"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("auth/index.html")

        # Authenticate user (checks bcrypt password hash)
        is_authentic, user = authenticate_user(username, password)
        if not is_authentic:
            flash("Invalid username or password.", "danger")
            return render_template("auth/index.html")

        # Check if account is active (not disabled by admin)
        is_active = safe_row_get(user, 'is_active', 1)
        if not is_active:
            flash("Your account has been disabled.", "danger")
            return render_template("auth/index.html")

        # Set session variables (cookie-based persistence)
        session["logged_in"] = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = safe_row_get(user, "role", "health_officer")

        # Log successful login
        log_audit("LOGIN", "users", user["id"])
        flash(f"Welcome back, {user['fullname']}!", "success")

        # Redirect pending users to approval page
        if session["role"] == "pending":
            return redirect(url_for("pending_approval"))

        return redirect(url_for("dashboard"))

    # GET request - show login form
    return render_template("auth/index.html")
```

**Session Variables:**

- `logged_in`: Boolean flag
- `user_id`: Primary key for user
- `username`: Display name
- `role`: Current user role (used for access control)

---

#### **/forgot-password Route (Simplified)**

```python
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Initiate password reset process"""
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

            # Find user by email
            cursor.execute("SELECT id, fullname FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if not user:
                # For security, don't reveal if email exists
                flash("If that email exists, you will receive a reset code.", "success")
                db.close()
                return redirect(url_for("login"))

            user_id = user['id']
            user_fullname = user['fullname']

            # Generate 6-digit reset code
            reset_code = ''.join(random.choices(string.digits, k=6))

            # Delete any existing unused reset tokens for this user
            cursor.execute("""
                DELETE FROM password_reset_tokens
                WHERE user_id = ? AND is_used = 0
            """, (user_id,))

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
                flash(f"Reset code sent to {email}.", "success")
            else:
                flash(f"Account found, but email could not be sent.", "warning")

            # Redirect to code verification page
            return redirect(url_for("verify_reset_code", email=email))

        except sqlite3.Error as e:
            flash("An error occurred. Please try again.", "danger")
            if db:
                db.close()
            return render_template("auth/forgot_password.html")

    return render_template("auth/forgot_password.html")
```

**Process:**

1. User enters email
2. Generate 6-digit random code
3. Store code in `password_reset_tokens` table with expiration
4. Send email with code
5. Redirect to verification page

---

### Dashboard Route (Complex Analytics)

```python
@app.route("/dashboard")
def dashboard():
    """Main dashboard with analytics"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))

    try:
        cursor = db.cursor()

        # Get current user
        cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
        current_user = cursor.fetchone()

        # Get user role
        user_role = safe_row_get(current_user, 'role') if current_user else None
        if not user_role:
            db.close()
            flash("Your account is pending admin approval.", "warning")
            return redirect(url_for("pending_approval"))

        # Role-based data filtering
        if user_role == 'class_advisor' and safe_row_get(current_user, 'advisory_class'):
            # Class advisors see only their class
            advisory_class = safe_row_get(current_user, 'advisory_class')

            cursor.execute("SELECT * FROM students WHERE class = ?", (advisory_class,))
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]  # Decrypt
            total_students = len(students)
            total_records = len([s for s in students if s["allergies"] or s["conditions"]])
        else:
            # Admins see all students
            cursor.execute("SELECT * FROM students")
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]
            total_students = len(students)
            total_records = len([s for s in students if s["allergies"] or s["conditions"]])

        # Blood type distribution
        cursor.execute("""
            SELECT blood, COUNT(*) as count
            FROM students
            WHERE blood IS NOT NULL AND blood != ''
            GROUP BY blood
        """)
        blood_dist = cursor.fetchall()
        blood_distribution = {row['blood']: row['count'] for row in blood_dist} if blood_dist else {}

        # Analytics data
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE allergies IS NOT NULL")
        students_with_allergies = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM inventory
            WHERE expiry_date IS NOT NULL AND expiry_date < date('now')
        """)
        expired_items = cursor.fetchone()['count']

        db.close()

        # Render dashboard with all statistics
        return render_template(
            "shared/dashboard.html",
            total_students=total_students,
            total_records=total_records,
            blood_distribution=blood_distribution,
            students_with_allergies=students_with_allergies,
            expired_items=expired_items,
            # ... more variables
        )

    except Exception as e:
        db.close()
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for("login"))
```

**Key Features:**

- Role-based filtering (admins vs class advisors)
- Decryption of sensitive fields
- Multiple aggregation queries for statistics
- Error handling with fallback

---

## HTML/CSS/JavaScript EXPLANATIONS

### clinic_report.html (Selected lines 607)

**Line 607: "Print For"**
This appears in the filter section button area.

```html
<!-- Line ~607 context - Print button -->
<button type="button" class="btn-print" onclick="window.print()">
  Print Report
</button>
```

The `window.print()` JavaScript function triggers the browser's print dialog. The CSS has `@media print {}` rules that hide navigation and show only the printable content.

**Key CSS Features in clinic_report.html:**

```css
/* Pagination styling */
.pagination-btn {
  background-color: #8f2f41; /* School color (maroon)*/
  color: white;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
}

/* Print optimization */
@media print {
  .sidebar,
  .header,
  .filter-section {
    display: none !important; /* Hide navigation elements */
  }

  .print-preview {
    border: none !important;
    page-break-inside: avoid; /* Keep content on one page */
  }

  @page {
    margin: 0.15in;
    size: A4 landscape; /* Print as A4 landscape */
  }
}
```

**JavaScript Functions (clinic_report.html):**

```javascript
function exportToCSV() {
  const table = document.querySelector(".report-table");
  let csv = "Date,Person Name,Type,...\n";

  // Iterate through table rows
  const rows = table.querySelectorAll("tbody tr");
  rows.forEach((row) => {
    const cells = row.querySelectorAll("td");
    const rowData = [];

    cells.forEach((cell, index) => {
      if (index < 11) {
        let text = cell.textContent.trim();
        // Escape quotes in CSV
        text = '"' + text.replace(/"/g, '""') + '"';
        rowData.push(text);
      }
    });

    csv += rowData.join(",") + "\n";
  });

  // Create download link and trigger
  const link = document.createElement("a");
  link.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  link.download = `clinic_report_${new Date().toISOString().split("T")[0]}.csv`;
  link.click(); // Trigger download
}

// Pagination
let currentReportPage = 1;
const itemsPerPage = 7;

function paginateReport(page) {
  const table = document.getElementById("reportTable");
  const rows = table
    .getElementsByTagName("tbody")[0]
    .getElementsByTagName("tr");

  const startIndex = (page - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;

  // Show/hide rows based on page
  for (let i = 0; i < rows.length; i++) {
    rows[i].style.display = i >= startIndex && i < endIndex ? "" : "none";
  }

  // Update pagination info
  document.getElementById("reportCurrentPage").textContent = page;
  document.getElementById("reportTotalPages").textContent = Math.ceil(
    rows.length / itemsPerPage
  );
}
```

---

## SUMMARY

This system is a **moderately secure health records management system** with good foundational practices but significant technical debt and security gaps. The architecture is functional for small deployments but not scalable.

**Recommended Immediate Actions:**

1. Add HTTPS enforcement and secure cookies
2. Fix SQL injection in `get_advisor_class_filter()`
3. Increase password complexity requirements
4. Add rate limiting to all API endpoints
5. Refactor monolithic `app.py` into blueprints
6. Add comprehensive unit tests
7. Add API documentation
8. Implement database migration system
