"""
PlacePro – Campus Placement Portal
Uses: Flask + Jinja2 + SQLite (sqlite3 stdlib) + Flask sessions
No external DB/auth extensions needed.
"""

import sqlite3
import os
import hashlib
import secrets
from datetime import date
from functools import wraps
from werkzeug.utils import secure_filename

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, session, g, jsonify, abort)

app = Flask(__name__)
app.secret_key = 'placepro-iitm-2024-xK9#mP2qR7'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
DATABASE = 'placement_portal.db'
ALLOWED_EXT = {'pdf', 'doc', 'docx'}


# Custom Jinja2 filter for date strings from SQLite
@app.template_filter('fmtdate')
def fmtdate(s):
    if not s: return '—'
    try:
        # SQLite datetime strings: "2026-04-01 14:28:01" or "2026-04-01"
        s = str(s)[:10]
        from datetime import datetime
        return datetime.strptime(s, '%Y-%m-%d').strftime('%d %b %Y')
    except Exception:
        return str(s)[:10]


# ── DB HELPERS ────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


# ── PASSWORD HASHING ──────────────────────────────────────────
def hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}${h}"


def check_pw(stored, given):
    try:
        salt, h = stored.split('$', 1)
        return h == hashlib.sha256((salt + given).encode()).hexdigest()
    except Exception:
        return False


# ── AUTH HELPERS ──────────────────────────────────────────────
def current_user():
    uid = session.get('user_id')
    if uid is None:
        return None
    return query("SELECT * FROM users WHERE id=?", [uid], one=True)


def allowed_file(fn):
    return '.' in fn and fn.rsplit('.', 1)[1].lower() in ALLOWED_EXT


def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if not session.get('user_id'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec


def admin_required(f):
    @wraps(f)
    def dec(*a, **kw):
        u = current_user()
        if not u or u['role'] != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec


def company_required(f):
    @wraps(f)
    def dec(*a, **kw):
        u = current_user()
        if not u or u['role'] != 'company':
            flash('Company access required.', 'danger')
            return redirect(url_for('login'))
        c = query("SELECT * FROM companies WHERE user_id=?", [u['id']], one=True)
        if not c or c['approval_status'] != 'approved' or c['is_blacklisted']:
            flash('Your company is not approved or has been blacklisted.', 'danger')
            session.clear()
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec


def student_required(f):
    @wraps(f)
    def dec(*a, **kw):
        u = current_user()
        if not u or u['role'] != 'student':
            flash('Student access required.', 'danger')
            return redirect(url_for('login'))
        s = query("SELECT * FROM students WHERE user_id=?", [u['id']], one=True)
        if s and s['is_blacklisted']:
            flash('Your account has been blacklisted.', 'danger')
            session.clear()
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec


def redirect_by_role(u):
    if u['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif u['role'] == 'company':
        return redirect(url_for('company_dashboard'))
    return redirect(url_for('student_dashboard'))


@app.context_processor
def inject_user():
    u = current_user()
    return dict(current_user=u)


# ── DATABASE SETUP ────────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        department TEXT,
        cgpa REAL DEFAULT 0.0,
        graduation_year INTEGER,
        skills TEXT,
        address TEXT,
        resume_filename TEXT,
        is_blacklisted INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        company_name TEXT NOT NULL,
        hr_contact TEXT,
        hr_email TEXT,
        website TEXT,
        description TEXT,
        industry TEXT,
        approval_status TEXT DEFAULT 'pending',
        is_blacklisted INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS placement_drives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
        job_title TEXT NOT NULL,
        job_description TEXT,
        eligibility_criteria TEXT,
        package TEXT,
        location TEXT,
        application_deadline TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        drive_id INTEGER NOT NULL REFERENCES placement_drives(id) ON DELETE CASCADE,
        application_date TEXT DEFAULT (datetime('now')),
        status TEXT DEFAULT 'applied',
        cover_letter TEXT,
        UNIQUE(student_id, drive_id)
    );
    """)
    existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        pw = hash_pw('admin123')
        db.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                   ('admin', 'admin@placement.edu', pw, 'admin'))
        db.commit()
        print('[INFO] Admin created  ->  username: admin  |  password: admin123')
    else:
        print('[INFO] Admin already exists.')
    db.commit()
    db.close()


# ═══════════════════════════════════════════════════════════════
#  PUBLIC / AUTH ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    students   = query("SELECT COUNT(*) c FROM students", one=True)['c']
    companies  = query("SELECT COUNT(*) c FROM companies WHERE approval_status='approved'", one=True)['c']
    drives     = query("SELECT COUNT(*) c FROM placement_drives WHERE status='approved'", one=True)['c']
    placements = query("SELECT COUNT(*) c FROM applications WHERE status='selected'", one=True)['c']
    stats = dict(students=students, companies=companies, drives=drives, placements=placements)
    return render_template('index.html', stats=stats)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        u = current_user()
        if u:
            return redirect_by_role(u)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        u = query("SELECT * FROM users WHERE username=?", [username], one=True)
        if not u or not check_pw(u['password_hash'], password):
            flash('Invalid username or password.', 'danger')
            return render_template('auth/login.html')
        if not u['is_active']:
            flash('Your account has been deactivated.', 'danger')
            return render_template('auth/login.html')
        if u['role'] == 'company':
            c = query("SELECT * FROM companies WHERE user_id=?", [u['id']], one=True)
            if c['approval_status'] == 'pending':
                flash('Your registration is pending admin approval.', 'warning')
                return render_template('auth/login.html')
            if c['approval_status'] == 'rejected':
                flash('Your registration was rejected.', 'danger')
                return render_template('auth/login.html')
            if c['is_blacklisted']:
                flash('Your company has been blacklisted.', 'danger')
                return render_template('auth/login.html')
        if u['role'] == 'student':
            s = query("SELECT * FROM students WHERE user_id=?", [u['id']], one=True)
            if s and s['is_blacklisted']:
                flash('Your account has been blacklisted.', 'danger')
                return render_template('auth/login.html')
        session['user_id'] = u['id']
        session['role']    = u['role']
        flash(f"Welcome back, {u['username']}!", 'success')
        return redirect_by_role(u)
    return render_template('auth/login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register/student', methods=['GET', 'POST'])
def register_student():
    if session.get('user_id'):
        return redirect(url_for('student_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        full_name= request.form.get('full_name', '').strip()
        phone    = request.form.get('phone', '').strip()
        dept     = request.form.get('department', '').strip()
        grad_y   = request.form.get('graduation_year', '').strip()
        cgpa_s   = request.form.get('cgpa', '0').strip()
        skills   = request.form.get('skills', '').strip()
        errors = []
        if not username: errors.append('Username is required.')
        elif query("SELECT id FROM users WHERE username=?", [username], one=True):
            errors.append('Username already taken.')
        if not email: errors.append('Email is required.')
        elif query("SELECT id FROM users WHERE email=?", [email], one=True):
            errors.append('Email already registered.')
        if len(password) < 6: errors.append('Password must be at least 6 chars.')
        if password != confirm: errors.append('Passwords do not match.')
        if not full_name: errors.append('Full name is required.')
        if errors:
            for e in errors: flash(e, 'danger')
            return render_template('auth/register_student.html')
        try:    cgpa_v = float(cgpa_s)
        except: cgpa_v = 0.0
        try:    grad_v = int(grad_y) if grad_y else None
        except: grad_v = None
        uid = execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                      (username, email, hash_pw(password), 'student'))
        execute("INSERT INTO students (user_id,full_name,email,phone,department,cgpa,graduation_year,skills) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (uid, full_name, email, phone, dept, cgpa_v, grad_v, skills))
        flash('Registered! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register_student.html')


@app.route('/register/company', methods=['GET', 'POST'])
def register_company():
    if session.get('user_id'):
        return redirect(url_for('company_dashboard'))
    if request.method == 'POST':
        username     = request.form.get('username', '').strip()
        email        = request.form.get('email', '').strip()
        password     = request.form.get('password', '')
        confirm      = request.form.get('confirm_password', '')
        company_name = request.form.get('company_name', '').strip()
        hr_contact   = request.form.get('hr_contact', '').strip()
        hr_email     = request.form.get('hr_email', '').strip()
        website      = request.form.get('website', '').strip()
        description  = request.form.get('description', '').strip()
        industry     = request.form.get('industry', '').strip()
        errors = []
        if not username: errors.append('Username is required.')
        elif query("SELECT id FROM users WHERE username=?", [username], one=True):
            errors.append('Username already taken.')
        if not email: errors.append('Email is required.')
        elif query("SELECT id FROM users WHERE email=?", [email], one=True):
            errors.append('Email already registered.')
        if len(password) < 6: errors.append('Password must be at least 6 chars.')
        if password != confirm: errors.append('Passwords do not match.')
        if not company_name: errors.append('Company name is required.')
        if errors:
            for e in errors: flash(e, 'danger')
            return render_template('auth/register_company.html')
        uid = execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                      (username, email, hash_pw(password), 'company'))
        execute("INSERT INTO companies (user_id,company_name,hr_contact,hr_email,website,description,industry) "
                "VALUES (?,?,?,?,?,?,?)",
                (uid, company_name, hr_contact, hr_email, website, description, industry))
        flash('Company registered! Awaiting admin approval before you can log in.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/register_company.html')


# ═══════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    data = {
        'total_students':       query("SELECT COUNT(*) c FROM students", one=True)['c'],
        'total_companies':      query("SELECT COUNT(*) c FROM companies", one=True)['c'],
        'total_drives':         query("SELECT COUNT(*) c FROM placement_drives", one=True)['c'],
        'total_applications':   query("SELECT COUNT(*) c FROM applications", one=True)['c'],
        'pending_companies':    query("SELECT COUNT(*) c FROM companies WHERE approval_status='pending'", one=True)['c'],
        'approved_companies':   query("SELECT COUNT(*) c FROM companies WHERE approval_status='approved'", one=True)['c'],
        'pending_drives':       query("SELECT COUNT(*) c FROM placement_drives WHERE status='pending'", one=True)['c'],
        'approved_drives':      query("SELECT COUNT(*) c FROM placement_drives WHERE status='approved'", one=True)['c'],
        'selected':             query("SELECT COUNT(*) c FROM applications WHERE status='selected'", one=True)['c'],
        'blacklisted_students': query("SELECT COUNT(*) c FROM students WHERE is_blacklisted=1", one=True)['c'],
    }
    recent_apps = query("""
        SELECT a.id, a.status, a.application_date,
               s.full_name AS student_name, d.job_title, c.company_name
        FROM applications a
        JOIN students s ON s.id=a.student_id
        JOIN placement_drives d ON d.id=a.drive_id
        JOIN companies c ON c.id=d.company_id
        ORDER BY a.application_date DESC LIMIT 8""")
    pending_companies = query(
        "SELECT * FROM companies WHERE approval_status='pending' ORDER BY created_at DESC LIMIT 5")
    pending_drives = query("""
        SELECT d.*, c.company_name FROM placement_drives d
        JOIN companies c ON c.id=d.company_id
        WHERE d.status='pending' ORDER BY d.created_at DESC LIMIT 5""")
    return render_template('admin/dashboard.html', data=data,
                           recent_apps=recent_apps,
                           pending_companies=pending_companies,
                           pending_drives=pending_drives)


@app.route('/admin/companies')
@login_required
@admin_required
def admin_companies():
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'all')
    sql = """SELECT c.*, u.username,
             (SELECT COUNT(*) FROM placement_drives d WHERE d.company_id=c.id) drive_count
             FROM companies c JOIN users u ON u.id=c.user_id WHERE 1=1"""
    args = []
    if search:
        sql += " AND (c.company_name LIKE ? OR c.industry LIKE ? OR c.hr_contact LIKE ?)"
        args += [f'%{search}%', f'%{search}%', f'%{search}%']
    if status_filter != 'all':
        sql += " AND c.approval_status=?"
        args.append(status_filter)
    sql += " ORDER BY c.created_at DESC"
    companies = query(sql, args)
    return render_template('admin/companies.html', companies=companies,
                           search=search, status_filter=status_filter)


@app.route('/admin/companies/<int:cid>')
@login_required
@admin_required
def admin_company_detail(cid):
    company = query("SELECT c.*,u.username FROM companies c JOIN users u ON u.id=c.user_id WHERE c.id=?", [cid], one=True)
    if not company: abort(404)
    drives = query("""SELECT d.*,
                      (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id) app_count
                      FROM placement_drives d WHERE d.company_id=? ORDER BY d.created_at DESC""", [cid])
    return render_template('admin/company_detail.html', company=company, drives=drives)


@app.route('/admin/companies/<int:cid>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_company(cid):
    c = query("SELECT * FROM companies WHERE id=?", [cid], one=True)
    if not c: abort(404)
    execute("UPDATE companies SET approval_status='approved' WHERE id=?", [cid])
    flash(f'Company "{c["company_name"]}" approved.', 'success')
    return redirect(url_for('admin_companies'))


@app.route('/admin/companies/<int:cid>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_company(cid):
    c = query("SELECT * FROM companies WHERE id=?", [cid], one=True)
    if not c: abort(404)
    execute("UPDATE companies SET approval_status='rejected' WHERE id=?", [cid])
    flash(f'"{c["company_name"]}" rejected.', 'warning')
    return redirect(url_for('admin_companies'))


@app.route('/admin/companies/<int:cid>/blacklist', methods=['POST'])
@login_required
@admin_required
def admin_blacklist_company(cid):
    c = query("SELECT * FROM companies WHERE id=?", [cid], one=True)
    if not c: abort(404)
    new = 0 if c['is_blacklisted'] else 1
    execute("UPDATE companies SET is_blacklisted=? WHERE id=?", [new, cid])
    action = 'blacklisted' if new else 'removed from blacklist'
    flash(f'"{c["company_name"]}" {action}.', 'info')
    return redirect(url_for('admin_companies'))


@app.route('/admin/companies/<int:cid>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_company(cid):
    c = query("SELECT * FROM companies WHERE id=?", [cid], one=True)
    if not c: abort(404)
    execute("DELETE FROM users WHERE id=?", [c['user_id']])
    flash('Company deleted.', 'success')
    return redirect(url_for('admin_companies'))


@app.route('/admin/students')
@login_required
@admin_required
def admin_students():
    search = request.args.get('search', '').strip()
    sql = """SELECT s.*, u.username,
             (SELECT COUNT(*) FROM applications a WHERE a.student_id=s.id) app_count
             FROM students s JOIN users u ON u.id=s.user_id WHERE 1=1"""
    args = []
    if search:
        sql += " AND (s.full_name LIKE ? OR s.email LIKE ? OR s.phone LIKE ? OR s.department LIKE ? OR u.username LIKE ?)"
        args += [f'%{search}%'] * 5
    sql += " ORDER BY s.created_at DESC"
    students = query(sql, args)
    return render_template('admin/students.html', students=students, search=search)


@app.route('/admin/students/<int:sid>')
@login_required
@admin_required
def admin_student_detail(sid):
    student = query("SELECT s.*,u.username FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=?", [sid], one=True)
    if not student: abort(404)
    apps = query("""SELECT a.*, d.job_title, d.package, c.company_name
                    FROM applications a
                    JOIN placement_drives d ON d.id=a.drive_id
                    JOIN companies c ON c.id=d.company_id
                    WHERE a.student_id=? ORDER BY a.application_date DESC""", [sid])
    return render_template('admin/student_detail.html', student=student, apps=apps)


@app.route('/admin/students/<int:sid>/blacklist', methods=['POST'])
@login_required
@admin_required
def admin_blacklist_student(sid):
    s = query("SELECT * FROM students WHERE id=?", [sid], one=True)
    if not s: abort(404)
    new = 0 if s['is_blacklisted'] else 1
    execute("UPDATE students SET is_blacklisted=? WHERE id=?", [new, sid])
    action = 'blacklisted' if new else 'removed from blacklist'
    flash(f'"{s["full_name"]}" {action}.', 'info')
    return redirect(url_for('admin_students'))


@app.route('/admin/students/<int:sid>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_student(sid):
    s = query("SELECT * FROM students WHERE id=?", [sid], one=True)
    if not s: abort(404)
    execute("DELETE FROM users WHERE id=?", [s['user_id']])
    flash('Student deleted.', 'success')
    return redirect(url_for('admin_students'))


@app.route('/admin/drives')
@login_required
@admin_required
def admin_drives():
    status_filter = request.args.get('status', 'all')
    sql = """SELECT d.*, c.company_name,
             (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id) app_count
             FROM placement_drives d JOIN companies c ON c.id=d.company_id WHERE 1=1"""
    args = []
    if status_filter != 'all':
        sql += " AND d.status=?"
        args.append(status_filter)
    sql += " ORDER BY d.created_at DESC"
    drives = query(sql, args)
    return render_template('admin/drives.html', drives=drives, status_filter=status_filter)


@app.route('/admin/drives/<int:did>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_drive(did):
    d = query("SELECT * FROM placement_drives WHERE id=?", [did], one=True)
    if not d: abort(404)
    execute("UPDATE placement_drives SET status='approved' WHERE id=?", [did])
    flash(f'Drive "{d["job_title"]}" approved.', 'success')
    return redirect(url_for('admin_drives'))


@app.route('/admin/drives/<int:did>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_drive(did):
    d = query("SELECT * FROM placement_drives WHERE id=?", [did], one=True)
    if not d: abort(404)
    execute("UPDATE placement_drives SET status='rejected' WHERE id=?", [did])
    flash(f'Drive "{d["job_title"]}" rejected.', 'warning')
    return redirect(url_for('admin_drives'))


@app.route('/admin/applications')
@login_required
@admin_required
def admin_applications():
    status_filter = request.args.get('status', 'all')
    sql = """SELECT a.*, s.full_name AS student_name, s.department, s.cgpa,
             d.job_title, d.package, c.company_name
             FROM applications a
             JOIN students s ON s.id=a.student_id
             JOIN placement_drives d ON d.id=a.drive_id
             JOIN companies c ON c.id=d.company_id WHERE 1=1"""
    args = []
    if status_filter != 'all':
        sql += " AND a.status=?"
        args.append(status_filter)
    sql += " ORDER BY a.application_date DESC"
    apps = query(sql, args)
    return render_template('admin/applications.html', apps=apps, status_filter=status_filter)


# ═══════════════════════════════════════════════════════════════
#  COMPANY ROUTES
# ═══════════════════════════════════════════════════════════════

def get_company():
    u = current_user()
    return query("SELECT * FROM companies WHERE user_id=?", [u['id']], one=True)


@app.route('/company/dashboard')
@login_required
@company_required
def company_dashboard():
    company = get_company()
    drives = query("""SELECT d.*,
                      (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id) app_count,
                      (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id AND a.status='shortlisted') shortlisted,
                      (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id AND a.status='selected') selected_c
                      FROM placement_drives d WHERE d.company_id=?
                      ORDER BY d.created_at DESC""", [company['id']])
    total_applicants = sum(d['app_count'] for d in drives)
    shortlisted      = sum(d['shortlisted'] for d in drives)
    selected         = sum(d['selected_c'] for d in drives)
    return render_template('company/dashboard.html', company=company, drives=drives,
                           total_applicants=total_applicants,
                           shortlisted=shortlisted, selected=selected)


@app.route('/company/drives/create', methods=['GET', 'POST'])
@login_required
@company_required
def company_create_drive():
    if request.method == 'POST':
        job_title   = request.form.get('job_title', '').strip()
        job_desc    = request.form.get('job_description', '').strip()
        eligibility = request.form.get('eligibility_criteria', '').strip()
        package     = request.form.get('package', '').strip()
        location    = request.form.get('location', '').strip()
        deadline    = request.form.get('application_deadline', '').strip() or None
        if not job_title:
            flash('Job title is required.', 'danger')
            return render_template('company/create_drive.html')
        company = get_company()
        execute("""INSERT INTO placement_drives
                   (company_id,job_title,job_description,eligibility_criteria,package,location,application_deadline,status)
                   VALUES (?,?,?,?,?,?,?,'pending')""",
                (company['id'], job_title, job_desc, eligibility, package, location, deadline))
        flash('Drive submitted for admin approval!', 'success')
        return redirect(url_for('company_dashboard'))
    return render_template('company/create_drive.html')


@app.route('/company/drives/<int:did>/edit', methods=['GET', 'POST'])
@login_required
@company_required
def company_edit_drive(did):
    company = get_company()
    drive = query("SELECT * FROM placement_drives WHERE id=? AND company_id=?", [did, company['id']], one=True)
    if not drive:
        flash('Drive not found.', 'danger')
        return redirect(url_for('company_dashboard'))
    if request.method == 'POST':
        execute("""UPDATE placement_drives
                   SET job_title=?, job_description=?, eligibility_criteria=?,
                       package=?, location=?, application_deadline=?, status='pending'
                   WHERE id=?""",
                (request.form.get('job_title','').strip(),
                 request.form.get('job_description','').strip(),
                 request.form.get('eligibility_criteria','').strip(),
                 request.form.get('package','').strip(),
                 request.form.get('location','').strip(),
                 request.form.get('application_deadline','').strip() or None,
                 did))
        flash('Drive updated. Awaiting re-approval.', 'info')
        return redirect(url_for('company_dashboard'))
    return render_template('company/edit_drive.html', drive=drive)


@app.route('/company/drives/<int:did>/delete', methods=['POST'])
@login_required
@company_required
def company_delete_drive(did):
    company = get_company()
    execute("DELETE FROM placement_drives WHERE id=? AND company_id=?", [did, company['id']])
    flash('Drive deleted.', 'success')
    return redirect(url_for('company_dashboard'))


@app.route('/company/drives/<int:did>/close', methods=['POST'])
@login_required
@company_required
def company_close_drive(did):
    company = get_company()
    execute("UPDATE placement_drives SET status='closed' WHERE id=? AND company_id=?", [did, company['id']])
    flash('Drive closed.', 'info')
    return redirect(url_for('company_dashboard'))


@app.route('/company/drives/<int:did>/applications')
@login_required
@company_required
def company_drive_applications(did):
    company = get_company()
    drive = query("SELECT * FROM placement_drives WHERE id=? AND company_id=?", [did, company['id']], one=True)
    if not drive:
        flash('Drive not found.', 'danger')
        return redirect(url_for('company_dashboard'))
    status_filter = request.args.get('status', 'all')
    sql = """SELECT a.*, s.full_name, s.email, s.phone, s.department,
             s.cgpa, s.skills, s.resume_filename, s.id AS sid
             FROM applications a JOIN students s ON s.id=a.student_id
             WHERE a.drive_id=?"""
    args = [did]
    if status_filter != 'all':
        sql += " AND a.status=?"
        args.append(status_filter)
    sql += " ORDER BY a.application_date ASC"
    applications = query(sql, args)
    return render_template('company/drive_applications.html', drive=drive,
                           applications=applications, status_filter=status_filter)


@app.route('/company/applications/<int:app_id>/update', methods=['POST'])
@login_required
@company_required
def company_update_application(app_id):
    company = get_company()
    app_row = query("""SELECT a.*, d.company_id, a.drive_id FROM applications a
                       JOIN placement_drives d ON d.id=a.drive_id WHERE a.id=?""", [app_id], one=True)
    if not app_row or app_row['company_id'] != company['id']:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('company_dashboard'))
    new_status = request.form.get('status', '')
    if new_status in ['applied', 'shortlisted', 'selected', 'rejected']:
        execute("UPDATE applications SET status=? WHERE id=?", [new_status, app_id])
        flash(f'Status updated to "{new_status}".', 'success')
    return redirect(url_for('company_drive_applications', did=app_row['drive_id']))


# ═══════════════════════════════════════════════════════════════
#  STUDENT ROUTES
# ═══════════════════════════════════════════════════════════════

def get_student():
    u = current_user()
    return query("SELECT * FROM students WHERE user_id=?", [u['id']], one=True)


@app.route('/student/dashboard')
@login_required
@student_required
def student_dashboard():
    student = get_student()
    apps = query("""SELECT a.*, d.job_title, d.package, d.location, c.company_name
                    FROM applications a
                    JOIN placement_drives d ON d.id=a.drive_id
                    JOIN companies c ON c.id=d.company_id
                    WHERE a.student_id=? ORDER BY a.application_date DESC""", [student['id']])
    approved_drives = query("SELECT COUNT(*) c FROM placement_drives WHERE status='approved'", one=True)['c']
    applied_ids = {a['drive_id'] for a in apps}
    counts = dict(
        shortlisted=sum(1 for a in apps if a['status'] == 'shortlisted'),
        selected=sum(1 for a in apps if a['status'] == 'selected'),
    )
    u = current_user()
    return render_template('student/dashboard.html', student=student, user=u,
                           apps=apps, approved_drives=approved_drives,
                           applied_ids=applied_ids, counts=counts)


@app.route('/student/drives')
@login_required
@student_required
def student_drives():
    student = get_student()
    drives = query("""SELECT d.*, c.company_name, c.industry,
                      (SELECT COUNT(*) FROM applications a WHERE a.drive_id=d.id) app_count
                      FROM placement_drives d JOIN companies c ON c.id=d.company_id
                      WHERE d.status='approved' ORDER BY d.created_at DESC""")
    applied_ids = {r['drive_id'] for r in
                   query("SELECT drive_id FROM applications WHERE student_id=?", [student['id']])}
    today = date.today().isoformat()
    return render_template('student/drives.html', drives=drives,
                           applied_ids=applied_ids, today=today)


@app.route('/student/drives/<int:did>/apply', methods=['GET', 'POST'])
@login_required
@student_required
def student_apply(did):
    student = get_student()
    drive = query("""SELECT d.*, c.company_name, c.industry
                     FROM placement_drives d JOIN companies c ON c.id=d.company_id
                     WHERE d.id=?""", [did], one=True)
    if not drive or drive['status'] != 'approved':
        flash('Drive not available.', 'danger')
        return redirect(url_for('student_drives'))
    today = date.today().isoformat()
    if drive['application_deadline'] and drive['application_deadline'] < today:
        flash('Application deadline has passed.', 'danger')
        return redirect(url_for('student_drives'))
    if query("SELECT id FROM applications WHERE student_id=? AND drive_id=?", [student['id'], did], one=True):
        flash('You have already applied for this drive.', 'warning')
        return redirect(url_for('student_drives'))
    if request.method == 'POST':
        cover = request.form.get('cover_letter', '').strip()
        execute("INSERT INTO applications (student_id,drive_id,cover_letter) VALUES (?,?,?)",
                (student['id'], did, cover))
        flash(f'Application submitted for "{drive["job_title"]}"!', 'success')
        return redirect(url_for('student_drives'))
    return render_template('student/apply.html', drive=drive)


@app.route('/student/profile')
@login_required
@student_required
def student_profile():
    student = get_student()
    u = current_user()
    return render_template('student/profile.html', student=student, user=u)


@app.route('/student/profile/edit', methods=['GET', 'POST'])
@login_required
@student_required
def student_edit_profile():
    student = get_student()
    if request.method == 'POST':
        full_name  = request.form.get('full_name', '').strip()
        phone      = request.form.get('phone', '').strip()
        dept       = request.form.get('department', '').strip()
        skills     = request.form.get('skills', '').strip()
        address    = request.form.get('address', '').strip()
        try:    cgpa = float(request.form.get('cgpa', 0) or 0)
        except: cgpa = 0.0
        try:
            gy = request.form.get('graduation_year', '').strip()
            grad_year = int(gy) if gy else None
        except: grad_year = None
        resume_filename = student['resume_filename']
        if 'resume' in request.files:
            f = request.files['resume']
            if f and f.filename and allowed_file(f.filename):
                fname = secure_filename(f"resume_{student['id']}_{f.filename}")
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
                resume_filename = fname
        execute("""UPDATE students SET full_name=?,phone=?,department=?,skills=?,
                   address=?,cgpa=?,graduation_year=?,resume_filename=? WHERE id=?""",
                (full_name, phone, dept, skills, address, cgpa, grad_year, resume_filename, student['id']))
        flash('Profile updated!', 'success')
        return redirect(url_for('student_profile'))
    return render_template('student/edit_profile.html', student=student)


@app.route('/student/history')
@login_required
@student_required
def student_history():
    student = get_student()
    apps = query("""SELECT a.*, d.job_title, d.package, d.location,
                    d.application_deadline, c.company_name
                    FROM applications a
                    JOIN placement_drives d ON d.id=a.drive_id
                    JOIN companies c ON c.id=d.company_id
                    WHERE a.student_id=? ORDER BY a.application_date DESC""", [student['id']])
    counts = dict(
        total=len(apps),
        applied=sum(1 for a in apps if a['status']=='applied'),
        shortlisted=sum(1 for a in apps if a['status']=='shortlisted'),
        selected=sum(1 for a in apps if a['status']=='selected'),
        rejected=sum(1 for a in apps if a['status']=='rejected'),
    )
    return render_template('student/history.html', student=student, apps=apps, counts=counts)


# ═══════════════════════════════════════════════════════════════
#  API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/api/drives')
def api_drives():
    drives = query("""SELECT d.id, d.job_title, c.company_name, d.location,
                      d.package, d.application_deadline, d.status
                      FROM placement_drives d JOIN companies c ON c.id=d.company_id
                      WHERE d.status='approved'""")
    return jsonify([dict(r) for r in drives])


@app.route('/api/students')
def api_students():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    students = query("SELECT id,full_name,department,cgpa,graduation_year,is_blacklisted FROM students")
    return jsonify([dict(r) for r in students])


@app.route('/api/applications')
def api_applications():
    if not session.get('user_id') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    apps = query("""SELECT a.id, s.full_name AS student, d.job_title AS drive,
                    c.company_name AS company, a.status, a.application_date
                    FROM applications a
                    JOIN students s ON s.id=a.student_id
                    JOIN placement_drives d ON d.id=a.drive_id
                    JOIN companies c ON c.id=d.company_id
                    ORDER BY a.application_date DESC""")
    return jsonify([dict(r) for r in apps])


# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    init_db()
    app.run(debug=True, port=5001)
