<<<<<<< HEAD
# placement
=======
# PlacePro – Campus Placement Portal

## Setup & Run

```bash
pip install Flask Werkzeug
python app.py
```

Visit: http://127.0.0.1:5000

## Default Admin Login
- Username: `admin`
- Password: `admin123`

## Demo Flow
1. Register as Student → login → browse drives → apply
2. Register as Company → wait for admin approval → login → post drives
3. Admin approves companies & drives, manages everything

## Roles
| Role    | Access                                              |
|---------|-----------------------------------------------------|
| Admin   | Dashboard, approve/reject companies & drives, manage users |
| Company | Post drives, view applicants, update statuses       |
| Student | Browse approved drives, apply, track status, upload resume |

## API Endpoints
- `GET /api/drives` — list approved drives (public)
- `GET /api/students` — list students (admin only)
- `GET /api/applications` — list all applications (admin only)

## Stack
- Flask + Jinja2 + Bootstrap 5
- SQLite (stdlib sqlite3, no ORM)
- Pure Flask sessions (no flask-login)
- No JS required for core functionality
>>>>>>> ecb6c0d (Initial commit)
