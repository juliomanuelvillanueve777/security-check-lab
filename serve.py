"""
Security Check Lab — local development server.
Binds exclusively to 127.0.0.1:8080 by default.

Optional flags:
  --lan            Bind to 0.0.0.0 (WARNING: exposes lab to every device on
                   your local network — use only on a trusted Wi-Fi network).
  --https CERT,KEY Enable HTTPS using PEM-encoded certificate and private key
                   files, e.g. --https cert.pem,key.pem  (required for camera
                   access from a phone over LAN — see README-mobile.md).
  --port N         Listen on port N instead of 8080.
"""

import argparse
import base64
import html
import http.server
import json
import os
import re
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import sqlite3
import socketserver
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

# ── CLI flags ─────────────────────────────────────────────────────────────

_default_port = int(os.environ.get('PORT', 8080))
_ap = argparse.ArgumentParser(description='Security Check Lab — local dev server', add_help=True)
_ap.add_argument('--lan',   action='store_true',
                 help='Bind to 0.0.0.0 (LAN access — trusted Wi-Fi only)')
_ap.add_argument('--https', metavar='CERT,KEY',
                 help='Enable HTTPS: PEM cert and key files, comma-separated')
_ap.add_argument('--port',  type=int, default=_default_port,
                 help=f'Port to listen on (default: {_default_port})')
_ARGS = _ap.parse_args()

# ── Config ────────────────────────────────────────────────────────────────

PORT    = _ARGS.port
HOST    = '0.0.0.0' if (_ARGS.lan or os.environ.get('PORT')) else '127.0.0.1'
ROOT    = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(ROOT, 'lab.db')

# ── Email / SMTP Config ───────────────────────────────────────────────────

NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL', 'louiep89@outlook.com')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.office365.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

def send_recruitment_email(candidate_name, form_data, file_paths):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER if SMTP_USER else NOTIFICATION_EMAIL
        msg['To'] = NOTIFICATION_EMAIL
        msg['Subject'] = f"Aplicație Nouă - Candidat: {candidate_name}"

        body = f"A fost înregistrată o nouă aplicație.\n\n"
        body += "--- DETALII CANDIDAT ---\n"
        for key, value in form_data.items():
            body += f"{key}: {value}\n"

        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        for path in file_paths:
            if os.path.exists(path):
                filename = os.path.basename(path)
                with open(path, "rb") as attachment:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f"attachment; filename= {filename}",
                    )
                    msg.attach(part)

        if SMTP_USER and SMTP_PASSWORD:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(msg['From'], NOTIFICATION_EMAIL, msg.as_string())
            server.quit()
            print(f"[OK] E-mail trimis cu succes către {NOTIFICATION_EMAIL}")
        else:
            print(f"[INFO] Datele SMTP lipsesc, dar fișierele au fost salvate local pentru candidatul {candidate_name}.")
    except Exception as e:
        print(f"[EROARE] Trimiterea e-mailului a eșuat: {e}")

MAX_BODY    = 64 * 1024   # 64 KB (accommodates multi-entry address payloads)
MAX_STR_LEN = 200         # per-field character ceiling

# Canonical storage root (all sessions, all artifact types)
RECORDS_DIR    = os.path.join(ROOT, 'records')
MAX_IMG_BODY   = 15 * 1024 * 1024   # 15 MB JSON body (base64 of ~10 MB image)
MAX_IMAGE_RAW  = 10 * 1024 * 1024   # 10 MB decoded image
MAX_VID_BODY   = 100 * 1024 * 1024  # 100 MB raw video
MAX_EVENT_TEXT = 500                 # max chars per appended event line
MAX_DOC_RAW    = 10 * 1024 * 1024   # 10 MB decoded document
MAX_DOC_BODY   = 14 * 1024 * 1024   # 14 MB JSON body (base64 overhead ~1.37×)

UPLOAD_CATEGORIES = frozenset({'cv', 'identity-doc', 'poa-doc', 'share-code-doc'})

# API upload category → filesystem subdirectory name inside the session directory
_CATEGORY_DIR = {
    'cv':             'cv',
    'identity-doc':   'identity-doc',
    'poa-doc':        'poa-doc',
    'share-code-doc': 'share-code',
}

# Artifact short API name → path relative to session directory
_ARTIFACT_SUBPATH = {
    '02-facial-capture.jpg':       'facial-capture/02-facial-capture.jpg',
    '03-facial-verification.webm': 'facial-verification/03-facial-verification.webm',
}

# Magic byte → (detected mime, extension)
_DOC_MAGIC = [
    (b'%PDF',           'application/pdf',  '.pdf'),
    (b'\xff\xd8',       'image/jpeg',       '.jpg'),
    (b'\x89PNG',        'image/png',        '.png'),
    (b'PK\x03\x04',    'application/zip',  '.docx'),   # DOCX/XLSX/PPTX are ZIP
]

# Category → set of detected mime types allowed
_CATEGORY_ALLOWED = {
    'cv':              frozenset({'application/pdf', 'application/zip'}),
    'identity-doc':    frozenset({'application/pdf', 'image/jpeg', 'image/png'}),
    'poa-doc':         frozenset({'application/pdf', 'image/jpeg', 'image/png'}),
    'share-code-doc':  frozenset({'application/pdf', 'image/jpeg', 'image/png'}),
}

# F1: category → session statuses that permit an upload.
# cv and identity-doc are uploaded immediately after /api/submit (status='started');
# all later statuses are also valid (e.g. retake after address-history step).
# poa-doc is only uploaded after /api/poa succeeds (status='poa_done'); earlier
# statuses indicate the POA step has not been completed.
_CATEGORY_VALID_STATUSES = {
    'cv':              frozenset({'started', 'addr_history', 'poa_done', 'face_check', 'completed'}),
    'identity-doc':    frozenset({'started', 'addr_history', 'poa_done', 'face_check', 'completed'}),
    'share-code-doc':  frozenset({'started', 'addr_history', 'poa_done', 'face_check', 'completed'}),
    'poa-doc':         frozenset({'poa_done', 'face_check', 'completed'}),
}

# Artifact names: only these two can be saved or deleted via API (short names)
SAVE_ARTIFACTS = frozenset(_ARTIFACT_SUBPATH.keys())
# All four can be read/listed (short names; mapped to sub-paths via _ARTIFACT_SUBPATH)
READ_ARTIFACTS = frozenset({
    'details.txt',
    '04-session-events.txt',
} | set(_ARTIFACT_SUBPATH.keys()))

ALLOWED_EVENTS = frozenset({
    'session_started',
    'form_validation_passed',
    'synthetic_record_saved',
    'next_stage_opened',      # legacy — kept in allowlist for idempotency on old sessions
    'face_sim_started',
    'simulation_completed',
})

# Maps current_status → {event_name: new_status} for /api/event transitions.
# addr_history and poa_done transitions are driven by their own dedicated endpoints.
TRANSITIONS = {
    'poa_done':   {'face_sim_started':     'face_check'},
    'face_check': {'simulation_completed': 'completed'},
    'completed':  {},
}

# Events that must produce a status change; rejected if no transition found.
STATUS_CHANGING_EVENTS = frozenset(
    evt for t in TRANSITIONS.values() for evt in t
)

DOC_TYPES     = frozenset({'passport', 'driving_licence', 'national_id', 'id_card'})
POA_DOC_TYPES = frozenset({'utility_bill', 'bank_statement', 'driving_licence_poa'})

RE_EMAIL   = re.compile(r'^[^\s@]{1,64}@[^\s@]{1,64}\.[^\s@]{1,32}$')
RE_PHONE   = re.compile(r'^[\d\s\+\(\)\-]{7,15}$')
RE_NINO    = re.compile(r'^[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]$', re.IGNORECASE)
RE_RTW     = re.compile(r'^[A-Z0-9]{3}[-\s]?[A-Z0-9]{3}[-\s]?[A-Z0-9]{3}$', re.IGNORECASE)
RE_SALARY  = re.compile(r'^[£$]?\d[\d,]*(\.\d{1,2})?(k|K)?$')
RE_SID     = re.compile(r'^[0-9a-f]{32}$')
RE_SAFE_FN = re.compile(r'[^\w.\- ]')
RE_YM      = re.compile(r'^\d{4}-(0[1-9]|1[0-2])$')   # YYYY-MM

# ── Date / month helpers ──────────────────────────────────────────────────

def _parse_ym(s):
    """'YYYY-MM' → (year, month) int tuple."""
    return (int(s[:4]), int(s[5:7]))

def _ym_str(ym):
    """(year, month) → 'YYYY-MM'."""
    return f'{ym[0]}-{ym[1]:02d}'

def _add_months(ym, n):
    """Add n months (may be negative) to a (year, month) tuple."""
    y, m = ym
    total = y * 12 + (m - 1) + n
    return (total // 12, total % 12 + 1)

def _month_range_set(start_ym, end_ym):
    """Set of (year, month) tuples from start_ym to end_ym inclusive."""
    months = set()
    cur = start_ym
    while cur <= end_ym:
        months.add(cur)
        cur = _add_months(cur, 1)
    return months

def _required_window(session_created_at):
    """
    Returns (window_start, anchor) for the required 5-year coverage window.

    anchor     = calendar month of session creation  (YYYY-MM slice of created_at).
    window     = 60 calendar months ending at anchor, inclusive on both ends.
    Example:   anchor 2026-10  →  window_start 2021-11  …  2026-10 (60 months).
    """
    anchor = _parse_ym(session_created_at[:7])
    start  = _add_months(anchor, -59)   # 60 months inclusive
    return start, anchor

# ── Database ──────────────────────────────────────────────────────────────

def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _connect()

    # Create all tables; executescript uses autocommit so IF NOT EXISTS is safe.
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id           TEXT    PRIMARY KEY,
            first_name   TEXT    NOT NULL,
            last_name    TEXT    NOT NULL,
            dob          TEXT    NOT NULL,
            address      TEXT    NOT NULL,
            email        TEXT    NOT NULL,
            phone        TEXT    NOT NULL,
            rtw          TEXT    NOT NULL,
            nino         TEXT    NOT NULL,
            employer     TEXT    NOT NULL,
            job_title    TEXT    NOT NULL,
            salary       TEXT    NOT NULL,
            duration     TEXT    NOT NULL,
            doc_type     TEXT    NOT NULL,
            cv_filename  TEXT,
            cv_selected  INTEGER NOT NULL DEFAULT 0,
            doc_filename TEXT,
            doc_selected INTEGER NOT NULL DEFAULT 0,
            status       TEXT    NOT NULL DEFAULT 'started',
            created_at   TEXT    NOT NULL,
            updated_at   TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT    NOT NULL,
            event_name   TEXT    NOT NULL,
            created_at   TEXT    NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS address_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT    NOT NULL,
            sort_order   INTEGER NOT NULL,
            line1        TEXT    NOT NULL,
            line2        TEXT,
            city         TEXT    NOT NULL,
            postcode     TEXT    NOT NULL,
            country      TEXT    NOT NULL,
            move_in      TEXT    NOT NULL,
            move_out     TEXT,
            is_current   INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT    NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
    """)

    # Additive migration: add new columns to sessions only if missing.
    # Uses PRAGMA table_info rather than ALTER TABLE … IF NOT EXISTS.
    existing = {row['name'] for row in conn.execute('PRAGMA table_info(sessions)')}
    new_cols = [
        ('poa_doc_type', 'TEXT'),
        ('poa_filename',  'TEXT'),
        ('poa_selected',  'INTEGER DEFAULT 0'),
    ]
    for col_name, col_def in new_cols:
        if col_name not in existing:
            conn.execute(f'ALTER TABLE sessions ADD COLUMN {col_name} {col_def}')
    conn.commit()
    conn.close()

def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def _sanitise_filename(raw):
    if not isinstance(raw, str) or not raw.strip():
        return None
    basename = os.path.basename(raw.strip())[:100]
    return RE_SAFE_FN.sub('_', basename) or None

def _gs(addr, key, maxlen=200):
    """Safe string getter from a dict: returns stripped, length-limited string."""
    v = addr.get(key, '')
    if v is None:
        return ''
    return str(v).strip()[:maxlen]

# ── Session directory helpers ─────────────────────────────────────────────

_SAFE_NAME_RE = re.compile(r'[^\w\- ]')

def _session_dir(sid, conn=None):
    """Return the canonical directory path for a session (does not create it).
    Returns None if the session does not exist in the database."""
    def _lookup(c):
        return c.execute(
            'SELECT first_name, last_name FROM sessions WHERE id = ?', (sid,)
        ).fetchone()

    if conn is not None:
        row = _lookup(conn)
    else:
        c = _connect()
        try:
            row = _lookup(c)
        finally:
            c.close()

    if row is None:
        return None

    full_name = f"{row['first_name']} {row['last_name']}".strip()
    safe_name = _SAFE_NAME_RE.sub('_', full_name)[:60].strip('_ ')
    dir_name  = f'{safe_name} ({sid[:8]})'
    return os.path.join(RECORDS_DIR, dir_name)

def _collect_session_files(sess_dir):
    """Collect all non-temporary files from the session directory and its subdirectories."""
    file_paths = []
    if not sess_dir or not os.path.isdir(sess_dir):
        return file_paths
    for root, _, files in os.walk(sess_dir):
        for f in sorted(files):
            if not f.endswith('.tmp'):
                file_paths.append(os.path.join(root, f))
    return file_paths

def _send_session_email_notification(sid, conn=None):
    """Send recruitment email notification with attached files for a session."""
    close_conn = False
    if conn is None:
        conn = _connect()
        close_conn = True
    try:
        sess_dir = _session_dir(sid, conn)
        row = conn.execute('SELECT * FROM sessions WHERE id = ?', (sid,)).fetchone()
        if not row:
            return
        form_data = dict(row)
        full_name = f"{form_data.get('first_name', '')} {form_data.get('last_name', '')}".strip()
        candidate_name = full_name if full_name else 'Candidat_Anonim'
        files = _collect_session_files(sess_dir)
        send_recruitment_email(candidate_name, form_data, files)
    except Exception as e:
        print(f"[EROARE] Trimiterea notificării pentru sesiunea {sid} a eșuat: {e}")
    finally:
        if close_conn:
            conn.close()

def _append_record_event(sid, line):
    """Append one sanitised line to 04-session-events.txt; no-op if directory missing."""
    rec_dir = _session_dir(sid)
    if rec_dir is None or not os.path.isdir(rec_dir):
        return
    log_path = os.path.join(rec_dir, '04-session-events.txt')
    clean = re.sub(r'[\r\n]', ' ', line.strip())[:MAX_EVENT_TEXT]
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f'{_now()}  {clean}\n')

def _gen_submitted_data(conn, sid):
    """Generate text content for details.txt from the database."""
    s = conn.execute(
        '''SELECT first_name, last_name, dob, address, email, phone,
                  rtw, nino, employer, job_title, salary, duration,
                  doc_type, cv_filename, cv_selected, doc_filename, doc_selected,
                  poa_doc_type, poa_filename, poa_selected,
                  status, created_at, updated_at
           FROM sessions WHERE id = ?''', (sid,)
    ).fetchone()
    if s is None:
        return None

    addrs = conn.execute(
        '''SELECT line1, line2, city, postcode, country, move_in, move_out, is_current
           FROM address_history WHERE session_id = ? ORDER BY sort_order ASC''',
        (sid,)
    ).fetchall()

    evts = conn.execute(
        'SELECT event_name, created_at FROM events WHERE session_id = ? ORDER BY id ASC',
        (sid,)
    ).fetchall()

    ts = _now()
    lines = [
        '=== SECURITY TRAINING LAB -- SYNTHETIC TEST RECORD ===',
        f'Generated     : {ts}',
        f'Session ID    : {sid}',
        f'Status        : {s["status"]}',
        f'Session start : {s["created_at"]}',
        f'Last updated  : {s["updated_at"]}',
        '',
        'IMPORTANT: This record contains SYNTHETIC TEST DATA only.',
        'Not a real identity record. No biometric processing was performed.',
        '',
        '--- 1. PERSONAL DETAILS ---',
        f'First name    : {s["first_name"]}',
        f'Last name     : {s["last_name"]}',
        f'Date of birth : {s["dob"]}',
        f'Address       : {s["address"]}',
        f'Email         : {s["email"]}',
        f'Phone         : {s["phone"]}',
        '',
        '--- 2. EMPLOYMENT ELIGIBILITY (DEMONSTRATION ONLY) ---',
        f'RTW code      : {s["rtw"]}',
        f'NINO          : {s["nino"]}',
        '',
        '--- 3. EMPLOYMENT HISTORY ---',
        f'Employer      : {s["employer"]}',
        f'Job title     : {s["job_title"]}',
        f'Salary        : {s["salary"]}',
        f'Duration      : {s["duration"]}',
        f'CV filename   : {s["cv_filename"] or "(not selected)"}',
        f'CV selected   : {"Yes" if s["cv_selected"] else "No"}',
        '',
        '--- 4. IDENTITY DOCUMENT (DEMONSTRATION ONLY) ---',
        f'Doc type      : {s["doc_type"]}',
        f'Doc filename  : {s["doc_filename"] or "(not selected)"}',
        f'Doc selected  : {"Yes" if s["doc_selected"] else "No"}',
        '',
        '--- 5. ADDRESS HISTORY ---',
    ]

    if addrs:
        for i, a in enumerate(addrs, 1):
            lines.append(f'Entry {i}:')
            lines.append(f'  Line 1    : {a["line1"]}')
            if a['line2']:
                lines.append(f'  Line 2    : {a["line2"]}')
            lines.append(f'  City      : {a["city"]}')
            lines.append(f'  Postcode  : {a["postcode"]}')
            lines.append(f'  Country   : {a["country"]}')
            lines.append(f'  Move-in   : {a["move_in"]}')
            if a['is_current']:
                lines.append(f'  Status    : Current address')
            else:
                lines.append(f'  Move-out  : {a["move_out"] or "(not recorded)"}')
    else:
        lines.append('(no address history recorded)')

    lines += [
        '',
        '--- 6. PROOF OF ADDRESS ---',
        f'Document type : {s["poa_doc_type"] or "(not selected)"}',
        f'Filename      : {s["poa_filename"] or "(not selected)"}',
        f'File selected : {"Yes" if s["poa_selected"] else "No"}',
        '',
        '--- 7. WORKFLOW EVENT TIMELINE ---',
    ]

    for ev in evts:
        lines.append(f'  {ev["created_at"]}  {ev["event_name"]}')
    if not evts:
        lines.append('  (no events)')

    lines += [
        '',
        '=== END OF SUBMITTED DATA ===',
        'SYNTHETIC TEST DATA ONLY -- NOT A REAL IDENTITY RECORD.',
    ]

    return '\n'.join(lines) + '\n'

# ── Server-side validation ────────────────────────────────────────────────

class _ValidationError(Exception):
    def __init__(self, errors: dict):
        self.errors = errors

def _validate_submission(body: dict) -> dict:
    if not isinstance(body, dict):
        raise _ValidationError({'_form': 'Request body must be a JSON object.'})

    known_keys = {
        'firstName', 'lastName', 'dob', 'address', 'email', 'phone',
        'rtw', 'nino', 'employer', 'jobTitle', 'salary', 'duration',
        'docType', 'cvFilename', 'cvSelected', 'docFilename', 'docSelected',
    }
    unknown = set(body.keys()) - known_keys
    if unknown:
        raise _ValidationError({'_form': 'Unexpected fields in request.'})

    errors = {}

    def get_str(key):
        v = body.get(key, '')
        return str(v).strip()[:MAX_STR_LEN] if isinstance(v, str) else ''

    def require(key, label):
        v = get_str(key)
        if not v:
            errors[key] = f'{label} is required.'
        return v

    first_name = require('firstName', 'First name')
    last_name  = require('lastName',  'Last name')

    dob = get_str('dob')
    if not dob:
        errors['dob'] = 'Date of birth is required.'
    else:
        try:
            d   = datetime.strptime(dob, '%Y-%m-%d')
            now = datetime.now()
            age = now.year - d.year - ((now.month, now.day) < (d.month, d.day))
            if d >= now or age < 16 or age > 120:
                errors['dob'] = 'Date of birth must be valid; candidate must be 16–120 years old.'
        except ValueError:
            errors['dob'] = 'Date of birth format is invalid (expected YYYY-MM-DD).'

    address = get_str('address')
    if len(address) < 5:
        errors['address'] = 'Residential address is required (at least 5 characters).'

    email = get_str('email')
    if not RE_EMAIL.match(email):
        errors['email'] = 'Enter a valid email address.'

    phone = get_str('phone')
    if not RE_PHONE.match(phone):
        errors['phone'] = 'Enter a valid phone number (7–15 digits).'

    rtw = get_str('rtw')
    if not RE_RTW.match(rtw):
        errors['rtw'] = 'Enter a valid share code in format XXX-XXX-XXX (e.g. W1X-2YZ-3AB).'

    nino = get_str('nino')
    if not RE_NINO.match(nino):
        errors['nino'] = 'Enter a synthetic NINO in format AB 12 34 56 C.'

    employer  = require('employer',  'Most recent employer')
    job_title = require('jobTitle',  'Job title')

    salary = get_str('salary')
    if not RE_SALARY.match(salary):
        errors['salary'] = 'Enter a salary value, e.g. £45,000.'

    duration = require('duration', 'Employment duration')

    doc_type = get_str('docType')
    if doc_type not in DOC_TYPES:
        errors['docType'] = 'Select a valid document type.'

    if errors:
        raise _ValidationError(errors)

    return {
        'first_name':   first_name,
        'last_name':    last_name,
        'dob':          dob,
        'address':      address,
        'email':        email,
        'phone':        phone,
        'rtw':          rtw,
        'nino':         nino,
        'employer':     employer,
        'job_title':    job_title,
        'salary':       salary,
        'duration':     duration,
        'doc_type':     doc_type,
        'cv_filename':  _sanitise_filename(body.get('cvFilename')),
        'cv_selected':  1 if body.get('cvSelected') else 0,
        'doc_filename': _sanitise_filename(body.get('docFilename')),
        'doc_selected': 1 if body.get('docSelected') else 0,
    }

def _validate_addresses(addresses, session_created_at):
    """
    Validate a list of address history entries against the 5-year coverage window.
    Returns cleaned list of dicts on success; raises _ValidationError on failure.

    Window: 60 calendar months ending at session_created_at's calendar month
    (inclusive on both ends). Current address has move_out = None and covers
    from move_in through the anchor month.
    """
    if not isinstance(addresses, list):
        raise _ValidationError({'addresses': 'addresses must be a list.'})
    if not (1 <= len(addresses) <= 10):
        raise _ValidationError({'addresses': 'Provide between 1 and 10 address entries.'})

    window_start, anchor = _required_window(session_created_at)
    now_ym = _parse_ym(_now()[:7])

    errors:    dict = {}
    cleaned:   list = []
    all_months: set = set()   # union of months covered across all entries

    for i, addr in enumerate(addresses):
        pfx = f'addresses[{i}]'

        if not isinstance(addr, dict):
            errors[pfx] = 'Each entry must be a JSON object.'
            cleaned.append(None)
            continue

        line1       = _gs(addr, 'line1', 200)
        line2       = _gs(addr, 'line2', 200)
        city        = _gs(addr, 'city', 100)
        postcode    = _gs(addr, 'postcode', 20)
        country     = _gs(addr, 'country', 60)
        move_in_raw = _gs(addr, 'moveIn', 7)
        is_current  = bool(addr.get('isCurrent', False))
        move_out_raw = '' if is_current else _gs(addr, 'moveOut', 7)

        entry_errors: dict = {}

        if not line1:
            entry_errors[f'{pfx}.line1'] = 'Address line 1 is required.'
        if not city:
            entry_errors[f'{pfx}.city'] = 'City/town is required.'
        if not postcode:
            entry_errors[f'{pfx}.postcode'] = 'Postcode is required.'
        if not country:
            entry_errors[f'{pfx}.country'] = 'Country is required.'

        move_in_ym = None
        if not move_in_raw:
            entry_errors[f'{pfx}.moveIn'] = 'Move-in date (YYYY-MM) is required.'
        elif not RE_YM.match(move_in_raw):
            entry_errors[f'{pfx}.moveIn'] = 'Move-in date must be in YYYY-MM format.'
        else:
            move_in_ym = _parse_ym(move_in_raw)
            if move_in_ym > now_ym:
                entry_errors[f'{pfx}.moveIn'] = 'Move-in date cannot be in the future.'

        move_out_ym = None
        if is_current:
            move_out_ym = anchor   # current address covers through anchor month
        else:
            if not move_out_raw:
                entry_errors[f'{pfx}.moveOut'] = (
                    'Move-out date is required (or check "current address").'
                )
            elif not RE_YM.match(move_out_raw):
                entry_errors[f'{pfx}.moveOut'] = 'Move-out date must be in YYYY-MM format.'
            else:
                move_out_ym = _parse_ym(move_out_raw)
                if move_in_ym and move_out_ym < move_in_ym:
                    entry_errors[f'{pfx}.moveOut'] = (
                        'Move-out date must not be before move-in date.'
                    )

        if entry_errors:
            errors.update(entry_errors)
            cleaned.append(None)
            continue

        addr_months = _month_range_set(move_in_ym, move_out_ym)

        overlap = addr_months & all_months
        if overlap:
            first_overlap = _ym_str(min(overlap))
            errors[f'{pfx}._'] = (
                f'This address overlaps with another entry at {first_overlap}.'
            )
            cleaned.append(None)
            continue

        all_months |= addr_months
        cleaned.append({
            'line1':      line1,
            'line2':      line2 or None,
            'city':       city,
            'postcode':   postcode,
            'country':    country,
            'move_in':    move_in_raw,
            'move_out':   None if is_current else move_out_raw,
            'is_current': 1 if is_current else 0,
        })

    if errors:
        raise _ValidationError(errors)

    # Coverage check: every required month must be covered by exactly one entry.
    required = _month_range_set(window_start, anchor)
    missing  = required - all_months
    if missing:
        first_missing = _ym_str(min(missing))
        raise _ValidationError({'addresses': (
            f'Address history does not cover the full five-year window. '
            f'Missing coverage from at least {first_missing}. '
            f'Required: {_ym_str(window_start)} through {_ym_str(anchor)} '
            f'(60 months inclusive).'
        )})

    return [c for c in cleaned if c is not None]

# ── HTTP handler ──────────────────────────────────────────────────────────

class LabHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    # ── GET routing ──────────────────────────────────────────────────────

    def do_GET(self):
        clean = self.path.split('?')[0].rstrip('/')

        # Block direct static access to test-records/ and records/
        if clean.startswith('/test-records') or clean.startswith('/records'):
            self._json_err(403, 'Direct access to upload storage is not permitted.')
            return

        if clean == '/lab/audit':
            self._serve_audit()
            return
        if clean == '/api/session-status':
            self._handle_session_status()
            return
        if clean == '/api/record/artifacts':
            self._handle_record_list()
            return
        if clean == '/api/record/artifact':
            self._handle_record_get()
            return
        if clean == '/lab/face-check':
            self.path = '/lab/face-check/index.html'
        elif clean in ('', '/'):
            self.path = '/index.html'
        super().do_GET()

    # ── POST routing ─────────────────────────────────────────────────────

    def do_POST(self):
        path = self.path.split('?')[0]
        if path == '/api/submit':
            self._handle_submit()
        elif path == '/submit':
            self._handle_direct_submit()
        elif path == '/api/event':
            self._handle_event()
        elif path == '/api/addr-history':
            self._handle_addr_history()
        elif path == '/api/poa':
            self._handle_poa()
        elif path == '/api/upload-doc':
            self._handle_upload_doc()
        elif path == '/api/record/init':
            self._handle_record_init()
        elif path == '/api/record/save':
            self._handle_record_save()
        elif path == '/api/record/delete':
            self._handle_record_delete()
        elif path == '/api/record/event':
            self._handle_record_event()
        else:
            self._json_err(404, 'Not found.')

    # ── POST /api/submit ──────────────────────────────────────────────────

    def _handle_submit(self):
        body = self._read_json()
        if body is None:
            return

        try:
            data = _validate_submission(body)
        except _ValidationError as e:
            self._json_out(422, {'errors': e.errors})
            return

        sid = secrets.token_hex(16)
        ts  = _now()

        try:
            with _connect() as conn:
                conn.execute(
                    """INSERT INTO sessions
                       (id, first_name, last_name, dob, address, email, phone,
                        rtw, nino, employer, job_title, salary, duration,
                        doc_type, cv_filename, cv_selected, doc_filename, doc_selected,
                        status, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (sid,
                     data['first_name'], data['last_name'], data['dob'],
                     data['address'],    data['email'],      data['phone'],
                     data['rtw'],        data['nino'],
                     data['employer'],   data['job_title'],  data['salary'],
                     data['duration'],   data['doc_type'],
                     data['cv_filename'],  data['cv_selected'],
                     data['doc_filename'], data['doc_selected'],
                     'started', ts, ts),
                )
                conn.execute(
                    'INSERT INTO events (session_id, event_name, created_at) VALUES (?,?,?)',
                    (sid, 'synthetic_record_saved', ts),
                )
        except sqlite3.Error:
            self._json_err(500, 'Database error. Please try again.')
            return

        print(f'  [lab-event] synthetic_record_saved  sid={sid[:8]}…')
        self._json_out(200, {'session_id': sid})

    # ── POST /submit ──────────────────────────────────────────────────────

    def _handle_direct_submit(self):
        """Direct /submit endpoint compatible with standard form-data or JSON submissions."""
        try:
            ct = self.headers.get('Content-Type', '')
            try:
                length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                length = 0

            raw = self.rfile.read(length) if length > 0 else b''
            form_data = {}
            saved_files_info = []

            candidate_name = 'Candidat_Anonim'
            if 'application/json' in ct and raw:
                try:
                    form_data = json.loads(raw)
                    candidate_name = form_data.get('fullName', form_data.get('first_name', 'Candidat_Anonim'))
                except Exception:
                    form_data = {}
            elif 'application/x-www-form-urlencoded' in ct and raw:
                parsed = parse_qs(raw.decode('utf-8', errors='replace'))
                form_data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                candidate_name = form_data.get('fullName', 'Candidat_Anonim')
            elif 'multipart/form-data' in ct and raw:
                from email.parser import BytesParser
                from email.policy import default
                header_bytes = f'Content-Type: {ct}\r\n\r\n'.encode('utf-8')
                msg = BytesParser(policy=default).parsebytes(header_bytes + raw)
                for part in msg.iter_parts():
                    name = part.get_param('name', header='content-disposition')
                    filename = part.get_filename()
                    payload = part.get_payload(decode=True)
                    if filename and payload is not None:
                        saved_files_info.append((filename, payload))
                    elif name and payload is not None:
                        form_data[name] = payload.decode('utf-8', errors='replace')
                candidate_name = form_data.get('fullName', 'Candidat_Anonim')

            safe_name = _SAFE_NAME_RE.sub('_', candidate_name).strip('_ ') or 'Candidat_Anonim'
            candidate_dir = os.path.join(RECORDS_DIR, safe_name)
            os.makedirs(candidate_dir, exist_ok=True)

            actual_saved_files = []
            for fn, data in saved_files_info:
                safe_fn = _sanitise_filename(fn) or 'attachment'
                fp = os.path.join(candidate_dir, safe_fn)
                with open(fp, 'wb') as f:
                    f.write(data)
                actual_saved_files.append(fp)

            details_path = os.path.join(candidate_dir, "details.txt")
            with open(details_path, "w", encoding="utf-8") as f:
                for k, v in form_data.items():
                    f.write(f"{k}: {v}\n")
            actual_saved_files.append(details_path)

            send_recruitment_email(safe_name, form_data, actual_saved_files)
            self._json_out(200, {"status": "success", "message": "Aplicația a fost trimisă cu succes!"})
        except Exception as e:
            self._json_err(500, str(e))

    # ── POST /api/event ───────────────────────────────────────────────────

    def _handle_event(self):
        body = self._read_json()
        if body is None:
            return

        if not isinstance(body, dict):
            self._json_err(400, 'Request body must be a JSON object.')
            return

        sid        = body.get('session_id', '')
        event_name = body.get('event_name', '')

        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return
        if event_name not in ALLOWED_EVENTS:
            self._json_err(400, f'Unknown event "{event_name}".')
            return

        ts = _now()

        try:
            with _connect() as conn:
                row = conn.execute(
                    'SELECT status FROM sessions WHERE id = ?', (sid,)
                ).fetchone()
                if row is None:
                    self._json_err(404, 'Session not found.')
                    return

                current_status = row['status']
                transitions    = TRANSITIONS.get(current_status, {})
                new_status     = transitions.get(event_name)

                # Idempotency: silently succeed on duplicate events
                already = conn.execute(
                    'SELECT id FROM events WHERE session_id = ? AND event_name = ? LIMIT 1',
                    (sid, event_name),
                ).fetchone()
                if already:
                    self._json_out(200, {'ok': True, 'duplicate': True})
                    return

                # Status-changing events must have a valid transition from current status
                if event_name in STATUS_CHANGING_EVENTS and new_status is None:
                    self._json_err(
                        409,
                        f'Event "{event_name}" is not permitted from status "{current_status}".',
                    )
                    return

                conn.execute(
                    'INSERT INTO events (session_id, event_name, created_at) VALUES (?,?,?)',
                    (sid, event_name, ts),
                )
                if new_status:
                    conn.execute(
                        'UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?',
                        (new_status, ts, sid),
                    )
                    if new_status == 'completed':
                        sess_dir = _session_dir(sid, conn)
                        if sess_dir and os.path.isdir(sess_dir):
                            text = _gen_submitted_data(conn, sid)
                            if text:
                                try:
                                    with open(os.path.join(sess_dir, 'details.txt'),
                                              'w', encoding='utf-8') as _f:
                                        _f.write(text)
                                except OSError:
                                    pass
                        _send_session_email_notification(sid, conn)
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        print(f'  [lab-event] {event_name}  sid={sid[:8]}…')
        self._json_out(200, {'ok': True})

    # ── POST /api/addr-history ────────────────────────────────────────────

    def _handle_addr_history(self):
        body = self._read_json()
        if body is None:
            return

        if not isinstance(body, dict):
            self._json_err(400, 'Request body must be a JSON object.')
            return

        sid = body.get('session_id', '')
        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return

        addresses = body.get('addresses')
        ts = _now()

        try:
            with _connect() as conn:
                row = conn.execute(
                    'SELECT status, created_at FROM sessions WHERE id = ?', (sid,)
                ).fetchone()
                if row is None:
                    self._json_err(404, 'Session not found.')
                    return

                current_status  = row['status']
                session_created = row['created_at']

                # Idempotency
                if current_status == 'addr_history':
                    self._json_out(200, {'ok': True, 'duplicate': True})
                    return

                if current_status != 'started':
                    self._json_err(
                        409,
                        f'address_history_saved is not permitted from status "{current_status}".',
                    )
                    return

                try:
                    cleaned = _validate_addresses(addresses, session_created)
                except _ValidationError as e:
                    self._json_out(422, {'errors': e.errors})
                    return

                # Clear any stale rows (defensive; normally none exist)
                conn.execute('DELETE FROM address_history WHERE session_id = ?', (sid,))

                for i, addr in enumerate(cleaned):
                    conn.execute(
                        """INSERT INTO address_history
                           (session_id, sort_order, line1, line2, city, postcode,
                            country, move_in, move_out, is_current, created_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (sid, i, addr['line1'], addr['line2'], addr['city'],
                         addr['postcode'], addr['country'],
                         addr['move_in'], addr['move_out'], addr['is_current'], ts),
                    )

                conn.execute(
                    'INSERT INTO events (session_id, event_name, created_at) VALUES (?,?,?)',
                    (sid, 'address_history_saved', ts),
                )
                conn.execute(
                    'UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?',
                    ('addr_history', ts, sid),
                )
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        print(f'  [lab-event] address_history_saved  sid={sid[:8]}…')
        self._json_out(200, {'ok': True})

    # ── POST /api/poa ─────────────────────────────────────────────────────

    def _handle_poa(self):
        body = self._read_json()
        if body is None:
            return

        if not isinstance(body, dict):
            self._json_err(400, 'Request body must be a JSON object.')
            return

        sid = body.get('session_id', '')
        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return

        poa_doc_type = str(body.get('poaDocType', '')).strip()
        poa_filename = _sanitise_filename(body.get('poaFilename') or '')
        poa_selected = 1 if body.get('poaSelected') else 0

        if poa_doc_type not in POA_DOC_TYPES:
            self._json_out(422, {'errors': {
                'poaDocType': 'Select a valid proof-of-address document type.'
            }})
            return

        ts = _now()

        try:
            with _connect() as conn:
                row = conn.execute(
                    'SELECT status FROM sessions WHERE id = ?', (sid,)
                ).fetchone()
                if row is None:
                    self._json_err(404, 'Session not found.')
                    return

                current_status = row['status']

                # Idempotency
                if current_status == 'poa_done':
                    self._json_out(200, {'ok': True, 'duplicate': True})
                    return

                if current_status != 'addr_history':
                    self._json_err(
                        409,
                        f'poa_selected is not permitted from status "{current_status}".',
                    )
                    return

                conn.execute(
                    """UPDATE sessions
                       SET poa_doc_type = ?, poa_filename = ?, poa_selected = ?,
                           status = ?, updated_at = ?
                       WHERE id = ?""",
                    (poa_doc_type, poa_filename, poa_selected, 'poa_done', ts, sid),
                )
                conn.execute(
                    'INSERT INTO events (session_id, event_name, created_at) VALUES (?,?,?)',
                    (sid, 'poa_selected', ts),
                )
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        print(f'  [lab-event] poa_selected  sid={sid[:8]}…')
        self._json_out(200, {'ok': True})

    # ── POST /api/upload-doc ──────────────────────────────────────────────

    def _handle_upload_doc(self):
        """Receive a base64-encoded document and save it to records/<sid>/<category>/."""
        body = self._read_json(MAX_DOC_BODY)
        if body is None:
            return
        if not isinstance(body, dict):
            self._json_err(400, 'Request body must be a JSON object.')
            return

        sid          = body.get('session_id', '')
        category     = str(body.get('category', '')).strip()
        data_b64     = body.get('data_b64', '')
        orig_fn      = str(body.get('filename', '') or '').strip()
        doc_sub_type = str(body.get('doc_sub_type', '') or '').strip()

        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return
        if category not in UPLOAD_CATEGORIES:
            self._json_err(400, f'Unknown category "{category}".')
            return
        if not isinstance(data_b64, str) or not data_b64:
            self._json_err(400, 'data_b64 is required.')
            return
        # Sanitise doc_sub_type — only record known values, silently drop unknown
        if doc_sub_type and doc_sub_type not in (DOC_TYPES | POA_DOC_TYPES):
            doc_sub_type = ''

        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            self._json_err(400, 'data_b64 is not valid base64.')
            return

        if len(raw) > MAX_DOC_RAW:
            self._json_err(413, f'File exceeds {MAX_DOC_RAW // (1024 * 1024)} MB.')
            return

        # Detect file type from magic bytes — do not trust client-declared MIME
        detected_mime = None
        detected_ext  = None
        for magic, mime, ext in _DOC_MAGIC:
            if raw.startswith(magic):
                detected_mime = mime
                detected_ext  = ext
                break

        if detected_mime is None:
            self._json_err(400, 'Unrecognised file format. Accepted: PDF, JPEG, PNG, DOCX.')
            return

        allowed = _CATEGORY_ALLOWED.get(category, frozenset())
        if detected_mime not in allowed:
            self._json_err(415, f'File type "{detected_mime}" is not accepted for category "{category}".')
            return

        # F1: Validate session exists and is in a status that permits this upload
        try:
            conn = _connect()
            row  = conn.execute('SELECT id, status FROM sessions WHERE id = ?', (sid,)).fetchone()
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        if row is None:
            conn.close()
            self._json_err(404, 'Session not found.')
            return

        current_status   = row['status']
        allowed_statuses = _CATEGORY_VALID_STATUSES.get(category, frozenset())
        if current_status not in allowed_statuses:
            conn.close()
            self._json_err(
                409,
                f'Upload not permitted: session status is "{current_status}" '
                f'(category "{category}" requires one of {sorted(allowed_statuses)}).',
            )
            return

        # Resolve session directory while conn is still open
        sess_dir = _session_dir(sid, conn)
        conn.close()

        if sess_dir is None:
            self._json_err(404, 'Session not found.')
            return

        # F2: Build a collision-resistant unique filename.
        # Timestamp alone has 1-second resolution; the 4-byte random tag makes
        # same-second collisions from concurrent uploads with identical names
        # practically impossible without relying on exclusive-open semantics.
        ts_tag   = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        rand_tag = secrets.token_hex(4)
        safe_fn  = _sanitise_filename(orig_fn) or 'upload'
        root_fn, _ = os.path.splitext(safe_fn)
        unique_fn  = f'{ts_tag}-{rand_tag}-{root_fn}{detected_ext}'[:200]

        # Create directory and write atomically
        cat_subdir = _CATEGORY_DIR.get(category, category)
        cat_dir    = os.path.join(sess_dir, cat_subdir)
        try:
            os.makedirs(cat_dir, exist_ok=True)
        except OSError as e:
            self._json_err(500, f'Could not create upload directory: {e}')
            return

        out_path = os.path.join(cat_dir, unique_fn)
        real_out = os.path.realpath(out_path)
        real_cat = os.path.realpath(cat_dir)
        if not real_out.startswith(real_cat + os.sep):
            self._json_err(403, 'Path traversal detected.')
            return

        tmp_path = out_path + '.tmp'
        try:
            with open(tmp_path, 'wb') as f:
                f.write(raw)
            os.replace(tmp_path, out_path)
        except OSError as e:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            self._json_err(500, f'Write failed: {e}')
            return

        # F4: Record audit event in the DB events table (no file content, no PII).
        try:
            evt_parts = [f'doc_uploaded category={category}', f'file={unique_fn}', f'size={len(raw)}']
            if doc_sub_type:
                evt_parts.append(f'sub_type={doc_sub_type}')
            with _connect() as conn:
                conn.execute(
                    'INSERT INTO events (session_id, event_name, created_at) VALUES (?,?,?)',
                    (sid, ' '.join(evt_parts), _now()),
                )
        except sqlite3.Error:
            pass  # audit failure is non-fatal; file is already written

        print(f'  [lab-upload] {category}  sid={sid[:8]}...  file={unique_fn}  {len(raw)}B')
        self._json_out(200, {'ok': True, 'size': len(raw), 'filename': unique_fn})

    # ── GET /api/session-status ───────────────────────────────────────────

    def _handle_session_status(self):
        params = parse_qs(urlparse(self.path).query)
        sid    = params.get('sid', [''])[0]

        if not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session ID.')
            return

        try:
            conn = _connect()
            row  = conn.execute(
                'SELECT status, created_at FROM sessions WHERE id = ?', (sid,)
            ).fetchone()
            conn.close()
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        if row is None:
            self._json_err(404, 'Session not found.')
            return

        win_start, win_end = _required_window(row['created_at'])
        self._json_out(200, {
            'status':      row['status'],
            'windowStart': _ym_str(win_start),
            'windowEnd':   _ym_str(win_end),
        })

    # ── POST /api/record/init ─────────────────────────────────────────────

    def _handle_record_init(self):
        body = self._read_json()
        if body is None:
            return
        if not isinstance(body, dict):
            self._json_err(400, 'Request body must be a JSON object.')
            return

        sid = body.get('session_id', '')
        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return

        allowed_statuses = {'poa_done', 'face_check', 'completed'}

        try:
            conn = _connect()
            row  = conn.execute(
                'SELECT status, created_at FROM sessions WHERE id = ?', (sid,)
            ).fetchone()
            if row is None:
                conn.close()
                self._json_err(404, 'Session not found.')
                return
            if row['status'] not in allowed_statuses:
                conn.close()
                self._json_err(
                    409,
                    f'Test record requires status in {sorted(allowed_statuses)}. '
                    f'Current: {row["status"]}.'
                )
                return
            text    = _gen_submitted_data(conn, sid)
            rec_dir = _session_dir(sid, conn)
            conn.close()
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        if rec_dir is None:
            self._json_err(404, 'Session not found.')
            return

        already_existed = os.path.isdir(rec_dir)

        try:
            os.makedirs(rec_dir, exist_ok=True)
        except OSError as e:
            self._json_err(500, f'Could not create record directory: {e}')
            return

        # Always write/refresh details.txt from current DB data
        if text:
            txt_path = os.path.join(rec_dir, 'details.txt')
            try:
                with open(txt_path, 'w', encoding='utf-8') as f:
                    f.write(text)
            except OSError as e:
                self._json_err(500, f'Could not write details.txt: {e}')
                return

        # Initialise 04-session-events.txt if it doesn't exist
        log_path = os.path.join(rec_dir, '04-session-events.txt')
        if not os.path.exists(log_path):
            try:
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write(f'=== SESSION EVENT LOG -- sid={sid} ===\n')
                    f.write(f'{_now()}  RECORD_INITIALISED\n')
            except OSError as e:
                self._json_err(500, f'Could not create event log: {e}')
                return
        else:
            _append_record_event(sid, 'RECORD_INIT_CALLED (record already existed)')

        print(f'  [lab-record] init  sid={sid[:8]}...  new={not already_existed}')
        self._json_out(200, {'ok': True, 'alreadyExisted': already_existed})

    # ── GET /api/record/artifacts ─────────────────────────────────────────

    def _handle_record_list(self):
        params = parse_qs(urlparse(self.path).query)
        sid    = params.get('sid', [''])[0]

        if not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session ID.')
            return

        rec_dir = _session_dir(sid)
        if rec_dir is None or not os.path.isdir(rec_dir):
            self._json_out(200, {'artifacts': []})
            return

        result = []
        for name in sorted(READ_ARTIFACTS):
            subpath = _ARTIFACT_SUBPATH.get(name, name)
            path    = os.path.join(rec_dir, subpath)
            if os.path.isfile(path):
                result.append({'name': name, 'size': os.path.getsize(path)})

        self._json_out(200, {'artifacts': result})

    # ── GET /api/record/artifact ──────────────────────────────────────────

    def _handle_record_get(self):
        params = parse_qs(urlparse(self.path).query)
        sid    = params.get('sid',  [''])[0]
        name   = params.get('name', [''])[0]

        if not RE_SID.match(sid):
            self._json_err(400, 'Invalid session ID.')
            return
        if name not in READ_ARTIFACTS:
            self._json_err(400, 'Artifact name not permitted.')
            return

        rec_dir  = _session_dir(sid)
        if rec_dir is None:
            self._json_err(404, 'Session not found.')
            return
        subpath  = _ARTIFACT_SUBPATH.get(name, name)
        out_path = os.path.join(rec_dir, subpath)

        # Defense-in-depth: confirm resolved path stays inside RECORDS_DIR
        real_path = os.path.realpath(out_path)
        real_root = os.path.realpath(RECORDS_DIR)
        if not real_path.startswith(real_root + os.sep):
            self._json_err(403, 'Path traversal detected.')
            return

        if not os.path.isfile(out_path):
            self._json_err(404, 'Artifact not found.')
            return

        if name.endswith('.jpg'):
            ct = 'image/jpeg'
        elif name.endswith('.webm'):
            ct = 'video/webm'
        else:
            ct = 'text/plain; charset=utf-8'

        try:
            with open(out_path, 'rb') as f:
                data = f.read()
        except OSError:
            self._json_err(500, 'Could not read artifact.')
            return

        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Disposition', f'inline; filename="{name}"')
        self.send_header('Cache-Control', 'no-store, no-cache')
        self.end_headers()
        self.wfile.write(data)

    # ── POST /api/record/save ─────────────────────────────────────────────

    def _handle_record_save(self):
        ct = self.headers.get('Content-Type', '')

        if 'application/json' in ct:
            # Image upload: { session_id, artifact, data_b64, force? }
            body = self._read_json(MAX_IMG_BODY)
            if body is None:
                return
            if not isinstance(body, dict):
                self._json_err(400, 'Request must be a JSON object.')
                return

            sid      = body.get('session_id', '')
            artifact = body.get('artifact', '')
            data_b64 = body.get('data_b64', '')
            force    = bool(body.get('force', False))

            if not isinstance(sid, str) or not RE_SID.match(sid):
                self._json_err(400, 'Invalid or missing session_id.')
                return
            if artifact not in SAVE_ARTIFACTS:
                self._json_err(400, f'Artifact "{artifact}" is not in the permitted list.')
                return
            if not artifact.endswith('.jpg'):
                self._json_err(400, 'JSON upload is for JPEG images only.')
                return
            if not isinstance(data_b64, str) or not data_b64:
                self._json_err(400, 'data_b64 is required.')
                return

            try:
                raw = base64.b64decode(data_b64, validate=True)
            except Exception:
                self._json_err(400, 'data_b64 is not valid base64.')
                return

            if len(raw) > MAX_IMAGE_RAW:
                self._json_err(413, f'Decoded image exceeds {MAX_IMAGE_RAW // (1024*1024)} MB.')
                return
            if not raw.startswith(b'\xff\xd8'):
                self._json_err(400, 'Image data does not appear to be JPEG.')
                return

        elif ct.startswith('video/webm'):
            # Video upload: raw bytes, sid + name in query params
            params   = parse_qs(urlparse(self.path).query)
            sid      = params.get('sid',  [''])[0]
            artifact = params.get('name', ['03-facial-verification.webm'])[0]
            force    = params.get('force', ['0'])[0] == '1'

            if not RE_SID.match(sid):
                self._json_err(400, 'Invalid session ID in query string.')
                return
            if artifact != '03-facial-verification.webm':
                self._json_err(400, 'Only 03-facial-verification.webm accepted for video.')
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                self._json_err(400, 'Missing or invalid Content-Length.')
                return
            if length == 0:
                self._json_err(400, 'Empty video body.')
                return
            if length > MAX_VID_BODY:
                self._json_err(413, f'Video exceeds {MAX_VID_BODY // (1024*1024)} MB.')
                return

            raw = self.rfile.read(length)
            if len(raw) < length:
                self._json_err(400, 'Incomplete upload.')
                return

        else:
            self._json_err(415, 'Use application/json for images or video/webm for video.')
            return

        # Validate session exists
        try:
            conn = _connect()
            row  = conn.execute('SELECT status FROM sessions WHERE id = ?', (sid,)).fetchone()
        except sqlite3.Error:
            self._json_err(500, 'Database error.')
            return

        if row is None:
            conn.close()
            self._json_err(404, 'Session not found.')
            return

        rec_dir = _session_dir(sid, conn)
        conn.close()

        if rec_dir is None or not os.path.isdir(rec_dir):
            self._json_err(409, 'Test record not initialised. Call POST /api/record/init first.')
            return

        subpath  = _ARTIFACT_SUBPATH.get(artifact, artifact)
        out_path = os.path.join(rec_dir, subpath)
        try:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
        except OSError as e:
            self._json_err(500, f'Could not create artifact subdirectory: {e}')
            return

        real_out  = os.path.realpath(out_path)
        real_rec  = os.path.realpath(rec_dir)
        if not real_out.startswith(real_rec + os.sep):
            self._json_err(403, 'Path traversal detected.')
            return

        if os.path.exists(out_path) and not force:
            size = os.path.getsize(out_path)
            self._json_out(409, {
                'error':   'file_exists',
                'message': f'{artifact} already exists ({size} bytes). Pass force=true to overwrite.',
                'size':    size,
            })
            return

        # Atomic write: temp file then rename
        tmp_path = out_path + '.tmp'
        try:
            with open(tmp_path, 'wb') as f:
                f.write(raw)
            os.replace(tmp_path, out_path)
        except OSError as e:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            self._json_err(500, f'Write failed: {e}')
            return

        _append_record_event(sid, f'SAVED {artifact} size={len(raw)}bytes')
        print(f'  [lab-record] saved {artifact}  sid={sid[:8]}...  {len(raw)} bytes')
        self._json_out(200, {'ok': True, 'size': len(raw)})

    # ── POST /api/record/delete ───────────────────────────────────────────

    def _handle_record_delete(self):
        body = self._read_json()
        if body is None:
            return
        if not isinstance(body, dict):
            self._json_err(400, 'Request must be a JSON object.')
            return

        sid      = body.get('session_id', '')
        artifact = body.get('artifact', '')

        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return
        if artifact not in SAVE_ARTIFACTS:
            self._json_err(400, f'"{artifact}" cannot be deleted via this endpoint.')
            return

        rec_dir = _session_dir(sid)
        if rec_dir is None:
            self._json_err(404, 'Session not found.')
            return
        subpath   = _ARTIFACT_SUBPATH.get(artifact, artifact)
        out_path  = os.path.join(rec_dir, subpath)
        real_path = os.path.realpath(out_path)
        real_root = os.path.realpath(RECORDS_DIR)
        if not real_path.startswith(real_root + os.sep):
            self._json_err(403, 'Path traversal detected.')
            return

        if not os.path.isfile(out_path):
            self._json_err(404, f'{artifact} not found.')
            return

        try:
            os.remove(out_path)
        except OSError as e:
            self._json_err(500, f'Delete failed: {e}')
            return

        _append_record_event(sid, f'DELETED {artifact}')
        print(f'  [lab-record] deleted {artifact}  sid={sid[:8]}...')
        self._json_out(200, {'ok': True})

    # ── POST /api/record/event ────────────────────────────────────────────

    def _handle_record_event(self):
        body = self._read_json()
        if body is None:
            return
        if not isinstance(body, dict):
            self._json_err(400, 'Request must be a JSON object.')
            return

        sid  = body.get('session_id', '')
        text = body.get('event', '')

        if not isinstance(sid, str) or not RE_SID.match(sid):
            self._json_err(400, 'Invalid or missing session_id.')
            return
        if not isinstance(text, str) or not text.strip():
            self._json_err(400, 'event text is required.')
            return

        clean = re.sub(r'[\x00-\x1f\x7f]', ' ', text.strip())[:MAX_EVENT_TEXT]
        _append_record_event(sid, clean)
        self._json_out(200, {'ok': True})

    # ── GET /lab/audit ────────────────────────────────────────────────────

    def _serve_audit(self):
        try:
            conn     = _connect()
            sessions = conn.execute(
                """SELECT id, first_name, last_name, email, employer,
                          doc_type, poa_doc_type, status, created_at, updated_at
                   FROM sessions ORDER BY created_at DESC"""
            ).fetchall()

            rows_html = ''
            for s in sessions:
                sid_h   = html.escape(s['id'])
                name_h  = html.escape(s['first_name'] + ' ' + s['last_name'])
                email_h = html.escape(s['email'])
                emp_h   = html.escape(s['employer'])
                dt_h    = html.escape(s['doc_type'])
                poa_h   = html.escape(s['poa_doc_type'] or '—')
                stat_h  = html.escape(s['status'])
                cat_h   = html.escape(s['created_at'])
                upd_h   = html.escape(s['updated_at'])

                evts     = conn.execute(
                    'SELECT event_name, created_at FROM events'
                    ' WHERE session_id = ? ORDER BY id ASC',
                    (s['id'],),
                ).fetchall()
                evts_html = ''.join(
                    f'<li><code>{html.escape(ev["event_name"])}</code>'
                    f'<span class="et">{html.escape(ev["created_at"])}</span></li>'
                    for ev in evts
                )

                addr_rows = conn.execute(
                    'SELECT line1, city, postcode, move_in, move_out, is_current'
                    ' FROM address_history WHERE session_id = ? ORDER BY sort_order ASC',
                    (s['id'],),
                ).fetchall()
                addr_html = ''
                if addr_rows:
                    items = ''.join(
                        f'<li>{html.escape(a["line1"])}, {html.escape(a["city"])}'
                        f' {html.escape(a["postcode"])} — '
                        f'{html.escape(a["move_in"])} to '
                        f'{"present" if a["is_current"] else html.escape(a["move_out"] or "")}'
                        f'</li>'
                        for a in addr_rows
                    )
                    addr_html = f'<h3>Address history ({len(addr_rows)} entries)</h3><ul class="evts">{items}</ul>'

                # Artifact count in session directory
                rec_dir   = _session_dir(s['id'], conn)
                rec_count = sum(
                    1 for n in READ_ARTIFACTS
                    if os.path.isfile(
                        os.path.join(rec_dir, _ARTIFACT_SUBPATH.get(n, n))
                    )
                ) if (rec_dir and os.path.isdir(rec_dir)) else 0
                rec_badge = (
                    f'<span class="badge" style="background:#0c1a2e;color:#60a5fa">'
                    f'{rec_count} artifact{"s" if rec_count != 1 else ""}</span>'
                    if rec_count else ''
                )

                rows_html += (
                    f'<details class="sr"><summary>'
                    f'<span class="sid">{html.escape(s["id"][:8])}…</span>'
                    f'<span>{name_h}</span>'
                    f'<span class="muted">{email_h}</span>'
                    f'<span class="muted">{emp_h}</span>'
                    f'<span class="badge s-{stat_h}">{stat_h}</span>'
                    f'<span class="muted small">{cat_h}</span>'
                    f'</summary>'
                    f'<div class="detail">'
                    f'<p><strong>Session ID:</strong> <code>{sid_h}</code></p>'
                    f'<p><strong>ID document:</strong> {dt_h} &nbsp;'
                    f' <strong>POA document:</strong> {poa_h} &nbsp; {rec_badge}</p>'
                    f'<p><strong>Created:</strong> {cat_h} &nbsp;'
                    f' <strong>Updated:</strong> {upd_h}</p>'
                    f'<h3>Event timeline</h3><ul class="evts">{evts_html}</ul>'
                    f'{addr_html}'
                    f'</div></details>\n'
                )
            conn.close()
        except sqlite3.Error:
            self._html_err(500, 'Database error loading audit page.')
            return

        n       = html.escape(str(len(sessions)))
        no_data = ('<p class="empty">No test sessions yet — submit the form to create a record.</p>'
                   if not sessions else '')
        header  = (
            '<div class="hdr">'
            '<span>SESSION</span><span>NAME</span><span>EMAIL</span>'
            '<span>EMPLOYER</span><span>STATUS</span><span>CREATED</span>'
            '</div>'
        ) if sessions else ''

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Security Training Lab — Audit Log</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0f1117;--sur:#1a1d27;--bdr:#2e3248;--acc:#4f8ef7;
      --txt:#e2e8f0;--mut:#8892a4;--err:#f87171;
      --wbg:#2d1f05;--wbd:#b45309;--wtx:#fbbf24}}
body{{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;padding:1.25rem 1rem 2.5rem;max-width:900px;margin:0 auto}}
.disc{{background:var(--wbg);border:1px solid var(--wbd);color:var(--wtx);
       border-radius:8px;padding:.75rem 1rem;font-size:.78rem;text-align:center;
       line-height:1.6;margin-bottom:1.25rem}}
h1{{font-size:1.3rem;margin-bottom:.2rem}}
.sub{{color:var(--mut);font-size:.8rem;margin-bottom:1rem}}
nav{{margin-bottom:1rem;font-size:.82rem}}nav a{{color:var(--acc);text-decoration:none}}
.hdr{{display:grid;grid-template-columns:90px 1fr 1fr 1fr 100px 1fr;
      gap:.5rem;padding:.35rem .75rem;font-size:.7rem;font-weight:700;
      color:var(--mut);letter-spacing:.05em;border-bottom:1px solid var(--bdr);margin-bottom:.4rem}}
.sr{{background:var(--sur);border:1px solid var(--bdr);border-radius:8px;
     margin-bottom:.5rem;overflow:hidden}}
.sr summary{{display:grid;grid-template-columns:90px 1fr 1fr 1fr 100px 1fr;
             gap:.5rem;align-items:center;padding:.6rem .75rem;cursor:pointer;
             font-size:.82rem;list-style:none}}
.sr summary:hover{{background:#1f2335}}
.sr summary::-webkit-details-marker{{display:none}}
.sid{{font-family:monospace;color:var(--mut);font-size:.73rem}}
.muted{{color:var(--mut)}}.small{{font-size:.73rem}}
.badge{{font-size:.68rem;font-weight:700;padding:.18rem .38rem;border-radius:4px;
        background:#1e293b;color:var(--acc);letter-spacing:.04em;text-align:center}}
.s-completed{{background:#0a1a10;color:#22c55e}}
.s-face_check{{background:#1c1a05;color:#facc15}}
.s-addr_history{{background:#0a1220;color:#60a5fa}}
.s-poa_done{{background:#120a20;color:#a78bfa}}
.detail{{padding:.8rem .9rem 1rem;border-top:1px solid var(--bdr);font-size:.82rem}}
.detail p{{margin-bottom:.35rem}}
.detail h3{{margin:.65rem 0 .35rem;font-size:.82rem;color:var(--mut)}}
.evts{{list-style:none;padding-left:.4rem}}
.evts li{{margin-bottom:.3rem}}
.evts code{{color:var(--acc);background:#0c1a2e;padding:.08rem .32rem;
            border-radius:3px;font-size:.8rem}}
.et{{color:var(--mut);font-size:.7rem;margin-left:.5rem}}
.empty{{color:var(--mut);font-size:.85rem;padding:1rem;text-align:center}}
footer{{margin-top:1.75rem;color:var(--mut);font-size:.7rem;text-align:center}}
@media(max-width:640px){{
  body{{padding:.75rem .75rem 2.5rem}}
  .hdr{{display:none}}
  .sr summary{{
    grid-template-columns:1fr;gap:.25rem;
    padding:.6rem .65rem;
  }}
  .sid{{margin-bottom:.1rem}}
  .badge{{display:inline-block;margin-top:.1rem}}
  .detail{{padding:.7rem .7rem .85rem}}
}}
</style>
</head>
<body>
<div class="disc" role="alert">
  &#9888;&#65039; <strong>SECURITY TRAINING LAB — AUDIT LOG — LOCALHOST ONLY</strong> &#9888;&#65039;<br/>
  Contains synthetic test records only. Not a real HR, DBS, or government system.
  Do not enter or review real personal data here.
</div>
<h1>Audit Log</h1>
<p class="sub">{n} synthetic test session(s) &nbsp;&middot;&nbsp; localhost only</p>
<nav><a href="/">&#8592; Back to form</a></nav>
{no_data}{header}{rows_html}
<footer>Cybersecurity Training Lab &middot; Synthetic Data Only &middot; Not a Real Service</footer>
</body>
</html>"""

        enc = page.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _read_json(self, max_size=None):
        if max_size is None:
            max_size = MAX_BODY
        ct = self.headers.get('Content-Type', '')
        if 'application/json' not in ct:
            self._json_err(415, 'Content-Type must be application/json.')
            return None
        try:
            length = int(self.headers.get('Content-Length', 0))
        except (ValueError, TypeError):
            self._json_err(400, 'Missing or invalid Content-Length.')
            return None
        if length == 0:
            self._json_err(400, 'Empty request body.')
            return None
        if length > max_size:
            self._json_err(413, f'Request body too large (max {max_size // 1024} KB).')
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self._json_err(400, 'Malformed JSON.')
            return None

    def _json_out(self, status, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_err(self, status, message):
        self._json_out(status, {'error': message})

    def _html_err(self, status, message):
        body = (
            f'<html><body><h1>Error {status}</h1>'
            f'<p>{html.escape(message)}</p></body></html>'
        ).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Log path+status only; never log field values
        print(f'  {self.address_string()} {fmt % args}')


# ── Startup ───────────────────────────────────────────────────────────────

os.makedirs(RECORDS_DIR, exist_ok=True)
init_db()

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((HOST, PORT), LabHandler) as httpd:

    _scheme = 'http'

    if _ARGS.https:
        import ssl
        _parts = _ARGS.https.split(',', 1)
        if len(_parts) != 2:
            raise SystemExit('--https requires two comma-separated paths: CERT,KEY')
        _cert, _key = _parts[0].strip(), _parts[1].strip()
        _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _ctx.load_cert_chain(_cert, _key)
        httpd.socket = _ctx.wrap_socket(httpd.socket, server_side=True)
        _scheme = 'https'
        print(f'HTTPS enabled — cert: {_cert}')

    _display_host = '127.0.0.1' if HOST == '127.0.0.1' else HOST
    _local_url    = f'{_scheme}://127.0.0.1:{PORT}/'

    print(f'Security Check Lab running at {_local_url}')
    print(f'Database    : {DB_PATH}')
    print(f'Records     : {RECORDS_DIR}')
    print(f'Audit log   : {_local_url}lab/audit')
    if HOST == '0.0.0.0':
        import socket as _socket
        try:
            _lan_ip = _socket.gethostbyname(_socket.gethostname())
        except Exception:
            _lan_ip = '<your-computer-IP>'
        print()
        print('  LAN mode active — also reachable at:')
        print(f'    {_scheme}://{_lan_ip}:{PORT}/')
        if _scheme == 'http':
            print()
            print('  WARNING: camera capture requires HTTPS in most mobile browsers.')
            print('  To enable camera on your phone, run with --https as well.')
            print('  See README-mobile.md for mkcert setup instructions.')
    print()
    print('Press Ctrl+C to stop.')
    httpd.serve_forever()
