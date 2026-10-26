import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, jsonify, render_template
from supabase import create_client, Client

app = Flask(__name__, static_folder='static', template_folder='.')

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'records')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL', 'louiep89@outlook.com')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.resend.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', 'resend')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("[OK] Conectat la Supabase.")
    except Exception as e:
        print(f"[EROARE] Conectare Supabase eșuată: {e}")

def save_to_supabase(form_data, saved_files):
    if supabase:
        try:
            payload = {
                "form_data": form_data,
                "files": [os.path.basename(f) for f in saved_files],
                "submitted_at": datetime.utcnow().isoformat()
            }
            res = supabase.table('candidates').insert({"data": payload}).execute()
            print("[OK] Candidat salvat cu succes în Supabase!")
        except Exception as e:
            print(f"[EROARE] Salvare în Supabase eșuată: {e}")

def send_recruitment_email(candidate_name, form_data, file_paths):
    try:
        msg = MIMEMultipart()
        msg['From'] = "onboarding@resend.dev"
        msg['To'] = NOTIFICATION_EMAIL
        msg['Subject'] = f"Aplicație Nouă - Candidat: {candidate_name}"

        body = f"A fost înregistrată o nouă aplicație prin platforma de recrutare.\n\n"
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

        if SMTP_PASSWORD:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(msg['From'], NOTIFICATION_EMAIL, msg.as_string())
            server.quit()
            print(f"[OK] E-mail trimis cu succes către {NOTIFICATION_EMAIL}")
        else:
            print("[EROARE] SMTP_PASSWORD nu este configurat.")
    except Exception as e:
        print(f"[EROARE] Trimitere e-mail eșuată: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_form():
    try:
        form_data = request.form.to_dict()
        candidate_name = form_data.get('fullName', 'Candidat_Anonim').replace(' ', '_')
        
        candidate_dir = os.path.join(UPLOAD_FOLDER, candidate_name)
        os.makedirs(candidate_dir, exist_ok=True)

        saved_files = []

        for key, file in request.files.items():
            if file and file.filename != '':
                file_path = os.path.join(candidate_dir, file.filename)
                file.save(file_path)
                saved_files.append(file_path)

        details_path = os.path.join(candidate_dir, "details.txt")
        with open(details_path, "w", encoding="utf-8") as f:
            for k, v in form_data.items():
                f.write(f"{k}: {v}\n")
        saved_files.append(details_path)

        # 1. Salvare Backup în Supabase
        save_to_supabase(form_data, saved_files)

        # 2. Trimitere E-mail
        send_recruitment_email(candidate_name, form_data, saved_files)

        return jsonify({"status": "success", "message": "Aplicația a fost trimisă cu succes!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
