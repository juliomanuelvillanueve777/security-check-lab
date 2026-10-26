import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, static_folder='static', template_folder='templates')

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'records')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL', 'louiep89@outlook.com')

SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.resend.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', 'resend')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

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
            print(f"[OK] E-mail trimis cu succes prin Resend către {NOTIFICATION_EMAIL}")
        else:
            print(f"[EROARE] SMTP_PASSWORD nu este setat.")
    except Exception as e:
        print(f"[EROARE] Trimiterea e-mailului a eșuat: {e}")

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

        send_recruitment_email(candidate_name, form_data, saved_files)

        return jsonify({"status": "success", "message": "Aplicația a fost trimisă cu succes!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
