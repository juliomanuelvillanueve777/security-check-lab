import os
import json
import base64
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, jsonify, render_template

try:
    import requests
except ImportError:
    requests = None
import urllib.request

app = Flask(__name__, static_folder='static', template_folder='.')

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'records')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Google Apps Script Web App Endpoint URL (Google Sheets & Google Drive)
GOOGLE_APPS_SCRIPT_URL = os.environ.get('GOOGLE_APPS_SCRIPT_URL', '')

# E-mail notification configuration (SMTP - optional)
NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL', 'louiep89@outlook.com')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.resend.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', 'resend')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

def forward_to_google_apps_script(gas_payload):
    """
    Trimite datele formularului și fișierele codificate în base64 către Web App-ul Google Apps Script
    pentru salvare în Google Sheets și Google Drive.
    """
    gas_url = GOOGLE_APPS_SCRIPT_URL.strip()
    if not gas_url:
        print("[INFO] GOOGLE_APPS_SCRIPT_URL nu este configurat. Salvarea în Google Sheets/Drive este omisă.")
        return {"status": "skipped", "message": "GOOGLE_APPS_SCRIPT_URL not configured"}

    print(f"[GAS] Se trimite aplicația către Google Apps Script Web App: {gas_url}")
    try:
        if requests is not None:
            resp = requests.post(gas_url, json=gas_payload, timeout=90, allow_redirects=True)
            print(f"[GAS] Răspuns primit (HTTP {resp.status_code}): {resp.text[:250]}")
            try:
                return resp.json()
            except Exception:
                return {"status": "success", "raw": resp.text}
        else:
            json_bytes = json.dumps(gas_payload).encode('utf-8')
            req = urllib.request.Request(
                gas_url,
                data=json_bytes,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=90) as response:
                res_text = response.read().decode('utf-8')
                print(f"[GAS] Răspuns primit via urllib: {res_text[:250]}")
                try:
                    return json.loads(res_text)
                except Exception:
                    return {"status": "success", "raw": res_text}
    except Exception as e:
        print(f"[EROARE GAS] Eroare la trimiterea către Google Apps Script: {e}")
        return {"status": "error", "message": str(e)}

def send_recruitment_email(candidate_name, form_data, file_paths):
    """
    Trimite o notificare prin e-mail echipei de recrutare cu detaliile candidatului și fișierele atașate.
    """
    try:
        if not SMTP_PASSWORD:
            print("[INFO] SMTP_PASSWORD nu este configurat. Notificarea prin e-mail a fost omisă.")
            return

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

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(msg['From'], NOTIFICATION_EMAIL, msg.as_string())
        server.quit()
        print(f"[OK] E-mail trimis cu succes către {NOTIFICATION_EMAIL}")
    except Exception as e:
        print(f"[EROARE] Trimitere e-mail eșuată: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
@app.route('/api/submit', methods=['POST'])
def submit_form():
    try:
        if request.is_json:
            form_data = request.get_json() or {}
        else:
            form_data = request.form.to_dict()

        full_name = form_data.get('fullName')
        if not full_name:
            first = form_data.get('firstName', form_data.get('first_name', ''))
            last = form_data.get('lastName', form_data.get('last_name', ''))
            full_name = f"{first} {last}".strip() or 'Candidat_Anonim'
        candidate_name = full_name.replace(' ', '_')
        
        candidate_dir = os.path.join(UPLOAD_FOLDER, candidate_name)
        os.makedirs(candidate_dir, exist_ok=True)

        saved_files = []
        files_payload = []

        for key, file in request.files.items():
            if file and file.filename != '':
                filename = file.filename
                file_bytes = file.read()

                # Salvare locală fișier în directorul candidatului
                file_path = os.path.join(candidate_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                saved_files.append(file_path)

                # Pregătire payload fișier codificat base64 pentru Google Apps Script
                b64_content = base64.b64encode(file_bytes).decode('utf-8')
                files_payload.append({
                    "field": key,
                    "filename": filename,
                    "mimeType": file.content_type or 'application/octet-stream',
                    "data": b64_content
                })

        # Salvare detalii în fișier text local
        details_path = os.path.join(candidate_dir, "details.txt")
        with open(details_path, "w", encoding="utf-8") as f:
            for k, v in form_data.items():
                f.write(f"{k}: {v}\n")
        saved_files.append(details_path)

        # 1. Trimitere date și fișiere către Google Apps Script (Google Sheets & Google Drive)
        gas_payload = {
            "action": "submit_application",
            "candidateName": full_name,
            "formData": form_data,
            "files": files_payload,
            "submittedAt": datetime.utcnow().isoformat() + 'Z'
        }
        gas_result = forward_to_google_apps_script(gas_payload)

        # 2. Notificare E-mail prin SMTP (Resend)
        send_recruitment_email(candidate_name, form_data, saved_files)

        return jsonify({
            "status": "success",
            "message": "Aplicația a fost trimisă cu succes!",
            "google_apps_script": gas_result
        }), 200
    except Exception as e:
        print(f"[EROARE SUBMIT] {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/validate-step', methods=['POST'])
def validate_step():
    return jsonify({"status": "success", "valid": True}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
