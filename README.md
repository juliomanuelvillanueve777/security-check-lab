# Security Check & DBS Background Verification Lab

Web application for candidate onboarding, identity verification, 5-year address history, and facial biometric verification.

## Features
- Candidate personal details, employment eligibility (RTW share code), and document upload (Passport, Driving License, National ID Card).
- 5-year address history validation and Proof of Address (POA) upload.
- Biometric facial capture and verification.
- Auto-save form progress across sessions and page navigation.
- Standalone Python web server using standard library only (`http.server`, `sqlite3`).

## Local Development
Run the server:
```bash
python serve.py
```
Open `http://127.0.0.1:8080` in your web browser.

## Deployment on Render
1. Create a new **Web Service** on [Render](https://dashboard.render.com).
2. Connect this GitHub repository.
3. Configure the service settings:
   - **Runtime**: `Python 3`
   - **Build Command**: *(leave blank or empty)*
   - **Start Command**: `python serve.py`
4. Deploy! Render automatically sets the `PORT` environment variable and provides free SSL/HTTPS, enabling camera capture for facial verification.
