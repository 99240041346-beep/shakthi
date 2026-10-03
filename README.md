# CAMPUS SHAKTHI

Campus safety platform with Student, Admin and Security portals.

## Core emergency workflow
- Student submits SOS with GPS coordinates.
- Admin receives the SOS and location.
- Admin buzzer continues until Admin forwards the SOS to Security.
- Forwarding stops the Admin buzzer and sends the same SOS/location to Security.
- Security can take action and mark the SOS Problem Solved.
- Reports follow the same Admin -> Security -> Resolution workflow.

## Run locally
```bash
pip install -r requirements.txt
gunicorn app:app
```

Demo logins are documented in the project files. Change credentials and SECRET_KEY before real deployment.

## Render
Build: `pip install -r requirements.txt`
Start: `gunicorn app:app`
