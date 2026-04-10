# AI Web Attack Detection System

A Flask-based web application firewall demo that analyzes HTTP requests in real time, blocks hostile traffic, and gives developers a built-in vulnerability scan plus investigation dashboard.

## Features

- User registration, login, and logout
- Password hashing with Werkzeug
- Session handling with Flask-Login
- Real-time HTTP request inspection through Flask middleware
- Automatic blocking of hostile traffic with `403` responses
- Detection coverage for SQLi, XSS, CSRF, command injection, traversal, and reconnaissance patterns
- Persistent security event logging with severity, confidence, and response guidance
- Analyst dashboard for live traffic, blocked requests, and manual payload triage
- Developer vulnerability scan endpoint with remediation findings
- SQLite database with Flask-SQLAlchemy
- Modern frontend with loading, result, and scan states
- Deployment-ready for Render or Railway

## Project Structure

```text
.
|-- app.py
|-- models.py
|-- requirements.txt
|-- Procfile
|-- .env.example
|-- README.md
|-- app/
|   |-- __init__.py
|   |-- models.py
|   |-- predictor.py
|   `-- routes.py
|-- templates/
|   |-- base.html
|   |-- login.html
|   |-- register.html
|   `-- dashboard.html
`-- static/
    |-- css/
    |   `-- styles.css
    `-- js/
        `-- dashboard.js
```

## Local Setup

1. Create a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Set `SECRET_KEY` in your environment.
4. Run `python app.py`.
5. Open `http://127.0.0.1:5000`.

## How It Works

- Passwords are never stored in plain text. They are hashed with Werkzeug before saving to SQLite.
- Flask-Login manages the user session after a successful login.
- Protected routes such as `/dashboard`, `/predict`, `/traffic/ingest`, `/scan`, and `/events` require an authenticated user.
- Incoming monitored HTTP requests are analyzed before the route handler executes.
- If a request is classified as hostile, the middleware blocks it with a `403` response and records the event.
- The analyst console can still use `/predict` to safely test suspicious payloads without triggering live blocking.

## Key Endpoints

- `/predict` accepts analyst-submitted raw HTTP request text as JSON: `{ "request_text": "..." }`
- `/traffic/ingest` demonstrates a protected live endpoint that is screened by the real-time firewall
- `/scan` returns a vulnerability scan report for developers
- `/events` returns the latest recorded security events for the signed-in analyst

## Frontend and Backend Integration

- The dashboard uses `fetch()` in `static/js/dashboard.js` to send live traffic probes, manual payloads, and vulnerability scan requests.
- Flask processes the input and returns JSON with attack type, confidence, severity, blocking decision, and recommended remediation.
- The frontend renders loading, success, error, scan, and event-history states without reloading the page.

## Deployment Notes

- Render start command: `gunicorn app:app`
- Railway start command: `gunicorn app:app`
- Vercel config is included in `vercel.json`
- Ensure `SECRET_KEY` is configured as an environment variable
- SQLite works best on Render or Railway with persistent disk storage. Vercel is suitable for demos, but local SQLite storage is ephemeral in serverless environments.

## Deploy on Render

1. Push this project to GitHub.
2. In Render, click **New +** and choose **Web Service**.
3. Connect your GitHub repository.
4. Render should detect the included `render.yaml`, or you can configure the service manually.
5. Confirm these settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
6. Add a persistent disk if you want SQLite data to survive redeploys and restarts.
7. If you add a disk, set `RENDER_DISK_PATH` to the mount path you choose, such as `/var/data`.
8. Deploy the service and open the generated `.onrender.com` URL.
