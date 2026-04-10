# AI Web Attack Detection System

A full-stack Flask application with authentication, a protected dashboard, and a dummy AI prediction API for detecting suspicious web requests.

## Features

- User registration, login, and logout
- Password hashing with Werkzeug
- Session handling with Flask-Login
- Protected dashboard route
- SQLite database with Flask-SQLAlchemy
- `/predict` POST API returning JSON
- Modern dark-theme frontend with loading and error states
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

## How Authentication Works

- Passwords are never stored in plain text. They are hashed with Werkzeug before saving to SQLite.
- Flask-Login manages the user session after a successful login.
- Protected routes such as `/dashboard` and `/predict` require an authenticated user.
- If a non-authenticated user calls `/predict`, the API returns a JSON `401` response.

## Frontend and Backend Integration

- The dashboard uses `fetch()` in `static/js/dashboard.js` to send a POST request to `/predict`.
- The request body is JSON in the form `{ "request_text": "..." }`.
- Flask processes the input and returns JSON with `attack_type`, `confidence`, `status`, and `message`.
- The frontend renders loading, success, and error states dynamically without reloading the page.

## Deployment Notes

- Render start command: `gunicorn app:app`
- Railway start command: `gunicorn app:app`
- Vercel config is included in `vercel.json`
- Ensure `SECRET_KEY` is configured as an environment variable
- SQLite works best on Render or Railway with persistent disk storage. Vercel is suitable for demos, but local SQLite storage is ephemeral in serverless environments.
