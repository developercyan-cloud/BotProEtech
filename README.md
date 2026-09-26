# Telegram Account Setup Assistant

A Telegram bot + Telegram Mini App for collecting registration information for Uber, DoorDash and Lyft.

## Important

This project does NOT automate CAPTCHA, identity verification, passwords, OTP codes, or other security controls. The final registration/verification step is completed through the platform's official process.

## Files

- `app.py` — Flask API + Telegram bot
- `templates/index.html` — Telegram Mini App UI
- `requirements.txt` — Python dependencies
- `Procfile` — Railway start command

## Environment variables

Required:

TELEGRAM_BOT_TOKEN=your_bot_token
WEBAPP_URL=https://your-public-domain.example

Optional:

ADMIN_KEY=change-this-long-random-value
DB_PATH=data.db

## Local test

python -m venv .venv

Windows:
.venv\Scripts\activate

macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

set TELEGRAM_BOT_TOKEN=...
set WEBAPP_URL=https://your-https-domain.example

python app.py

The Mini App needs HTTPS when opened by Telegram.

## Railway

1. Push this project to GitHub.
2. Create a Railway project.
3. Deploy the GitHub repository.
4. Add `TELEGRAM_BOT_TOKEN`.
5. After Railway generates a domain, set `WEBAPP_URL` to that HTTPS URL.
6. Redeploy.
7. Open your bot in Telegram and send `/start`.

For production, replace SQLite with PostgreSQL so registration data is not dependent on the local service filesystem.
