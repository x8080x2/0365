# Outlook Login Automation - Educational Project

## ⚠️ Important Notice

This is an **educational group project** for academic purposes only. This application demonstrates web automation techniques using Selenium WebDriver for legitimate educational research on authentication flows.

## What This Project Does

This Flask-based application provides:

1. **Educational Web Interface**: A demonstration of how modern web applications handle user authentication
2. **Browser Automation Research**: Uses Selenium WebDriver to study Microsoft Outlook login processes
3. **Session Management**: Demonstrates secure session handling with Redis and Flask-Session
4. **Security Features**: Includes CSRF protection, rate limiting, and bot protection mechanisms

## Technical Features

- **Framework**: Flask with SQLAlchemy ORM
- **Authentication**: Custom user management with bcrypt password hashing
- **Session Storage**: Redis backend with filesystem fallback
- **Security**: Rate limiting, CSRF protection, Cloudflare Turnstile integration
- **Browser Automation**: Selenium WebDriver for research purposes
- **Notifications**: Telegram integration for project notifications

## Educational Purpose

This project is designed to help students understand:
- Web application security best practices
- Session management techniques
- Browser automation for testing
- Modern web development patterns
- API integration methods

## Prerequisites

- Python 3.11+
- Redis (optional, falls back to filesystem sessions)
- Chrome/Chromium browser for Selenium
- Flask and related dependencies (see requirements)

## Installation

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt` or use the package manager
3. Set environment variables for configuration
4. Run with: `python main.py` or use Gunicorn for production

## Environment Variables

- `SESSION_SECRET`: Flask session secret key
- `DATABASE_URL`: Database connection string (defaults to SQLite)
- `BOT_TOKEN`: Telegram bot token for notifications
- `CHAT_ID`: Telegram chat ID for notifications
- `CLOUDFLARE_SITEKEY`: Cloudflare Turnstile site key
- `CLOUDFLARE_SECRET_KEY`: Cloudflare Turnstile secret key

## Academic Use Only

This project is intended for:
- Educational research on web security
- Learning web development best practices
- Understanding browser automation techniques
- Studying session management systems

## Disclaimer

This application is created for educational purposes only. It is designed to help students learn about web development, security practices, and browser automation in a controlled academic environment.

## License

This project is for educational use only. Please respect all applicable laws and terms of service when using this code for learning purposes.

## Support

For academic questions about this project, please contact your instructor or teaching assistant.