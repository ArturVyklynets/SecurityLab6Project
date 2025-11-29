import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from models import db, User, LoginAttempt
from forms import (RegistrationForm, LoginForm, TwoFactorForm, 
                   Enable2FAForm, Disable2FAForm, 
                   ForgotPasswordForm, ResetPasswordForm) 
from config import Config
from recaptcha import ReCaptcha
from email_utils import (mail, send_activation_email, verify_activation_token,
                         send_reset_password_email, verify_reset_token)
from totp_utils import generate_qr_code
from oauth import oauth, init_oauth
from urllib.parse import urlparse
import secrets

app = Flask(__name__)
app.config.from_object(Config)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

db.init_app(app)
mail.init_app(app)
init_oauth(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Будь ласка, увійдіть для доступу до цієї сторінки'
login_manager.login_message_category = 'warning'

recaptcha = ReCaptcha(
    site_key=app.config['RECAPTCHA_SITE_KEY'],
    secret_key=app.config['RECAPTCHA_SECRET_KEY']
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.context_processor
def inject_recaptcha():
    return {'recaptcha_site_key': app.config['RECAPTCHA_SITE_KEY']}

def log_login_attempt(user, username_entered, success, reason):
    attempt = LoginAttempt(
        user=user,
        user_id=user.id if user else None,
        username_entered=username_entered,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        success=success,
        reason=reason
    )
    db.session.add(attempt)


def generate_unique_username(base_name):
    """Генерує унікальне ім'я користувача"""
    username = base_name.lower().replace(' ', '_')
    username = ''.join(c for c in username if c.isalnum() or c == '_')
    
    if not User.query.filter_by(username=username).first():
        return username
    
    for _ in range(10):
        new_username = f"{username}_{secrets.randbelow(10000)}"
        if not User.query.filter_by(username=new_username).first():
            return new_username
    
    return f"{username}_{secrets.token_hex(4)}"

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        recaptcha_response = request.form.get('g-recaptcha-response')
        is_valid, message = recaptcha.verify(
            recaptcha_response,
            remote_ip=request.remote_addr
        )
        
        if not is_valid:
            flash(f'Помилка CAPTCHA: {message}', 'danger')
            return render_template('register.html', form=form)
        
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            if existing_user.username == form.username.data:
                flash('Це ім\'я користувача вже зайняте', 'danger')
            else:
                flash('Цей email вже зареєстровано', 'danger')
            return render_template('register.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_activated=False
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        try:
            send_activation_email(user)
            flash('Реєстрація успішна! Перевірте вашу пошту для активації акаунту.', 'success')
        except Exception as e:
            flash(f'Акаунт створено, але не вдалося надіслати email: {str(e)}', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/activate/<token>')
def activate(token):
    email, error = verify_activation_token(token)
    
    if error:
        flash(error, 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('register'))
    
    if user.is_activated:
        flash('Акаунт вже активовано. Ви можете увійти.', 'info')
        return redirect(url_for('login'))
    
    user.is_activated = True
    user.activated_at = datetime.utcnow()
    db.session.commit()
    
    flash('Акаунт успішно активовано! Тепер ви можете увійти.', 'success')
    return redirect(url_for('login'))


@app.route('/resend-activation', methods=['GET', 'POST'])
def resend_activation():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user and not user.is_activated:
            try:
                send_activation_email(user)
                flash('Лист активації надіслано повторно. Перевірте пошту.', 'success')
            except Exception as e:
                flash(f'Помилка надсилання: {str(e)}', 'danger')
        else:
            flash('Якщо акаунт існує і не активований, лист буде надіслано.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('resend_activation.html')

def is_safe_redirect_url(url):
    """
    Перевіряє, чи є URL безпечним для редиректу.
    Дозволяє тільки відносні URL (без схеми і домену).
    """
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.netloc == '' and parsed.scheme == ''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None:
            flash('Користувача з таким ім\'ям не знайдено. Будь ласка, зареєструйтесь.', 'warning')
            log_login_attempt(None, form.username.data, False, 'user_not_found')
            db.session.commit()
            return redirect(url_for('register'))
        
        if not user.has_password():
            provider = user.oauth_provider or 'OAuth'
            flash(f'Цей акаунт створено через {provider}. Використайте вхід через {provider}.', 'warning')
            return render_template('login.html', form=form)
        
        if not user.is_activated:
            flash('Акаунт не активовано. Перевірте вашу пошту.', 'warning')
            log_login_attempt(user, user.username, False, 'not_activated')
            db.session.commit()
            return render_template('login.html', form=form, show_resend=True)
        
        now = datetime.utcnow()
        if user.account_locked_until and user.account_locked_until > now:
            remaining_seconds = (user.account_locked_until - now).total_seconds()
            remaining_minutes = int(remaining_seconds // 60) + 1
            flash(f'Акаунт заблоковано. Спробуйте через {remaining_minutes} хв.', 'danger')
            log_login_attempt(user, user.username, False, 'account_locked')
            db.session.commit()
            return render_template('login.html', form=form)
        
        if not user.check_password(form.password.data):
            user.failed_login_attempts += 1
            reason = 'bad_password'
            
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.account_locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                reason = 'account_locked_after_too_many_attempts'
                flash(f'Забагато невдалих спроб. Акаунт заблоковано на {LOCKOUT_MINUTES} хв.', 'danger')
            else:
                flash('Невірний пароль', 'danger')
            
            log_login_attempt(user, user.username, False, reason)
            db.session.add(user)
            db.session.commit()
            return render_template('login.html', form=form)
        
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            session['2fa_remember'] = False
            return redirect(url_for('two_factor'))
        
        user.failed_login_attempts = 0
        user.account_locked_until = None
        log_login_attempt(user, user.username, True, 'success')
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        
        next_page = request.args.get('next')
        if not is_safe_redirect_url(next_page):
            next_page = None
        
        return redirect(next_page if next_page else url_for('dashboard'))
    
    return render_template('login.html', form=form)


@app.route('/oauth/google')
def oauth_google():
    """Початок OAuth авторизації через Google"""
    redirect_uri = url_for('oauth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/oauth/google/callback')
def oauth_google_callback():
    """Callback від Google після авторизації"""
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            user_info = oauth.google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
        
        email = user_info.get('email')
        google_id = user_info.get('sub')
        name = user_info.get('name', email.split('@')[0])
        avatar = user_info.get('picture')
        
        if not email:
            flash('Не вдалося отримати email від Google.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if not user.oauth_provider:
                user.oauth_provider = 'google'
                user.oauth_id = google_id
            if avatar:
                user.avatar_url = avatar
            db.session.commit()
        else:
            username = generate_unique_username(name)
            user = User(
                username=username,
                email=email,
                oauth_provider='google',
                oauth_id=google_id,
                avatar_url=avatar,
                is_activated=True,
                activated_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Акаунт створено! Ваше ім\'я користувача: {username}', 'success')
        
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            return redirect(url_for('two_factor'))
        
        log_login_attempt(user, user.username, True, 'oauth_google')
        db.session.commit()
        
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Помилка авторизації через Google: {str(e)}', 'danger')
        return redirect(url_for('login'))


@app.route('/oauth/github')
def oauth_github():
    """Початок OAuth авторизації через GitHub"""
    redirect_uri = url_for('oauth_github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@app.route('/oauth/github/callback')
def oauth_github_callback():
    """Callback від GitHub після авторизації"""
    try:
        token = oauth.github.authorize_access_token()
        
        resp = oauth.github.get('user')
        user_info = resp.json()
        
        github_id = str(user_info.get('id'))
        name = user_info.get('name') or user_info.get('login')
        avatar = user_info.get('avatar_url')
        
        email = user_info.get('email')
        if not email:
            emails_resp = oauth.github.get('user/emails')
            emails = emails_resp.json()
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e.get('email')
                    break
        
        if not email:
            flash('Не вдалося отримати email від GitHub. Переконайтесь, що email публічний або підтверджений.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if not user.oauth_provider:
                user.oauth_provider = 'github'
                user.oauth_id = github_id
            if avatar:
                user.avatar_url = avatar
            db.session.commit()
        else:
            username = generate_unique_username(name)
            user = User(
                username=username,
                email=email,
                oauth_provider='github',
                oauth_id=github_id,
                avatar_url=avatar,
                is_activated=True,
                activated_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Акаунт створено! Ваше ім\'я користувача: {username}', 'success')
        
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            return redirect(url_for('two_factor'))
        
        log_login_attempt(user, user.username, True, 'oauth_github')
        db.session.commit()
        
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Помилка авторизації через GitHub: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if '2fa_user_id' not in session:
        flash('Спочатку введіть логін і пароль.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        if user.verify_totp(form.code.data):
            session.pop('2fa_user_id', None)
            session.pop('2fa_remember', None)
            
            user.failed_login_attempts = 0
            user.account_locked_until = None
            log_login_attempt(user, user.username, True, 'success_with_2fa')
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            flash(f'Ласкаво просимо, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Невірний код. Спробуйте ще раз.', 'danger')
            log_login_attempt(user, user.username, False, 'invalid_2fa_code')
            db.session.commit()
    
    return render_template('two_factor.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Запит на відновлення пароля"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            if not user.has_password():
                flash(f'Цей акаунт створено через {user.oauth_provider}. '
                      f'Використайте вхід через {user.oauth_provider}.', 'warning')
                return render_template('forgot_password.html', form=form)
            
            try:
                send_reset_password_email(user)
            except Exception as e:
                print(f"Error sending reset email: {e}")
        
        flash('Якщо акаунт з такою адресою існує, ми надіслали лист з інструкціями.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Скидання пароля за токеном"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    email, error = verify_reset_token(token)
    
    if error:
        flash(error, 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.failed_login_attempts = 0
        user.account_locked_until = None
        db.session.commit()
        
        flash('Пароль успішно змінено! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA вже увімкнено.', 'info')
        return redirect(url_for('profile'))
    
    form = Enable2FAForm()
    
    if not current_user.totp_secret:
        current_user.generate_totp_secret()
        db.session.commit()
    
    totp_uri = current_user.get_totp_uri()
    qr_code = generate_qr_code(totp_uri)
    
    if form.validate_on_submit():
        if current_user.verify_totp(form.code.data):
            current_user.is_2fa_enabled = True
            db.session.commit()
            flash('2FA успішно увімкнено! 🔐', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Невірний код. Спробуйте ще раз.', 'danger')
    
    return render_template('enable_2fa.html', form=form, qr_code=qr_code, secret=current_user.totp_secret)


@app.route('/profile/disable-2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        flash('2FA не увімкнено.', 'info')
        return redirect(url_for('profile'))
    
    form = Disable2FAForm()
    
    if form.validate_on_submit():
        if not current_user.has_password() or current_user.check_password(form.password.data):
            current_user.is_2fa_enabled = False
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA вимкнено.', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Невірний пароль.', 'danger')
    
    return render_template('disable_2fa.html', form=form, has_password=current_user.has_password())

@app.route('/admin/login-attempts')
@login_required
def admin_login_attempts():
    attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(100).all()
    return render_template('admin_login_attempts.html', attempts=attempts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)