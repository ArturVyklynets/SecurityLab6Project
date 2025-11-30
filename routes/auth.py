from datetime import datetime, timedelta

from app import recaptcha
from constants import *
from email_utils import send_activation_email, verify_activation_token, send_reset_password_email, verify_reset_token
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, login_required, current_user, logout_user
from forms import RegistrationForm, LoginForm, TwoFactorForm, ForgotPasswordForm, ResetPasswordForm
from models import db, User
from utils.auth_helpers import log_login_attempt, is_safe_redirect_url

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        recaptcha_response = request.form.get('g-recaptcha-response')
        is_valid, message = recaptcha.verify(
            recaptcha_response,
            remote_ip=request.remote_addr
        )

        if not is_valid:
            flash(f'Помилка CAPTCHA: {message}', 'danger')
            return render_template(REGISTER_TEMPLATE, form=form)

        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            if existing_user.username == form.username.data:
                flash('Це ім\'я користувача вже зайняте', 'danger')
            else:
                flash('Цей email вже зареєстровано', 'danger')
            return render_template(REGISTER_TEMPLATE, form=form)

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

        return redirect(url_for('auth.login'))

    return render_template(REGISTER_TEMPLATE, form=form)


@auth_bp.route('/activate/<token>')
def activate(token):
    email, error = verify_activation_token(token)

    if error:
        flash(error, 'danger')
        return redirect(url_for('auth.register'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('auth.register'))

    if user.is_activated:
        flash('Акаунт вже активовано. Ви можете увійти.', 'info')
        return redirect(url_for('auth.login'))

    user.is_activated = True
    user.activated_at = datetime.utcnow()
    db.session.commit()

    flash('Акаунт успішно активовано! Тепер ви можете увійти.', 'success')
    return redirect(url_for('auth.login'))


@auth_bp.route('/resend-activation', methods=['GET', 'POST'])
def resend_activation():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

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

        return redirect(url_for('auth.login'))

    return render_template(RESEND_ACTIVATION_TEMPLATE)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user is None:
            flash('Користувача з таким ім\'ям не знайдено. Будь ласка, зареєструйтесь.', 'warning')
            log_login_attempt(None, form.username.data, False, 'user_not_found')
            db.session.commit()
            return redirect(url_for('auth.register'))

        if not user.has_password():
            provider = user.oauth_provider or 'OAuth'
            flash(f'Цей акаунт створено через {provider}. Використайте вхід через {provider}.', 'warning')
            return render_template(LOGIN_TEMPLATE, form=form)

        if not user.is_activated:
            flash('Акаунт не активовано. Перевірте вашу пошту.', 'warning')
            log_login_attempt(user, user.username, False, 'not_activated')
            db.session.commit()
            return render_template(LOGIN_TEMPLATE, form=form, show_resend=True)

        now = datetime.utcnow()

        if user.account_locked_until and user.account_locked_until > now:
            remaining_seconds = (user.account_locked_until - now).total_seconds()
            remaining_minutes = int(remaining_seconds // 60) + 1
            flash(f'Акаунт заблоковано. Спробуйте через {remaining_minutes} хв.', 'danger')
            log_login_attempt(user, user.username, False, 'account_locked')
            db.session.commit()
            return render_template(LOGIN_TEMPLATE, form=form)

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
            return render_template(LOGIN_TEMPLATE, form=form)

        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            session['2fa_remember'] = False
            return redirect(url_for('auth.two_factor'))

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

        return redirect(next_page if next_page else url_for('main.dashboard'))

    return render_template(LOGIN_TEMPLATE, form=form)


@auth_bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if '2fa_user_id' not in session:
        flash('Спочатку введіть логін і пароль.', 'warning')
        return redirect(url_for('auth.login'))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('auth.login'))

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
            return redirect(url_for('main.dashboard'))
        else:
            flash('Невірний код. Спробуйте ще раз.', 'danger')
            log_login_attempt(user, user.username, False, 'invalid_2fa_code')
            db.session.commit()

    return render_template(TWO_FACTOR_TEMPLATE, form=form)


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Запит на відновлення пароля"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = ForgotPasswordForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            if not user.has_password():
                flash(f'Цей акаунт створено через {user.oauth_provider}. '
                      f'Використайте вхід через {user.oauth_provider}.', 'warning')
                return render_template(FORGOT_PASSWORD_TEMPLATE, form=form)

            try:
                send_reset_password_email(user)
            except Exception as e:
                print(f"Error sending reset email: {e}")

        flash('Якщо акаунт з такою адресою існує, ми надіслали лист з інструкціями.', 'info')
        return redirect(url_for('auth.login'))

    return render_template(FORGOT_PASSWORD_TEMPLATE, form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Скидання пароля за токеном"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    email, error = verify_reset_token(token)

    if error:
        flash(error, 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash('Користувача не знайдено.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.failed_login_attempts = 0
        user.account_locked_until = None
        db.session.commit()

        flash('Пароль успішно змінено! Тепер ви можете увійти.', 'success')
        return redirect(url_for('auth.login'))

    return render_template(RESET_PASSWORD_TEMPLATE, form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for('auth.login'))
