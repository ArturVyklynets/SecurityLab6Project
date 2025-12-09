from datetime import datetime, timezone

from app import recaptcha
from constants import (
    FORGOT_PASSWORD_TEMPLATE,
    LOGIN_TEMPLATE,
    REGISTER_TEMPLATE,
    RESEND_ACTIVATION_TEMPLATE,
    RESET_PASSWORD_TEMPLATE,
    TWO_FACTOR_TEMPLATE,
    LOGIN_URL,
    DASHBOARD_URL,
    REGISTER_URL,
    USER_NOT_FOUND_MESSAGE,
)
from email_utils import (
    send_activation_email,
    verify_activation_token,
    send_reset_password_email,
    verify_reset_token
)
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    session
)
from flask_login import (
    login_required,
    current_user,
    logout_user
)
from forms import (
    RegistrationForm,
    LoginForm,
    TwoFactorForm,
    ForgotPasswordForm,
    ResetPasswordForm
)
from models import db, User
from utils.auth_helpers import (
    log_login_attempt,
    is_safe_redirect_url,
    handle_user_not_found,
    handle_oauth_user,
    handle_inactive_user,
    handle_locked_user,
    handle_wrong_password,
    handle_successful_login
)


auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    return redirect(url_for(LOGIN_URL))


@auth_bp.route('/register', methods=['GET'])
def register_get():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))
    
    form = RegistrationForm()
    return render_template(REGISTER_TEMPLATE, form=form)


@auth_bp.route('/register', methods=['POST'])
def register_post():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))
    
    form = RegistrationForm()
    
    if not form.validate_on_submit():
        return render_template(REGISTER_TEMPLATE, form=form)
    
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

    return redirect(url_for(LOGIN_URL))


@auth_bp.route('/activate/<token>')
def activate(token):
    email, error = verify_activation_token(token)

    if error:
        flash(error, 'danger')
        return redirect(url_for(REGISTER_URL))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash(USER_NOT_FOUND_MESSAGE, 'danger')
        return redirect(url_for(REGISTER_URL))

    if user.is_activated:
        flash('Акаунт вже активовано. Ви можете увійти.', 'info')
        return redirect(url_for(LOGIN_URL))

    user.is_activated = True
    user.activated_at = datetime.now(timezone.utc)
    db.session.commit()

    flash('Акаунт успішно активовано! Тепер ви можете увійти.', 'success')
    return redirect(url_for(LOGIN_URL))


@auth_bp.route('/resend-activation', methods=['GET'])
def resend_activation_get():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))
    
    return render_template(RESEND_ACTIVATION_TEMPLATE)


@auth_bp.route('/resend-activation', methods=['POST'])
def resend_activation_post():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))

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

    return redirect(url_for(LOGIN_URL))

@auth_bp.route('/login', methods=['GET'])
def login_get():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))
    
    form = LoginForm()
    return render_template(LOGIN_TEMPLATE, form=form)


@auth_bp.route('/login', methods=['POST'])
def login_post():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))

    form = LoginForm()
    
    if not form.validate_on_submit():
        return render_template(LOGIN_TEMPLATE, form=form)

    user = User.query.filter_by(username=form.username.data).first()

    if user is None:
        return handle_user_not_found(form.username.data)

    if not user.has_password():
        return handle_oauth_user(user, form)

    if not user.is_activated:
        return handle_inactive_user(user, form)

    locked_response = handle_locked_user(user, form)
    if locked_response:
        return locked_response

    if not user.check_password(form.password.data):
        return handle_wrong_password(user, form)

    if user.is_2fa_enabled:
        session['2fa_user_id'] = user.id
        session['2fa_remember'] = False
        return redirect(url_for('auth.two_factor'))

    handle_successful_login(user)

    next_page = request.args.get('next')
    if not is_safe_redirect_url(next_page):
        next_page = None

    return redirect(next_page or url_for(DASHBOARD_URL))


@auth_bp.route('/two-factor', methods=['GET'])
def two_factor_get():
    if '2fa_user_id' not in session:
        flash('Спочатку введіть логін і пароль.', 'warning')
        return redirect(url_for(LOGIN_URL))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        flash(USER_NOT_FOUND_MESSAGE, 'danger')
        return redirect(url_for(LOGIN_URL))

    form = TwoFactorForm()
    return render_template(TWO_FACTOR_TEMPLATE, form=form)


@auth_bp.route('/two-factor', methods=['POST'])
def two_factor_post():
    if '2fa_user_id' not in session:
        flash('Спочатку введіть логін і пароль.', 'warning')
        return redirect(url_for(LOGIN_URL))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.pop('2fa_user_id', None)
        flash(USER_NOT_FOUND_MESSAGE, 'danger')
        return redirect(url_for(LOGIN_URL))

    form = TwoFactorForm()

    if not form.validate_on_submit():
        return render_template(TWO_FACTOR_TEMPLATE, form=form)

    if user.verify_totp(form.code.data):
        session.pop('2fa_user_id', None)
        session.pop('2fa_remember', None)

        user.failed_login_attempts = 0
        user.account_locked_until = None
        log_login_attempt(user, user.username, True, 'success_with_2fa')
        db.session.add(user)
        db.session.commit()

        from flask_login import login_user
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        return redirect(url_for(DASHBOARD_URL))
    else:
        flash('Невірний код. Спробуйте ще раз.', 'danger')
        log_login_attempt(user, user.username, False, 'invalid_2fa_code')
        db.session.commit()
        return render_template(TWO_FACTOR_TEMPLATE, form=form)


@auth_bp.route('/forgot-password', methods=['GET'])
def forgot_password_get():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))
    
    form = ForgotPasswordForm()
    return render_template(FORGOT_PASSWORD_TEMPLATE, form=form)


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password_post():
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))

    form = ForgotPasswordForm()
    
    if not form.validate_on_submit():
        return render_template(FORGOT_PASSWORD_TEMPLATE, form=form)

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
    return redirect(url_for(LOGIN_URL))


@auth_bp.route('/reset-password/<token>', methods=['GET'])
def reset_password_get(token):
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))

    email, error = verify_reset_token(token)

    if error:
        flash(error, 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash(USER_NOT_FOUND_MESSAGE, 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    return render_template(RESET_PASSWORD_TEMPLATE, form=form)


@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password_post(token):
    if current_user.is_authenticated:
        return redirect(url_for(DASHBOARD_URL))

    email, error = verify_reset_token(token)

    if error:
        flash(error, 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash(USER_NOT_FOUND_MESSAGE, 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    
    if not form.validate_on_submit():
        return render_template(RESET_PASSWORD_TEMPLATE, form=form)

    user.set_password(form.password.data)
    user.failed_login_attempts = 0
    user.account_locked_until = None
    db.session.commit()

    flash('Пароль успішно змінено! Тепер ви можете увійти.', 'success')
    return redirect(url_for(LOGIN_URL))


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for(LOGIN_URL))
