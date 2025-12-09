from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from constants import DISABLE_2FA_TEMPLATE, ENABLE_2FA_TEMPLATE, PROFILE_TEMPLATE, PROFILE_URL
from forms import Enable2FAForm, Disable2FAForm
from models import db
from totp_utils import generate_qr_code

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')


@profile_bp.route('/')
@login_required
def profile():
    return render_template(PROFILE_TEMPLATE)


@profile_bp.route('/enable-2fa', methods=['GET'])
@login_required
def enable_2fa_get():
    if current_user.is_2fa_enabled:
        flash('2FA вже увімкнено.', 'info')
        return redirect(url_for(PROFILE_URL))

    if not current_user.totp_secret:
        current_user.generate_totp_secret()
        db.session.commit()

    totp_uri = current_user.get_totp_uri()
    qr_code = generate_qr_code(totp_uri)
    
    form = Enable2FAForm()
    return render_template(ENABLE_2FA_TEMPLATE, form=form, qr_code=qr_code, secret=current_user.totp_secret)


@profile_bp.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa_post():
    if current_user.is_2fa_enabled:
        flash('2FA вже увімкнено.', 'info')
        return redirect(url_for(PROFILE_URL))

    form = Enable2FAForm()
    
    if not form.validate_on_submit():
        if not current_user.totp_secret:
            current_user.generate_totp_secret()
            db.session.commit()
        
        totp_uri = current_user.get_totp_uri()
        qr_code = generate_qr_code(totp_uri)
        return render_template(ENABLE_2FA_TEMPLATE, form=form, qr_code=qr_code, secret=current_user.totp_secret)

    if current_user.verify_totp(form.code.data):
        current_user.is_2fa_enabled = True
        db.session.commit()
        flash('2FA успішно увімкнено! 🔐', 'success')
        return redirect(url_for(PROFILE_URL))
    else:
        totp_uri = current_user.get_totp_uri()
        qr_code = generate_qr_code(totp_uri)
        flash('Невірний код. Спробуйте ще раз.', 'danger')
        return render_template(ENABLE_2FA_TEMPLATE, form=form, qr_code=qr_code, secret=current_user.totp_secret)


@profile_bp.route('/disable-2fa', methods=['GET'])
@login_required
def disable_2fa_get():
    if not current_user.is_2fa_enabled:
        flash('2FA не увімкнено.', 'info')
        return redirect(url_for(PROFILE_URL))

    form = Disable2FAForm()
    return render_template(DISABLE_2FA_TEMPLATE, form=form, has_password=current_user.has_password())


@profile_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa_post():
    if not current_user.is_2fa_enabled:
        flash('2FA не увімкнено.', 'info')
        return redirect(url_for(PROFILE_URL))

    form = Disable2FAForm()
    
    if not form.validate_on_submit():
        return render_template(DISABLE_2FA_TEMPLATE, form=form, has_password=current_user.has_password())

    if not current_user.has_password() or current_user.check_password(form.password.data):
        current_user.is_2fa_enabled = False
        current_user.totp_secret = None
        db.session.commit()
        flash('2FA вимкнено.', 'success')
        return redirect(url_for(PROFILE_URL))
    else:
        flash('Невірний пароль.', 'danger')
        return render_template(DISABLE_2FA_TEMPLATE, form=form, has_password=current_user.has_password())
