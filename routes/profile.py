from constants import *
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from forms import Enable2FAForm, Disable2FAForm
from models import db
from totp_utils import generate_qr_code

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')


@profile_bp.route('/')
@login_required
def profile():
    return render_template(PROFILE_TEMPLATE)


@profile_bp.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA вже увімкнено.', 'info')
        return redirect(url_for('profile.profile'))

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
            return redirect(url_for('profile.profile'))
        else:
            flash('Невірний код. Спробуйте ще раз.', 'danger')

    return render_template(ENABLE_2FA_TEMPLATE, form=form, qr_code=qr_code, secret=current_user.totp_secret)


@profile_bp.route('/disable-2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        flash('2FA не увімкнено.', 'info')
        return redirect(url_for('profile.profile'))

    form = Disable2FAForm()

    if form.validate_on_submit():
        if not current_user.has_password() or current_user.check_password(form.password.data):
            current_user.is_2fa_enabled = False
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA вимкнено.', 'success')
            return redirect(url_for('profile.profile'))
        else:
            flash('Невірний пароль.', 'danger')

    return render_template(DISABLE_2FA_TEMPLATE, form=form, has_password=current_user.has_password())
