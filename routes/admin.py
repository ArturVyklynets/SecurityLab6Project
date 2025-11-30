from constants import *
from flask import Blueprint, render_template
from flask_login import login_required
from models import LoginAttempt
from utils.auth_helpers import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/login-attempts')
@login_required
@admin_required
def login_attempts():
    attempts = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(100).all()
    return render_template(ADMIN_LOGIN_ATTEMPTS_TEMPLATE, attempts=attempts)
