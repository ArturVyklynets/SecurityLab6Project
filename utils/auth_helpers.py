import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import request, flash, redirect, url_for
from flask_login import current_user
from constants import LOGIN_URL, DASHBOARD_URL
from models import db, User, LoginAttempt


def log_login_attempt(user, username_entered, success, reason):
    attempt = LoginAttempt(
        user=user,
        user_id=user.id if user else None,
        username_entered=username_entered,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:255],
        success=success,
        reason=reason,
    )
    db.session.add(attempt)


def generate_unique_username(base_name):
    username = base_name.lower().replace(' ', '_')
    username = ''.join(c for c in username if c.isalnum() or c == '_')

    if not User.query.filter_by(username=username).first():
        return username

    for _ in range(10):
        new_username = f"{username}_{secrets.randbelow(10000)}"
        if not User.query.filter_by(username=new_username).first():
            return new_username

    return f"{username}_{secrets.token_hex(4)}"


def is_safe_redirect_url(url):
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.netloc == '' and parsed.scheme == ''


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Будь ласка, увійдіть для доступу до цієї сторінки.', 'warning')
            return redirect(url_for(LOGIN_URL))
        if not current_user.is_admin:
            flash('У вас немає прав для доступу до цієї сторінки.', 'danger')
            return redirect(url_for(DASHBOARD_URL))
        return f(*args, **kwargs)

    return decorated_function
