# utils/auth_helpers.py
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import request, flash, redirect, url_for, render_template, session
from flask_login import current_user, login_user

from constants import (
    LOGIN_URL,
    DASHBOARD_URL,
    REGISTER_URL,
    LOGIN_TEMPLATE,
    LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS,
    INVALID_CREDENTIALS_MESSAGE,
)
from models import db, User, LoginAttempt


def log_login_attempt(user, username_entered, success, reason):
    attempt = LoginAttempt(
        user=user,
        user_id=user.id if user else None,
        username_entered=username_entered,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:255],
        success=success,
        reason=reason,
    )
    db.session.add(attempt)


def generate_unique_username(base_name):
    username = base_name.lower().replace(" ", "_")
    username = "".join(c for c in username if c.isalnum() or c == "_")

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
    return parsed.netloc == "" and parsed.scheme == ""


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Будь ласка, увійдіть для доступу до цієї сторінки.", "warning")
            return redirect(url_for(LOGIN_URL))
        if not current_user.is_admin:
            flash("У вас немає прав для доступу до цієї сторінки.", "danger")
            return redirect(url_for(DASHBOARD_URL))
        return f(*args, **kwargs)

    return decorated_function


def handle_user_not_found(username):
    flash("Користувача з таким ім'ям не знайдено. Будь ласка, зареєструйтесь.", "warning")
    log_login_attempt(None, username, False, "user_not_found")
    db.session.commit()
    return redirect(url_for(REGISTER_URL))


def handle_oauth_user(user, form):
    provider = user.oauth_provider or "OAuth"
    flash(f"Цей акаунт створено через {provider}. Використайте вхід через {provider}.", "warning")
    return render_template(LOGIN_TEMPLATE, form=form)


def handle_inactive_user(user, form):
    flash("Акаунт не активовано. Перевірте вашу пошту.", "warning")
    log_login_attempt(user, user.username, False, "not_activated")
    db.session.commit()
    return render_template(LOGIN_TEMPLATE, form=form, show_resend=True)


def handle_locked_user(user, form):
    now = datetime.now(timezone.utc)
    locked_until = user.get_account_locked_until()
    if not locked_until or locked_until <= now:
        return None

    remaining = int((locked_until - now).total_seconds() // 60) + 1
    flash(f"Акаунт заблоковано. Спробуйте через {remaining} хв.", "danger")
    log_login_attempt(user, user.username, False, "account_locked")
    db.session.commit()
    return render_template(LOGIN_TEMPLATE, form=form)


def handle_wrong_password(user, form):
    user.failed_login_attempts += 1
    reason = "bad_password"

    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.account_locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=LOCKOUT_MINUTES
        )
        reason = "account_locked_after_too_many_attempts"
        flash(
            f"Забагато невдалих спроб. Акаунт заблоковано на {LOCKOUT_MINUTES} хв.",
            "danger",
        )
    else:
        flash(INVALID_CREDENTIALS_MESSAGE, "danger")

    log_login_attempt(user, user.username, False, reason)
    db.session.add(user)
    db.session.commit()
    return render_template(LOGIN_TEMPLATE, form=form)


def handle_successful_login(user):
    user.failed_login_attempts = 0
    user.account_locked_until = None
    log_login_attempt(user, user.username, True, "success")
    db.session.add(user)
    db.session.commit()
    login_user(user)
    flash(f"Ласкаво просимо, {user.username}!", "success")


def _create_oauth_user(
    username,
    email,
    provider,
    provider_id,
    avatar,
    activated_at,
):
    user = User(
        username=username,
        email=email,
        oauth_provider=provider,
        oauth_id=provider_id,
        avatar_url=avatar,
        is_activated=True,
        activated_at=activated_at,
    )
    db.session.add(user)
    db.session.commit()
    flash(f"Акаунт створено! Ваше ім'я користувача: {username}", "success")
    return user


def _update_oauth_user(user, provider, provider_id, avatar):
    if not user.oauth_provider:
        user.oauth_provider = provider
        user.oauth_id = provider_id
    if avatar:
        user.avatar_url = avatar
    db.session.commit()
    return user


def handle_oauth_login(user, provider_name):
    if user.is_2fa_enabled:
        session["2fa_user_id"] = user.id
        return redirect(url_for("auth.two_factor"))

    log_login_attempt(user, user.username, True, f"oauth_{provider_name}")
    db.session.commit()
    login_user(user)
    flash(f"Ласкаво просимо, {user.username}!", "success")
    return redirect(url_for(DASHBOARD_URL))

