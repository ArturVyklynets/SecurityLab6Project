from flask import Blueprint, redirect, url_for, flash, session
from flask_login import login_user
from datetime import datetime, timezone
from oauth import oauth
from utils.auth_helpers import log_login_attempt, generate_unique_username
from models import db, User
from constants import *

oauth_bp = Blueprint('oauth', __name__)

@oauth_bp.route('/oauth/google')
def oauth_google():
    redirect_uri = url_for('oauth.oauth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@oauth_bp.route('/oauth/google/callback')
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
            return redirect(url_for('auth.login'))
        
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
                activated_at = datetime.now(timezone.utc)
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Акаунт створено! Ваше ім\'я користувача: {username}', 'success')
        
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            return redirect(url_for('auth.two_factor'))
        
        log_login_attempt(user, user.username, True, 'oauth_google')
        db.session.commit()
        
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        return redirect(url_for('main.dashboard'))
        
    except Exception as e:
        flash(f'Помилка авторизації через Google: {str(e)}', 'danger')
        return redirect(url_for('auth.login'))

@oauth_bp.route('/oauth/github')
def oauth_github():
    """Початок OAuth авторизації через GitHub"""
    redirect_uri = url_for('oauth.oauth_github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@oauth_bp.route('/oauth/github/callback')
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
            return redirect(url_for('auth.login'))
        
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
                activated_at = datetime.now(timezone.utc)
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Акаунт створено! Ваше ім\'я користувача: {username}', 'success')
        
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            return redirect(url_for('auth.two_factor'))
        
        log_login_attempt(user, user.username, True, 'oauth_github')
        db.session.commit()
        
        login_user(user)
        flash(f'Ласкаво просимо, {user.username}!', 'success')
        return redirect(url_for('main.dashboard'))
        
    except Exception as e:
        flash(f'Помилка авторизації через GitHub: {str(e)}', 'danger')
        return redirect(url_for('auth.login'))