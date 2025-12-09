from datetime import datetime, timezone

from flask import Blueprint, redirect, url_for, flash
from constants import LOGIN_URL
from models import User
from utils.auth_helpers import (
    generate_unique_username,
    _create_oauth_user,
    _update_oauth_user,
    handle_oauth_login,
)
from oauth import oauth

oauth_bp = Blueprint('oauth', __name__)

def _get_github_email():
    try:
        emails_resp = oauth.github.get('user/emails')
        emails = emails_resp.json()
        for e in emails:
            if e.get('primary') and e.get('verified'):
                return e.get('email')
    except Exception:
        pass
    return None


@oauth_bp.route('/oauth/google')
def oauth_google():
    redirect_uri = url_for('oauth.oauth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@oauth_bp.route('/oauth/google/callback')
def oauth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo') or oauth.google.get(
            'https://openidconnect.googleapis.com/v1/userinfo'
        ).json()

        email = user_info.get('email')
        if not email:
            flash('Не вдалося отримати email від Google.', 'danger')
            return redirect(url_for(LOGIN_URL))

        google_id = user_info.get('sub')
        name = user_info.get('name', email.split('@')[0])
        avatar = user_info.get('picture')

        user = User.query.filter_by(email=email).first()

        if user:
            _update_oauth_user(user, 'google', google_id, avatar)
        else:
            username = generate_unique_username(name)
            user = _create_oauth_user(
                username=username,
                email=email,
                provider='google',
                provider_id=google_id,
                avatar=avatar,
                activated_at=datetime.now(timezone.utc),
            )

        return handle_oauth_login(user, 'google')

    except Exception as e:
        flash(f'Помилка авторизації через Google: {str(e)}', 'danger')
        return redirect(url_for(LOGIN_URL))


@oauth_bp.route('/oauth/github')
def oauth_github():
    redirect_uri = url_for('oauth.oauth_github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@oauth_bp.route('/oauth/github/callback')
def oauth_github_callback():
    try:
        oauth.github.authorize_access_token()

        resp = oauth.github.get('user')
        user_info = resp.json()

        github_id = str(user_info.get('id'))
        name = user_info.get('name') or user_info.get('login')
        avatar = user_info.get('avatar_url')
        email = user_info.get('email') or _get_github_email()

        if not email:
            flash(
                'Не вдалося отримати email від GitHub. '
                'Переконайтесь, що email публічний або підтверджений.',
                'danger'
            )
            return redirect(url_for(LOGIN_URL))

        user = User.query.filter_by(email=email).first()

        if user:
            _update_oauth_user(user, 'github', github_id, avatar)
        else:
            username = generate_unique_username(name)
            user = _create_oauth_user(
                username=username,
                email=email,
                provider='github',
                provider_id=github_id,
                avatar=avatar,
                activated_at=datetime.now(timezone.utc),
            )

        return handle_oauth_login(user, 'github')

    except Exception as e:
        flash(f'Помилка авторизації через GitHub: {str(e)}', 'danger')
        return redirect(url_for(LOGIN_URL))
