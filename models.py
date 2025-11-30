from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt
import pyotp

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    is_activated = db.Column(db.Boolean, default=False)
    activated_at = db.Column(db.DateTime, nullable=True)

    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked_until = db.Column(db.DateTime, nullable=True)

    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    
    oauth_provider = db.Column(db.String(20), nullable=True)
    oauth_id = db.Column(db.String(100), nullable=True)
    avatar_url = db.Column(db.String(255), nullable=True)

    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            salt
        ).decode('utf-8')
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            self.password_hash.encode('utf-8')
        )
    
    def has_password(self):
        return self.password_hash is not None
    
    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        if not self.totp_secret:
            return None
        return pyotp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="PasswordSystem"
        )
    
    def verify_totp(self, code):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)
    
    def __repr__(self):
        return f'<User {self.username}>'


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username_entered = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, nullable=False)
    reason = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='login_attempts')
