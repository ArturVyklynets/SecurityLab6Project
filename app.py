import os

from flask import Flask
from flask_login import LoginManager

from config import Config
from email_utils import mail
from models import db, User
from oauth import init_oauth
from recaptcha import ReCaptcha

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
mail.init_app(app)
init_oauth(app)

recaptcha = ReCaptcha(
    site_key=app.config['RECAPTCHA_SITE_KEY'],
    secret_key=app.config['RECAPTCHA_SECRET_KEY']
)

login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Будь ласка, увійдіть для доступу до цієї сторінки'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_recaptcha():
    return {'recaptcha_site_key': app.config['RECAPTCHA_SITE_KEY']}


from routes import auth_bp, oauth_bp, main_bp, profile_bp, admin_bp

app.register_blueprint(auth_bp)
app.register_blueprint(oauth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(admin_bp)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)
