from flask import url_for, current_app
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

mail = Mail()


def generate_activation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-activation-salt')


def verify_activation_token(token, max_age=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-activation-salt', max_age=max_age)
        return email, None
    except SignatureExpired:
        return None, 'Посилання для активації застаріло. Зареєструйтесь ще раз.'
    except BadSignature:
        return None, 'Невірне посилання для активації.'


def send_activation_email(user):
    token = generate_activation_token(user.email)
    activation_url = url_for('auth.activate', token=token, _external=True)

    msg = Message(
        subject='Активація облікового запису',
        recipients=[user.email]
    )

    msg.html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                       color: white; padding: 15px 30px; text-decoration: none; 
                       border-radius: 5px; margin: 20px 0; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Активація акаунту</h1>
            </div>
            <div class="content">
                <h2>Привіт, {user.username}!</h2>
                <p>Дякуємо за реєстрацію. Для активації облікового запису натисніть кнопку нижче:</p>
                
                <p style="text-align: center;">
                    <a href="{activation_url}" class="button">✅ Активувати акаунт</a>
                </p>
                
                <p>Або скопіюйте це посилання у браузер:</p>
                <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                    {activation_url}
                </p>
                
                <p><strong>⏰ Увага:</strong> Посилання дійсне протягом 1 години.</p>
                
                <p>Якщо ви не реєструвались на нашому сайті, просто проігноруйте цей лист.</p>
            </div>
            <div class="footer">
                <p>© 2025 Password System. Всі права захищені.</p>
            </div>
        </div>
    </body>
    </html>
    '''

    msg.body = f'''
    Привіт, {user.username}!
    
    Дякуємо за реєстрацію. Для активації облікового запису перейдіть за посиланням:
    {activation_url}
    
    Посилання дійсне протягом 1 години.
    
    Якщо ви не реєструвались, проігноруйте цей лист.
    '''

    mail.send(msg)


def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')


def verify_reset_token(token, max_age=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        return email, None
    except SignatureExpired:
        return None, 'Посилання для скидання пароля застаріло. Запросіть нове.'
    except BadSignature:
        return None, 'Невірне посилання для скидання пароля.'


def send_reset_password_email(user):
    token = generate_reset_token(user.email)
    reset_url = url_for('auth.reset_password', token=token, _external=True)

    msg = Message(
        subject='Відновлення пароля',
        recipients=[user.email]
    )

    msg.html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
                       color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
            .button {{ display: inline-block; background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
                       color: white; padding: 15px 30px; text-decoration: none; 
                       border-radius: 5px; margin: 20px 0; }}
            .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; 
                        border-radius: 5px; margin: 15px 0; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔑 Відновлення пароля</h1>
            </div>
            <div class="content">
                <h2>Привіт, {user.username}!</h2>
                <p>Ми отримали запит на скидання пароля для вашого акаунту.</p>
                
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">🔓 Скинути пароль</a>
                </p>
                
                <p>Або скопіюйте це посилання у браузер:</p>
                <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 5px;">
                    {reset_url}
                </p>
                
                <div class="warning">
                    <strong>⏰ Увага:</strong> Посилання дійсне протягом <strong>1 години</strong>.
                </div>
                
                <p><strong>🛡️ Безпека:</strong> Якщо ви не запитували скидання пароля, 
                   проігноруйте цей лист. Ваш пароль залишиться без змін.</p>
            </div>
            <div class="footer">
                <p>© 2025 Password System. Всі права захищені.</p>
            </div>
        </div>
    </body>
    </html>
    '''

    msg.body = f'''
    Привіт, {user.username}!
    
    Ми отримали запит на скидання пароля для вашого акаунту.
    
    Для скидання пароля перейдіть за посиланням:
    {reset_url}
    
    ⏰ Посилання дійсне протягом 1 години.
    
    Якщо ви не запитували скидання пароля, проігноруйте цей лист.
    Ваш пароль залишиться без змін.
    '''

    mail.send(msg)
