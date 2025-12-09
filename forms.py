from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp

from constants import REQUIRED_FIELD_MESSAGE
from validators import validate_password


class RegistrationForm(FlaskForm):
    username = StringField('Ім\'я користувача', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE),
        Length(min=3, max=80, message="Ім'я має бути від 3 до 80 символів")
    ])

    email = StringField('Email', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE),
        Email(message="Введіть коректний email")
    ])

    password = PasswordField('Пароль', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE)
    ])

    confirm_password = PasswordField('Підтвердіть пароль', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE),
        EqualTo('password', message="Паролі не співпадають")
    ])

    submit = SubmitField('Зареєструватися')

    def validate_password(self, field):
        errors = validate_password(field.data)
        if errors:
            raise ValidationError(' | '.join(errors))


class LoginForm(FlaskForm):
    username = StringField('Ім\'я користувача', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE)
    ])

    password = PasswordField('Пароль', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE)
    ])

    submit = SubmitField('Увійти')


class TwoFactorForm(FlaskForm):
    code = StringField('Код з Google Authenticator', validators=[
        DataRequired(message="Введіть 6-значний код"),
        Regexp(r'^\d{6}$', message="Код має містити рівно 6 цифр")
    ])

    submit = SubmitField('Підтвердити')


class Enable2FAForm(FlaskForm):
    code = StringField('Код з Google Authenticator', validators=[
        DataRequired(message="Введіть 6-значний код"),
        Regexp(r'^\d{6}$', message="Код має містити рівно 6 цифр")
    ])

    submit = SubmitField('Увімкнути 2FA')


class Disable2FAForm(FlaskForm):
    password = PasswordField('Ваш пароль', validators=[
        DataRequired(message="Введіть пароль для підтвердження")
    ])

    submit = SubmitField('Вимкнути 2FA')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Введіть ваш email"),
        Email(message="Введіть коректний email")
    ])

    submit = SubmitField('Надіслати посилання')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новий пароль', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE)
    ])

    confirm_password = PasswordField('Підтвердіть новий пароль', validators=[
        DataRequired(message=REQUIRED_FIELD_MESSAGE),
        EqualTo('password', message="Паролі не співпадають")
    ])

    submit = SubmitField('Змінити пароль')

    def validate_password(self, field):
        errors = validate_password(field.data)
        if errors:
            raise ValidationError(' | '.join(errors))
