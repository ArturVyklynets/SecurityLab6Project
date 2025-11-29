import re

def validate_password(password):
    errors = []
    
    if len(password) < 8:
        errors.append("Пароль повинен містити мінімум 8 символів")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Пароль повинен містити хоча б одну велику літеру")
    
    if not re.search(r'[a-z]', password):
        errors.append("Пароль повинен містити хоча б одну малу літеру")
    
    if not re.search(r'\d', password):
        errors.append("Пароль повинен містити хоча б одну цифру")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~]', password):
        errors.append("Пароль повинен містити хоча б один спеціальний символ (!@#$%^&* тощо)")
    
    return errors
